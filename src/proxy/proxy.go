package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"net"
	"strings"
	"sync"
	"time"

	"github.com/adrianmoye/ssh-gateway/src/api"
	"github.com/adrianmoye/ssh-gateway/src/gencert"
	"github.com/adrianmoye/ssh-gateway/src/log"
	"github.com/adrianmoye/ssh-gateway/src/sshnet"
	"github.com/adrianmoye/ssh-gateway/src/users"
)

// Config provides proxy config options
type Config struct {
	OperationMode string
	SkipHeaders   []string
	Port          string
	Certs         gencert.RawPEM
	TLSConfig     *tls.Config
}

var config Config

// API for access to the API
var API = api.ClientConfig()

// Proxy contains the data for a proxy session.
type Proxy struct {
	clientReader *bufio.Reader
	apiReader    *bufio.Reader
	clientConn   net.Conn
	apiConn      net.Conn
	authToken    string
	upgrade      bool
	method       string
	request      string
}

func (p Proxy) writeHeader(key, value string) {
	fmt.Fprintf(p.clientConn, "%s: %s\r\n", key, value)
}

func (p Proxy) close400() {
	fmt.Fprintf(p.clientConn, "HTTP/1.1 400 Bad Request\r\n")
	p.writeHeader("Content-Type", "text/plain; charset=utf-8")
	p.writeHeader("Connection", "close")
	fmt.Fprintf(p.clientConn, "\r\n")
	p.close()
}
func (p Proxy) close403(msg string) {
	message := fmt.Sprintf(`{
	"kind": "Status",
	"apiVersion": "v1",
	"metadata": {},
	"status": "Failure",
	"message": "%s",
	"reason": "Forbidden",
	"details": {},
	"code": 403
}`, msg)

	fmt.Fprintf(p.clientConn, "HTTP/1.1 403 Forbidden\r\n")
	p.writeHeader("Cache-Control", "no-cache, private")
	p.writeHeader("Content-Type", "application/json")
	p.writeHeader("X-Content-Type-Options", "nosniff")
	p.writeHeader("Date", time.Now().Format(time.RFC1123))
	p.writeHeader("Content-Length", fmt.Sprintf("%d", len(message)))
	p.writeHeader("Connection", "close")
	fmt.Fprintf(p.clientConn, "\r\n")
	fmt.Fprintf(p.clientConn, message)
	p.close()
}

func (p Proxy) close() {
	p.clientConn.Close()
	p.apiConn.Close()
}

func skipHeaders(header string) bool {
	for _, skip := range config.SkipHeaders {
		if header == skip {
			return true
		}
	}
	return false
}

func (p Proxy) requestReader() {

	// start off by reading the first line of the header
	// this is a standard http header so GET /blah HTTP/1.1
	header, _ := p.clientReader.ReadString('\n')
	meth, req, _, ok := parseResponseLine(header)
	p.method = meth
	p.request = req
	if !ok {
		log.Info("cannot parse request", p.clientConn.RemoteAddr().String())
		p.close400()
		return
	}
	log.Debug("Got request header: "+header, p.clientConn.RemoteAddr().String())
	p.apiConn.Write([]byte(header))
	for {
		header, err := p.clientReader.ReadString('\n')
		if err != nil {
			log.Debug("buffreadstring err"+fmt.Sprint(err), p.clientConn.RemoteAddr().String())
			p.close400()
		}
		key, value, ok := parseHeaderLine(header)
		log.Debug("Copying header: "+key+" "+value, p.clientConn.RemoteAddr().String())
		if !ok { // we've finished the headers
			break
		}
		if key == "Authorization" {
			p.authToken = value[len("Bearer "):]
			log.Debug("Got auth token: "+p.authToken, p.clientConn.RemoteAddr().String())
			continue
		}
		if skipHeaders(key) {
			continue
		}
		if key == "Upgrade" {
			p.upgrade = true
		}

		log.Debug("Writing header: "+header, p.clientConn.RemoteAddr().String())
		// we've filtered the headers
		p.apiConn.Write([]byte(header))
	}

	if p.authToken == "" {
		// todo fix no token
		log.Info("UNAUTHORIZED request "+p.method+" "+p.request, p.clientConn.RemoteAddr().String())

		p.close403("forbidden: User \\\"system:anonymous\\\" cannot get path \\\"" + p.request + "\\\"")
		return
	}
	//debug.Printf(" user token\n[%s]\n[%s]\n",t,token)
	name := users.GetNameFromToken(p.authToken)
	if !(len(name) > 0) {

		log.Info("UNAUTHORIZED request "+p.method+" "+p.request, p.clientConn.RemoteAddr().String())

		p.close403("forbidden: User \"system:anonymous\" cannot get path \"" + p.request + "\"")
		return
	}

	log.Debug("operation mode auth headers: "+config.OperationMode, p.clientConn.RemoteAddr().String())
	// do authorization
	switch config.OperationMode {
	case "serviceaccount": // Give the SA token
		fmt.Fprintf(p.apiConn, "Authorization: %s\r\n", users.SATokens[name])
	case "proxy":
		// set appropriate headers
		fmt.Fprintf(p.apiConn, "X-Remote-User: %s\r\n", name)
		log.Debug("add username header: "+name, p.clientConn.RemoteAddr().String())
		if users.GetUser(name).Groups != nil {
			for _, group := range *users.GetUser(name).Groups {
				fmt.Fprintf(p.apiConn, "X-Remote-Group: %s\r\n", group)
				log.Debug("add group for un header: "+name+" "+group, p.clientConn.RemoteAddr().String())
			}
		}
	default: //  "impersonate"
		fmt.Fprintf(p.apiConn, "Authorization: Bearer %s\r\n", API.Bearer)
		fmt.Fprintf(p.apiConn, "Impersonate-User: %s\r\n", name)
		if users.GetUser(name).Groups != nil {
			for _, group := range *users.GetUser(name).Groups {
				fmt.Fprintf(p.apiConn, "Impersonate-Group: %s\r\n", group)
			}
		}
	}

	// TODO: don't auto-close, follow the protocol
	// and allow connection reuse
	if !p.upgrade {
		fmt.Fprintf(p.apiConn, "Connection: %s\r\n", "close")
	}
	fmt.Fprintf(p.apiConn, "\r\n")

	log.Info("request "+p.method+" "+p.request, p.clientConn.RemoteAddr().String())

	io.Copy(p.apiConn, p.clientReader)

}
func (p Proxy) responseReader() {
	io.Copy(p.clientConn, p.apiReader)
}

func newProxyHandler(clientConn net.Conn) {
	p := new(Proxy)
	p.clientConn = clientConn
	// start buffering the client connection
	p.clientReader = bufio.NewReader(clientConn)
	// dial up the api server
	apiConn, err := tls.Dial("tcp", API.Dest, config.TLSConfig)
	p.apiConn = apiConn
	if err != nil {
		log.Info("Error connecting to API server:"+fmt.Sprint(err), p.clientConn.RemoteAddr().String())
		// we really shouldn't 403 this but it'll do for now
		p.close403("forbidden: User \"system:anonymous\" cannot connect to apiserver")
		//http.Error(clientConn, err.Error(), http.StatusServiceUnavailable)
		return
	}
	p.apiReader = bufio.NewReader(apiConn)

	log.Debug("Mixing the streams...", p.clientConn.RemoteAddr().String())

	var wg sync.WaitGroup

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()
		p.requestReader()
	}(&wg)
	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()
		p.responseReader()
	}(&wg)

	wg.Wait()

	//Log.Println("closing...")
	//clientConn.Close()
	//apiConn.Close()
}

// from golang/request.go
// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseResponseLine(line string) (proto, responseCode, message string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1 : len(line)-2], true
}
func parseHeaderLine(line string) (key, value string, ok bool) {
	s1 := strings.Index(line, ": ")
	if s1 < 0 {
		return
	}
	return line[:s1], line[s1+2 : len(line)-2], true
}

// Server listens on an sshnet https connection
func Server(c Config) *sshnet.Listener {

	config = c

	cert, err := tls.X509KeyPair([]byte(config.Certs.Cert), []byte(config.Certs.Key))
	if err != nil {
		log.Info("cannot decode proxy certificate"+fmt.Sprint(err), "server")
		os.Exit(1)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(API.CA))

	config.TLSConfig = &tls.Config{ /*
		        MinVersion:               tls.VersionTLS12,
		        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		        PreferServerCipherSuites: true,
		        CipherSuites: []uint16{
		            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},*/

		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	sshNetListener, _ := sshnet.Listen("0.0.0.0:" + config.Port)
	tlsListener := tls.NewListener(sshNetListener, config.TLSConfig)

	go func() {
		for {
			clientConn, err := tlsListener.Accept()
			if err != nil {
				log.Info("Failed to accept connection: "+fmt.Sprint(err), "server")
			} else {
				log.Debug("Accept connection:", clientConn.RemoteAddr().String())
				go newProxyHandler(clientConn)
			}
		}
	}()

	return sshNetListener
}
