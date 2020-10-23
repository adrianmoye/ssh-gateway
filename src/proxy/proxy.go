package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	Log "log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/adrianmoye/ssh-gateway/src/api"
	"github.com/adrianmoye/ssh-gateway/src/gencert"
	"github.com/adrianmoye/ssh-gateway/src/sshnet"
	"github.com/adrianmoye/ssh-gateway/src/users"
)

// Config provides proxy config options
type Config struct {
	OperationMode string
	CopyHeaders   []string
	Port          string
	Certs         gencert.RawPEM
	TLSConfig     *tls.Config
}

var config Config

// API for access to the API
var API = api.ClientConfig()

// Debug make true to log debug messages
type Debug bool

// Println a wrapper for debug.Println
func (d Debug) Println(v ...interface{}) {
	if d {
		Log.Println(v...)
	}
}

var debug Debug = false

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

func (p Proxy) requestReader() {

	// start off by reading the first line of the header
	// this is a standard http header so GET /blah HTTP/1.1
	header, _ := p.clientReader.ReadString('\n')
	meth, req, _, ok := parseResponseLine(header)
	p.method = meth
	p.request = req
	if !ok {
		Log.Println("cannot parse request [" + p.clientConn.RemoteAddr().String() + "]")
		p.close400()
		return
	}
	debug.Println("Got request header:", header)
	p.apiConn.Write([]byte(header))
	for {
		header, err := p.clientReader.ReadString('\n')
		if err != nil {
			debug.Println("buffreadstring err", err)
		}
		key, value, ok := parseHeaderLine(header)
		debug.Println("Copying header: ", key, value)
		if !ok {
			// we've finished the headers
			break
		}
		if key == "Authorization" {
			p.authToken = regexp.MustCompilePOSIX("Bearer ").ReplaceAllString(value, "")
			debug.Println("Got auth token:", p.authToken)
			continue
		}
		if key == "Upgrade" {
			p.upgrade = true
		}
		// strip headers
		switch config.OperationMode {
		case "serviceaccount": // Give the SA token
			if key == "X-Remote-User" ||
				key == "X-Remote-Group" {
				continue
			}
		case "proxy":
			if key == "X-Remote-User" ||
				key == "X-Remote-Group" {
				continue
			}
		default: //  "impersonate"
			if key == "X-Remote-User" ||
				key == "X-Remote-Group" ||
				key == "Impersonate-User" ||
				key == "Impersonate-Group" {
				continue
			}
		}

		debug.Println("Writing header: ", header)
		// we've filtered the headers
		p.apiConn.Write([]byte(header))
	}

	if p.authToken == "" {
		// todo fix no token
		Log.Println("UNAUTHORIZED request [" + p.clientConn.RemoteAddr().String() + "] " + p.method + " " + p.request)
		debug.Println("FAILED REQ ", "UNKNOWN", p.clientConn.RemoteAddr().String())

		p.close403("forbidden: User \\\"system:anonymous\\\" cannot get path \\\"" + p.request + "\\\"")
		return
	}
	//debug.Printf(" user token\n[%s]\n[%s]\n",t,token)
	name := users.GetNameFromToken(p.authToken)
	if !(len(name) > 0) {
		Log.Println("UNAUTHORIZED request [" + p.clientConn.RemoteAddr().String() + "] " + p.method + " " + p.request)
		debug.Println("FAILED REQ ", "UNKNOWN", p.clientConn.RemoteAddr().String())

		p.close403("forbidden: User \"system:anonymous\" cannot get path \"" + p.request + "\"")
		return
	}

	debug.Println("operation mode auth headers:", config.OperationMode)
	// do authorization
	switch config.OperationMode {
	case "serviceaccount": // Give the SA token
		fmt.Fprintf(p.apiConn, "Authorization: %s\r\n", users.SATokens[name])
	case "proxy":
		// set appropriate headers
		fmt.Fprintf(p.apiConn, "X-Remote-User: %s\r\n", name)
		debug.Println("add username header:", name)
		if users.GetUser(name).Groups != nil {
			for _, group := range *users.GetUser(name).Groups {
				fmt.Fprintf(p.apiConn, "X-Remote-Group: %s\r\n", group)
				debug.Println("add group for un header:", name, group)
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

	Log.Println("request [" + p.clientConn.RemoteAddr().String() + "] " + p.method + " " + p.request)

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
		Log.Println("Error connecting to API server:", err)
		//http.Error(clientConn, err.Error(), http.StatusServiceUnavailable)
		return
	}
	p.apiReader = bufio.NewReader(apiConn)

	debug.Println("Mixing the streams...")

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

// HTTPSServer listens on an sshnet https connection
func HTTPSServer(c Config) *sshnet.Listener {

	config = c

	cert, err := tls.X509KeyPair([]byte(config.Certs.Cert), []byte(config.Certs.Key))
	if err != nil {
		log.Fatal(err)
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
				debug.Println("Failed to accept connection:", err)
			} else {
				debug.Println("Accept connection:", clientConn.RemoteAddr())
				go newProxyHandler(clientConn)
			}
		}
	}()

	return sshNetListener
}
