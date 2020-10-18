package proxy

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"

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

var API = api.ClientConfig()

// proxyHandler provides the handler for ssh channel requests
// Arguments are handler func(ResponseWriter, *Request)
func proxyHandler(sshWriter http.ResponseWriter, sshReq *http.Request) {

	// lets do the auth stuff
	var userToken string
	if token, ok := sshReq.Header["Authorization"]; ok {
		userToken = regexp.MustCompilePOSIX("Bearer ").ReplaceAllString(token[0], "")
	} else {
		http.Error(sshWriter, "Unauthorized", http.StatusUnauthorized)
		log.Printf("FAILED REQ [%s][%s] [%s] [%s]\n", "UNKNOWN", sshReq.RemoteAddr, sshReq.Method, sshReq.URL.Path)
		return
	}
	//log.Printf(" user token\n[%s]\n[%s]\n",t,token)
	name := users.GetNameFromToken(userToken)
	if !(len(name) > 0) {
		http.Error(sshWriter, "Unauthorized", http.StatusUnauthorized)
		log.Printf("FAILED REQ [%s][%s] [%s] [%s]\n", "UNKNOWN", sshReq.RemoteAddr, sshReq.Method, sshReq.URL.Path)
		return
	}

	log.Printf("REQ [%s][%s] [%s] [%s]", sshReq.RemoteAddr, name, sshReq.Method, sshReq.URL.Path)

	//log.Printf("upgrade REQ [%s] [%s] [%s]\n", name, req.Method, req.URL.Path)

	connectHeader := make(http.Header)

	// depending on the operating mode we need to give
	// the appropriate headers to the API server.
	switch config.OperationMode {
	case "serviceaccount": // Give the SA token
		connectHeader.Set("Authorization", users.SATokens[name])
	case "proxy":
		// set appropriate headers
		connectHeader.Set("X-Remote-User", name)
		//log.Println("groups for ", name, " are ", users[name].Groups)
		if users.GetUser(name).Groups != nil {
			for _, group := range *users.GetUser(name).Groups {
				//log.Println("setgroup for ", name, ":", group)
				connectHeader.Set("X-Remote-Group", group)
			}
		}
	default: //  "impersonate"
		connectHeader.Set("Authorization", API.Bearer)
		connectHeader.Set("Impersonate-User", name)
		if users.GetUser(name).Groups != nil {
			for _, group := range *users.GetUser(name).Groups {
				connectHeader.Set("Impersonate-Group", group)
			}
		}
	}

	connectHeader.Set("X-Forwarded-For", sshReq.RemoteAddr)
	connectHeader.Set("Connection", "close")
	for _, h := range config.CopyHeaders {
		if val, ok := sshReq.Header[h]; ok {
			for i := range val {
				connectHeader.Add(h, val[i])
			}
		}
	}

	// set default proxying mode, and use this unless
	// they kubectl is trying to upgrade the connection.
	if _, ok := sshReq.Header["Upgrade"]; !ok {

		apiRequest := &http.Request{
			Method: sshReq.Method,
			URL: &url.URL{
				Scheme: "https",
				Host:   API.Dest,
				Path:   sshReq.URL.Path,
				//RawPath:  sshReq.URL.RawPath,
				RawQuery: sshReq.URL.RawQuery,
				//Opaque: API.base + sshReq.URL.Path + "?" + sshReq.URL.RawQuery,
			},
			Host:   API.Dest,
			Header: connectHeader,
			Body:   sshReq.Body,
		}
		transport := &http.Transport{TLSClientConfig: config.TLSConfig}
		client := &http.Client{Transport: transport}
		apiResponse, err := client.Do(apiRequest)
		if err != nil {
			log.Println("Req to API error", err)
			http.Error(sshWriter, err.Error(), http.StatusServiceUnavailable)
			return
		}

		for h := range apiResponse.Header {
			if val, ok := apiResponse.Header[h]; ok {
				for i := range val {
					sshWriter.Header().Add(h, val[i])
				}
			}
		}

		data, err := ioutil.ReadAll(apiResponse.Body)
		if err != nil {
			log.Println(err)
		}

		sshWriter.Write(data)

		return
	}

	apiConn, err := tls.Dial("tcp", API.Dest, config.TLSConfig)

	if err != nil {
		log.Println(err)
		http.Error(sshWriter, err.Error(), http.StatusServiceUnavailable)
		return
	}

	apiRequest := &http.Request{
		Method: sshReq.Method,
		URL:    &url.URL{Opaque: API.Base + sshReq.URL.Path + "?" + sshReq.URL.RawQuery},
		Host:   API.Dest,
		Header: connectHeader,
	}

	if err := apiRequest.Write(apiConn); err != nil {
		log.Println(err)
		apiConn.Close()
		return
	}
	//fmt.Println("Hijacking")

	hijacker, ok := sshWriter.(http.Hijacker)
	if !ok {
		log.Println(err)
		http.Error(sshWriter, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	//fmt.Println("getting client con")
	sshConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Println(err)
		http.Error(sshWriter, err.Error(), http.StatusServiceUnavailable)
		return
	}
	//log.Println("going to transfer mode")

	waitfor := make(chan bool)

	go func() {
		io.Copy(apiConn, sshConn)
		waitfor <- true
	}()
	go func() {
		io.Copy(sshConn, apiConn)
		waitfor <- true
	}()

	//log.Println("waiting to close")
	<-waitfor
	<-waitfor
	close(waitfor)

	sshConn.Close()
	apiConn.Close()

	//log.Println("closed")

}

// HttpsServer listens on an sshnet https connection
func HttpsServer(c Config) *sshnet.Listener {

	config = c

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler)

	cert, err := tls.X509KeyPair([]byte(config.Certs.Cert), []byte(config.Certs.Key))
	if err != nil {
		log.Fatal(err)
	}

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
		Certificates: []tls.Certificate{cert},
	}
	server := &http.Server{
		Handler:      mux,
		TLSConfig:    config.TLSConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// Create listener for ssh channels, and serve them
	// through a tls enabled webserver
	sshNetListener, _ := sshnet.Listen("0.0.0.0:" + config.Port)
	tlsListener := tls.NewListener(sshNetListener, config.TLSConfig)
	go server.Serve(tlsListener)
	return sshNetListener
}
