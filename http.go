package main

import (
	"crypto/tls"
	//"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"

	"github.com/adrianmoye/ssh-gateway/src/sshnet"
)

// ProxyHandler provides the handler for ssh channel requests
// Arguments are handler func(ResponseWriter, *Request)
func ProxyHandler(w http.ResponseWriter, req *http.Request) {

	// lets do the auth stuff
	token := regexp.MustCompilePOSIX("Bearer ").ReplaceAllString(req.Header["Authorization"][0], "")
	//log.Printf(" user token\n[%s]\n[%s]\n",t,token)
	record := GetNameFromToken(token)
	if !(len(record) > 0) {
		log.Printf("FAILED REQ [%s][%s] [%s] [%s]\n", "UNKNOWN", req.RemoteAddr, req.Method, req.URL.Path)
		// TODO: handle failure better
		return
	}
	name := record

	//req.RemoteAddr

	log.Printf("REQ [%s][%s] [%s] [%s]", req.RemoteAddr, name, req.Method, req.URL.Path)

	//log.Printf("upgrade REQ [%s] [%s] [%s]\n", name, req.Method, req.URL.Path)

	//dest := config.Api.host + ":" + config.Api.port
	//dest := fmt.Sprintf("%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))

	destConn, err := tls.Dial("tcp", config.Api.dest, config.TlsConfig)

	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	connectHeader := make(http.Header)

	switch config.OperationMode {
	case "serviceaccount": // TODO, give the SA token
		connectHeader.Set("Authorization", config.Api.bearer)
	case "proxy":
		//connectHeader.Set("Authorization", config.Api.bearer)
		connectHeader.Set("X-Remote-User", name)
		connectHeader.Set("X-Remote-Group", name)
	default: //  "impersonate"
		connectHeader.Set("Authorization", config.Api.bearer)
		connectHeader.Set("Impersonate-User", name)
	}

	connectHeader.Set("X-Forwarded-For", req.RemoteAddr)
	connectHeader.Set("Connection", "close")
	for _, h := range config.CopyHeaders {
		if val, ok := req.Header[h]; ok {
			for i := range val {
				connectHeader.Set(h, val[i])
			}
		}
	}

	connectReq := &http.Request{
		Method: req.Method,
		URL:    &url.URL{Opaque: config.Api.base + req.URL.Path + "?" + req.URL.RawQuery},
		Host:   config.Api.dest,
		Header: connectHeader,
	}

	if err := connectReq.Write(destConn); err != nil {
		log.Println(err)
		destConn.Close()
		return
	}

	//fmt.Println("Hijacking")

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Println(err)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	//fmt.Println("getting client con")
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	//log.Println("going to transfer mode")

	waitfor := make(chan bool)

	go func() {
		io.Copy(destConn, clientConn)
		waitfor <- true
	}()
	go func() {
		io.Copy(clientConn, destConn)
		waitfor <- true
	}()

	//log.Println("waiting to close")
	<-waitfor
	<-waitfor
	close(waitfor)

	clientConn.Close()
	destConn.Close()

	//log.Println("closed")

}

func httpsServer(Certs RawPEM) *sshnet.Listener {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ProxyHandler)

	cert, err := tls.X509KeyPair([]byte(Certs.Cert), []byte(Certs.Key))
	if err != nil {
		log.Fatal(err)
	}

	cfg := &tls.Config{ /*
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
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// Create listener for ssh channels, and serve them
	// through a tls enabled webserver
	sshNetListener, _ := sshnet.Listen("0.0.0.0:" + config.Port)
	tlsListener := tls.NewListener(sshNetListener, cfg)
	go server.Serve(tlsListener)
	return sshNetListener
}
