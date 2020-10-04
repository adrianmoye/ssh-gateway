package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"io"
	"regexp"
	"fmt"
	"os"
)

func ProxyHandler(w http.ResponseWriter, req *http.Request) {


	// lets do the auth stuff
	token := regexp.MustCompilePOSIX("Bearer ").ReplaceAllString(req.Header["Authorization"][0], "")
	//log.Printf(" user token\n[%s]\n[%s]\n",t,token)
	record := GetNameFromToken(token)
	if !(len(record.Name) > 0) {
		log.Printf("FAILED REQ  [%s] [%s] [%s]\n", "UNKNOWN", req.Method, req.URL.Path)
		// TODO: handle failure better
		return
	}
	name := record.Name

	log.Printf("REQ [%s] [%s] [%s]\n", name, req.Method, req.URL.Path)


	dest := fmt.Sprintf("%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))
	dest_conn, err := tls.Dial("tcp", dest, config.Api.transport.TLSClientConfig)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	connectHeader := make(http.Header)
	connectHeader.Set("Authorization", config.Api.bearer)
	connectHeader.Set("Impersonate-User", name)
	connectHeader.Set("Connection", "close")
	for _, h := range []string{"Accept", "Accept-Encoding", "Connection", "Content-Length", "Content-Type", "User-Agent", "X-Stream-Protocol-Version", "Upgrade"} {
		if val, ok := req.Header[h]; ok {
			for i := range val {
				connectHeader.Set(h, val[i])
			}
		}
	}

	connectReq := &http.Request{
		Method: req.Method,
		URL:    &url.URL{Opaque: config.Api.base + req.URL.Path + "?" + req.URL.RawQuery},
		Host:   dest,
		Header: connectHeader,
	}

	if err := connectReq.Write(dest_conn); err != nil {
		log.Println(err)
		dest_conn.Close()
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
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	//log.Println("going to transfer mode")

	waitfor := make(chan bool)

	go func() {
		io.Copy(dest_conn, client_conn)
		waitfor <- true
	}()
	go func() {
		io.Copy(client_conn, dest_conn)
		waitfor <- true
	}()

	//log.Println("waiting to close")
	<-waitfor

	client_conn.Close()
	dest_conn.Close()
	//log.Println("closed")

}

func https_server(Certs RawPEM) {
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

	unixListener, err := tls.Listen("unix", "@sshd", cfg)
	if err != nil {
		log.Println(err)
	}

	server.Serve(unixListener)

}