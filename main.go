package main

import (
	"log"
	"net/http"

	"github.com/adrianmoye/ssh-gateway/src/proxy"
	"github.com/adrianmoye/ssh-gateway/src/sshserver"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/*
env GOOS=linux GOARCH=amd64 go build sshd.go
*/

var config gwConfig

func main() {

	config = setupConfig()

	log.Println("Starting Proxy")
	config.Listener = proxy.HTTPSServer(proxy.Config{
		OperationMode: config.OperationMode,
		CopyHeaders:   config.CopyHeaders,
		Port:          config.Port,
		Certs:         config.ProxyCert,
	})

	log.Println("Starting SSH server")
	sshserver.SSHServer(sshserver.Config{
		Port:         config.Port,
		ServerConfig: config.SSH,
		Listener:     *config.Listener,
		ProxyCA:      config.ProxyCA,
	})

	// a liveness probe
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	//log.Println("registering http handler")
	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))

	// lets hang on the metrics server
	log.Println("Starting metrics server")
	log.Fatal(http.ListenAndServe(":4141", nil))

}
