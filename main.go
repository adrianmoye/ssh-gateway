package main

import (
	"log"
	"net/http"

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
	config.Listener = httpsServer(config.ProxyCert)

	log.Println("registering http handler")
	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))

	log.Println("Starting metrics server")
	go func() { log.Fatal(http.ListenAndServe(":4141", nil)) }()

	log.Println("Starting SSH server")
	SSHServer()

}
