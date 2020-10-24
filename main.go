package main

import (
	"fmt"
	"net/http"

	"github.com/adrianmoye/ssh-gateway/src/log"
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

	log.Info("Starting Proxy", "server")
	config.Listener = proxy.Server(proxy.Config{
		OperationMode: config.OperationMode,
		SkipHeaders:   config.SkipHeaders,
		Port:          config.Port,
		Certs:         config.ProxyCert,
	})

	log.Info("Starting SSH server", "server")
	sshserver.Server(sshserver.Config{
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
	log.Info("Starting metrics server", "server")
	log.Info(fmt.Sprint(http.ListenAndServe(":4141", nil)), "server")

}
