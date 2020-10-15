package main

/*
env GOOS=linux GOARCH=amd64 go build sshd.go
*/

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"log"

	"github.com/adrianmoye/ssh-gateway/src/sshnet"
	"golang.org/x/crypto/ssh"
)

type gwConfig struct {
	Api           apiConfig
	Port          string
	Ssh           *ssh.ServerConfig
	ProxyCert     RawPEM
	ProxyCA       string
	TlsConfig     *tls.Config
	OperationMode string
	SecretName    string
	ResourceType  string
	CopyHeaders   []string
	Listener      *sshnet.Listener
}

func setupConfig() gwConfig {
	var config gwConfig

	PORT := flag.String("port", "2200", "Listen Port")
	CONFIG_SECRET := flag.String("config", "ssh-gateway-config", "Config Secret Name")
	OPERATING_MODE := flag.String("mode", "impersonate", "Operating mode (serviceaccount|proxy|impersonate)")
	RESOURCE_TYPE := flag.String("resource", "serviceaccounts", "Resource type for user records")
	flag.Parse()

	config.Port = *PORT
	config.OperationMode = *OPERATING_MODE
	config.SecretName = *CONFIG_SECRET
	config.ResourceType = *RESOURCE_TYPE

	config.Api = getApiClientConfig()

	var secret Secret

	var updateSecret bool = false
	config.Api.Get("/api/v1/namespaces/"+config.Api.namespace+"/secrets/"+config.SecretName, &secret)
	if secret.Data == nil {
		secret.Data = make(map[string]string)
	}
	if _, ok := secret.Data["sshd_key"]; !ok {
		keys := GenKeys()
		secret.Data["sshd_key"] = base64.StdEncoding.EncodeToString(keys.PrivateKey)
		updateSecret = true
	}

	var CA RawPEM
	if _, ok := secret.Data["ca_cert"]; !ok {
		log.Println("Regenerating CA Cert")
		CA = genCA("SSH Gateway CA")
		//log.Println(string(CA.Cert))
		//log.Println(string(CA.Key))
		secret.Data["ca_cert"] = base64.StdEncoding.EncodeToString([]byte(CA.Cert))
		secret.Data["ca_key"] = base64.StdEncoding.EncodeToString([]byte(CA.Key))
	}
	config.ProxyCA = secret.Data["ca_cert"]
	c, err := base64.StdEncoding.DecodeString(secret.Data["ca_cert"])
	if err != nil {
		log.Fatal(err)
	}
	k, err := base64.StdEncoding.DecodeString(secret.Data["ca_key"])
	if err != nil {
		log.Fatal(err)
	}
	CA.Cert, CA.Key = c, k
	config.ProxyCert = SignedCert("kubernetes.default", CA)

	if updateSecret {
		secret.ApiVersion = "v1"
		secret.Kind = "Secret"
		secret.Metadata.Name = config.SecretName
		secret.Metadata.Namespace = config.Api.namespace
		secret.Metadata.Labels = make(map[string]string)
		config.Api.Post("/api/v1/namespaces/"+config.Api.namespace+"/secrets", &secret)
		log.Printf("Created secret with keys: [%s]\n", config.SecretName)
	}
	// now we have the server cert
	//config.Api.UpdateTransport(config.ProxyCert)
	//updateTlsConfig()
	//config.Api.transport.TLSClientConfig.ClientCAs.AppendCertsFromPEM(CA.Cert)
	//config.Api.transport.TLSClientConfig.ClientCAs.AppendCertsFromPEM([]byte(config.Api.ca))

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(config.Api.ca))

	//log.Println("keycert:", ProxyCert)
	cert, err := tls.X509KeyPair(config.ProxyCert.Cert, config.ProxyCert.Key)
	if err != nil {
		log.Panic(err)
	}

	//log.Println("keycert past fatal:", ProxyCert)
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	config.TlsConfig = tlsConfig

	sshd_key, _ := base64.StdEncoding.DecodeString(secret.Data["sshd_key"])
	config.Ssh = genSshServerConfig(sshd_key)

	switch config.OperationMode {
	case "serviceaccount":
		config.CopyHeaders = []string{"Accept", "Accept-Encoding", "Connection", "Content-Length", "Content-Type", "Impersonate-Group", "Impersonate-User", "User-Agent", "X-Stream-Protocol-Version", "Upgrade"}
	case "proxy":
		config.CopyHeaders = []string{"Accept", "Accept-Encoding", "Connection", "Content-Length", "Content-Type", "Impersonate-Group", "Impersonate-User", "User-Agent", "X-Stream-Protocol-Version", "Upgrade"}
	default: //  "impersonate"
		config.CopyHeaders = []string{"Accept", "Accept-Encoding", "Connection", "Content-Length", "Content-Type", "User-Agent", "X-Stream-Protocol-Version", "Upgrade"}
	}

	return config
}

var config gwConfig

func main() {
	config = setupConfig()

	config.Listener = httpsServer(config.ProxyCert)

	SSHServer()

}
