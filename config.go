package main

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
	API           apiConfig
	Port          string
	SSH           *ssh.ServerConfig
	ProxyCert     RawPEM
	ProxyCA       string
	TLSConfig     *tls.Config
	OperationMode string
	SecretName    string
	ResourceType  string
	CopyHeaders   []string
	Listener      *sshnet.Listener
}

func setupConfig() gwConfig {
	var config gwConfig

	flagPort := flag.String("port", "2200", "Listen Port")
	flagConfigSecret := flag.String("config", "ssh-gateway-config", "Config Secret Name")
	flagOperatingMode := flag.String("mode", "impersonate", "Operating mode (serviceaccount|proxy|impersonate)")
	flagResourceType := flag.String("resource", "serviceaccounts", "Resource type for user records")
	flag.Parse()

	config.Port = *flagPort
	config.OperationMode = *flagOperatingMode
	config.SecretName = *flagConfigSecret
	config.ResourceType = *flagResourceType

	config.API = getAPIClientConfig()

	var secret Secret

	var updateSecret bool = false
	config.API.Get("/api/v1/namespaces/"+config.API.namespace+"/secrets/"+config.SecretName, &secret)
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
		secret.APIVersion = "v1"
		secret.Kind = "Secret"
		secret.Metadata.Name = config.SecretName
		secret.Metadata.Namespace = config.API.namespace
		secret.Metadata.Labels = make(map[string]string)
		config.API.Post("/api/v1/namespaces/"+config.API.namespace+"/secrets", &secret)
		log.Printf("Created secret with keys: [%s]\n", config.SecretName)
	}

	// now we have the server cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(config.API.ca))

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
	config.TLSConfig = tlsConfig

	sshdKey, _ := base64.StdEncoding.DecodeString(secret.Data["sshd_key"])
	config.SSH = genSSHServerConfig(sshdKey)

	// decide which headers to pass through to the API server
	// depending on what mode we're in.
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