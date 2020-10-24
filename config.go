package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"log"

	"golang.org/x/crypto/ssh"

	"github.com/adrianmoye/ssh-gateway/src/api"
	"github.com/adrianmoye/ssh-gateway/src/gencert"
	"github.com/adrianmoye/ssh-gateway/src/sshnet"
	"github.com/adrianmoye/ssh-gateway/src/sshserver"
	"github.com/adrianmoye/ssh-gateway/src/users"
)

type gwConfig struct {
	API           api.Config
	Port          string
	SSH           *ssh.ServerConfig
	ProxyCert     gencert.RawPEM
	ProxyCA       string
	TLSConfig     *tls.Config
	OperationMode string
	SecretName    string
	ResourceType  string
	APIGroup      string
	SkipHeaders   []string
	Listener      *sshnet.Listener
}

func setupConfig() gwConfig {
	var config gwConfig

	flagPort := flag.String("port", "2200", "Listen Port")
	flagConfigSecret := flag.String("config", "ssh-gateway-config", "Config Secret Name")
	flagOperatingMode := flag.String("mode", "impersonate", "Operating mode (serviceaccount|proxy|impersonate)")
	flagResourceType := flag.String("resource", "serviceaccounts", "Resource type for user records")
	flagAPIGroup := flag.String("apigroup", "/v1", "The api group to use, for crds you should start it \"s/example.com/v1\"")
	flag.Parse()

	config.Port = *flagPort
	config.OperationMode = *flagOperatingMode
	config.SecretName = *flagConfigSecret
	config.ResourceType = *flagResourceType
	config.APIGroup = *flagAPIGroup
	users.ResourceType = config.ResourceType

	config.API = api.ClientConfig()

	var secret api.Secret

	var updateSecret bool = false
	config.API.Get("/api/v1/namespaces/"+config.API.Namespace+"/secrets/"+config.SecretName, &secret)
	if secret.Data == nil {
		secret.Data = make(map[string]string)
	}
	if _, ok := secret.Data["sshd_key"]; !ok {
		keys := sshserver.GenKeys()
		secret.Data["sshd_key"] = base64.StdEncoding.EncodeToString(keys.PrivateKey)
		updateSecret = true
	}

	var CA gencert.RawPEM
	if _, ok := secret.Data["ca_cert"]; !ok {
		log.Println("Regenerating CA Cert")
		CA = gencert.GenCA("SSH Gateway CA")
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
	config.ProxyCert = gencert.SignedCert("kubernetes.default", CA)

	if updateSecret {
		secret.APIVersion = "v1"
		secret.Kind = "Secret"
		secret.Metadata.Name = config.SecretName
		secret.Metadata.Namespace = config.API.Namespace
		secret.Metadata.Labels = make(map[string]string)
		config.API.Post("/api/v1/namespaces/"+config.API.Namespace+"/secrets", &secret)
		log.Printf("Created secret with keys: [%s]\n", config.SecretName)
	}

	// now we have the server cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(config.API.CA))

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
	config.SSH = sshserver.GenSSHServerConfig(sshdKey)

	// decide which headers to pass through to the API server
	// depending on what mode we're in.

	switch config.OperationMode {
	case "serviceaccount":
		config.SkipHeaders = []string{"X-Remote-User", "X-Remote-Group"}
	case "proxy":
		config.SkipHeaders = []string{"X-Remote-User", "X-Remote-Group"}
	default: //  "impersonate"
		config.SkipHeaders = []string{"X-Remote-User", "X-Remote-Group", "Impersonate-User", "Impersonate-Group"}
	}

	return config
}
