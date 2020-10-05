package main

/*
env GOOS=linux GOARCH=amd64 go build sshd.go
*/

import (
	"encoding/base64"
	"flag"
	"log"

	"golang.org/x/crypto/ssh"
)

type gwConfig struct {
	Api           apiConfig
	Port          string
	Ssh           *ssh.ServerConfig
	ProxyCert     RawPEM
	ProxyCA       string
	OperationMode string
	SecretName    string
	ResourceType  string
}

var config gwConfig

func setupConfig() {

	PORT := flag.String("port", "2200", "Listen Port")
	CONFIG_SECRET := flag.String("config", "ssh-gateway-config", "Config Secret Name")
	OPERATING_MODE := flag.String("mode", "impersonate", "Operating mode (serviceaccount|impersonate)")
	RESOURCE_TYPE := flag.String("resource", "serviceaccounts", "Resource type for user records")
	flag.Parse()

	config.Port = *PORT
	config.OperationMode = *OPERATING_MODE
	config.SecretName = *CONFIG_SECRET
	config.ResourceType = *RESOURCE_TYPE

	config.Api = getApiClientConfig()

	users = make(map[string]User)

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
		CA = genCA("SSH Gateway CA")
		log.Println(string(CA.Cert))
		log.Println(string(CA.Key))
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
		log.Println("PUT SECRET")
		log.Println(secret)
	}

	//temp, _ := base64.StdEncoding.DecodeString(secret.Data["ca_cert"])
	//config.Api.ca = string(temp)
	sshd_key, _ := base64.StdEncoding.DecodeString(secret.Data["sshd_key"])
	config.Ssh = genSshServerConfig(sshd_key)

}

func main() {
	setupConfig()

	go https_server(config.ProxyCert)

	sshd_server(config.Port, config.Ssh)

}
