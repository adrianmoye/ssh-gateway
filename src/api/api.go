package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// Config The API config
type Config struct {
	Namespace string
	Host      string
	Port      string
	Token     string
	CA        string
	Dest      string
	Base      string
	Bearer    string
	Transport *http.Transport
}

// Metadata standard metadata k8s structure
type Metadata struct {
	Name          string            `json:"name"`
	Namespace     string            `json:"namespace"`
	Labels        map[string]string `json:"labels"`
	Annotations   map[string]string `json:"annotations"`
	ManagedFields []interface{}     `json:"managedFields"`
}

// Secret standard structure of a k8s secret
type Secret struct {
	APIVersion string            `json:"APIVersion"`
	Kind       string            `json:"kind"`
	Metadata   Metadata          `json:"metadata"`
	Data       map[string]string `json:"data"`
}

// ServiceaccountSecrets The secret field for a service account token
type ServiceaccountSecrets struct {
	Name string `json:"name"`
}

// Serviceaccount Standard k8s service account object
type Serviceaccount struct {
	APIVersion string                  `json:"APIVersion"`
	Kind       string                  `json:"kind"`
	Metadata   Metadata                `json:"metadata"`
	Secrets    []ServiceaccountSecrets `json:"secrets"`
}

// ServiceAccountEvent - currently unused
type ServiceAccountEvent struct {
	Type           string         `json:"type"`
	ServiceAccount Serviceaccount `json:"object"`
}

// GenericHeader generic k8s header format so we can use any object type.
type GenericHeader struct {
	APIVersion string   `json:"APIVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
}

// Post a JSON data structure to the API request string
func (api Config) Post(request string, deliver interface{}) {

	content, err := json.Marshal(deliver)
	if err != nil {
		log.Println(err)
	}
	length := len(content)

	client := &http.Client{Transport: api.Transport}
	reader := strings.NewReader(string(content))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", api.Base, request), reader)
	if err != nil {
		log.Println(err)
	}
	req.Header.Add("Authorization", api.Bearer)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", length))

	if err != nil {
		log.Println(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	content, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
	}
	resp.Body.Close()
	if err != nil {
		log.Println(err)
	}
}

// Get a data structure from the request string
func (api Config) Get(request string, reply interface{}) {
	client := &http.Client{Transport: api.Transport}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s%s", api.Base, request), nil)
	if err != nil {
		log.Println(err)
	}
	req.Header.Add("Authorization", api.Bearer)
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Println(err)
	}
	err = json.Unmarshal(content, reply)
	if err != nil {
		log.Println(err)
	}
}

func readfile(name string) string {
	v, e := ioutil.ReadFile(name)
	if e != nil {
		log.Println(e)
		log.Println("Kubernetes pod environment not detected")
		log.Fatal("access to service account files is required")
	}
	return string(v)
}

// ClientConfig Returns the API config
func ClientConfig() Config {
	var config Config

	config.Host = os.Getenv("KUBERNETES_SERVICE_HOST")
	config.Port = os.Getenv("KUBERNETES_SERVICE_PORT")
	config.Namespace = readfile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	config.Token = readfile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	config.CA = readfile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

	config.Dest = config.Host + ":" + config.Port
	config.Base = "https://" + config.Dest
	config.Bearer = fmt.Sprintf("Bearer %s", config.Token)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(config.CA))

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		//Certificates: []tls.Certificate{cert},
		RootCAs: caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	config.Transport = &http.Transport{TLSClientConfig: tlsConfig}

	return config
}
