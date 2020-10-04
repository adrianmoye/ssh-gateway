package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type apiConfig struct {
	namespace string
	host      string
	port      string
	token     string
	ca        string
	base      string
	bearer    string
	transport *http.Transport
}

type Metadata struct {
	Name          string            `json:"name"`
	Namespace     string            `json:"namespace"`
	Labels        map[string]string `json:"labels"`
	Annotations   map[string]string `json:"annotations"`
	ManagedFields []interface{}     `json:"managedFields"`
}

type Secret struct {
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   Metadata          `json:"metadata"`
	Data       map[string]string `json:"data"`
}

type ServiceaccountSecrets struct {
	Name string `json:"name"`
}
type Serviceaccount struct {
	ApiVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	Metadata   Metadata                `json:"metadata"`
	Secrets    []ServiceaccountSecrets `json:"secrets"`
}
type ServiceAccountEvent struct {
	Type           string         `json:"type"`
	ServiceAccount Serviceaccount `json:"object"`
}

type GenericHeader struct {
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   Metadata          `json:"metadata"`
}

type APIToken struct {
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Status     map[string]string `json:"status"`
}

type User struct {
	Name  string
	Token string
	Ssh   string
}

var users map[string]User

func (api apiConfig) Post(request string, deliver interface{}) {

	content, err := json.Marshal(deliver)
	if err != nil {
		log.Println(err)
	}
	length := len(content)

	client := &http.Client{Transport: api.transport}
	reader := strings.NewReader(string(content))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", api.base, request), reader)
	if err != nil {
		log.Println(err)
	}
	req.Header.Add("Authorization", api.bearer)
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

func (api apiConfig) Get(request string, reply interface{}) {
	client := &http.Client{Transport: api.transport}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s%s", api.base, request), nil)
	if err != nil {
		log.Println(err)
	}
	req.Header.Add("Authorization", api.bearer)
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
	}
	return string(v)
}

func getApiClientConfig() apiConfig {
	var config apiConfig

	config.host = os.Getenv("KUBERNETES_SERVICE_HOST")
	config.port = os.Getenv("KUBERNETES_SERVICE_PORT")
	config.namespace = readfile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	config.token = readfile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	config.ca = readfile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

	config.base = fmt.Sprintf("https://%s:%s", config.host, config.port)
	config.bearer = fmt.Sprintf("Bearer %s", config.token)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(config.ca))

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	config.transport = &http.Transport{TLSClientConfig: tlsConfig}

	return config
}

func genToken() string {
	buf := make([]byte, 510)
	_, _ = rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func b64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func CheckKey(name string, key ssh.PublicKey) bool {
	var SA Serviceaccount
	var GenRes GenericHeader
	var secret Secret
	var ssh_key string

	if config.OperationMode == "impersonate" {
		config.Api.Get("/api/v1/namespaces/"+config.Api.namespace+"/"+config.ResourceType+"/"+ name, &GenRes)

		if t, ok := GenRes.Metadata.Annotations["ssh"]; ok {
			ssh_key = t
		}
	}else {
		config.Api.Get("/api/v1/namespaces/"+config.Api.namespace+"/"+config.ResourceType+"/"+ name, &SA)
		if t, ok := SA.Metadata.Annotations["ssh"]; ok {
			ssh_key = t
		}
	}
	// log.Println("request: ","/api/v1/namespaces/"+config.Api.namespace+"/"+config.ResourceType+"/"+ name)

	
	if len(ssh_key) >0 {
		pubkey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(ssh_key))
		if string(key.Marshal()) == string(pubkey.Marshal()) {
			//var token []byte
			if config.OperationMode == "impersonate" {
				token := []byte(genToken())
				//token := "test_token"

				users[name] = User{
					Name:  name,
					Token: string(token),
					Ssh:   string(key.Marshal()),
				}

			} else {

				config.Api.Get(fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", config.Api.namespace, SA.Secrets[0].Name), &secret)
				token, _ := base64.StdEncoding.DecodeString(secret.Data["token"])

				users[name] = User{
					Name:  name,
					Token: string(token),
					Ssh:   string(key.Marshal()),
				}

			}
			return true
		}
	}
	return false
}

func GetToken(name string) string {
	return users[name].Token
}

func writeAPIToken(token string) string {
	encoded_token := APIToken{
		ApiVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
	}
	encoded_token.Status = make(map[string]string)
	encoded_token.Status["token"] = token
	content, err := json.Marshal(encoded_token)
	if err != nil {
		log.Println(err)
	}
	return string(content)
}

func GetNameFromToken(token string) User {
	for _, user := range users {
		if user.Token == token {
			return user
		}
	}
	return User{}
}
