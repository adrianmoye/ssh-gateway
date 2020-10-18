package users

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/adrianmoye/ssh-gateway/src/api"
)

// TOKENLIFE the lifetime of proxy tokens we create
const TOKENLIFE = 30 * time.Minute

// TOKENREFRESH how long before expiry a token can be refreshed
const TOKENREFRESH = 10 * time.Minute

// API api client object
var API = api.ClientConfig()

// Config users helpers config
type Config struct {
	OperationMode string
	APIGroup      string
	ResourceType  string
}

var config Config

// APIToken structured format for JSON api token
type APIToken struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Status     map[string]string `json:"status"`
}

// Token local representation of user token with expire time
type Token struct {
	Value  string
	Expire time.Time
}

// User local user record, containing the username and tokens
type User struct {
	Username string
	Groups   *[]string
	Token    Token
	OldToken Token
}

// user records global
var users map[string]User = make(map[string]User)

// token lookup table to user names for quick searching
var tokens map[string]string = make(map[string]string)

// SATokens a cache of service account tokens for the user name
var SATokens map[string]string = make(map[string]string)

func b64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func genToken() (ret Token) {
	buf := make([]byte, 510)
	_, _ = rand.Read(buf)
	ret.Value = b64(string(buf))
	// default expiry time
	ret.Expire = time.Now().Add(TOKENLIFE)
	return
}

// GetToken returns the current token for a username
// updating the token if required.
func GetToken(name string) string {
	// if the user hasn't logged in before generate a new token
	if _, ok := users[name]; !ok {
		users[name] = User{
			Username: name,
			Token:    genToken(),
			OldToken: genToken(),
		}
		tokens[users[name].Token.Value] = name
		tokens[users[name].OldToken.Value] = name
	}

	// rotate tokens if they're about to expire within the refresh window
	if users[name].Token.Expire.Before(time.Now().Add(TOKENREFRESH)) {
		// delete the old token from the tokens list
		delete(tokens, users[name].OldToken.Value)
		user := users[name]
		user.OldToken = users[name].Token
		user.Token = genToken()
		users[name] = user
		tokens[users[name].Token.Value] = name
	}

	if config.OperationMode == "serviceaccount" {
		var SA api.Serviceaccount

		var secret api.Secret
		API.Get("/api/v1/namespaces/"+API.Namespace+"/"+config.ResourceType+"/"+name, &SA)
		API.Get(fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", API.Namespace, SA.Secrets[0].Name), &secret)
		saToken, _ := base64.StdEncoding.DecodeString(secret.Data["token"])
		SATokens[name] = "Bearer " + string(saToken)
	}

	GetGroups(name)

	return users[name].Token.Value
}

// GetNameFromToken returns a username for an unexpired token
// otherwise it returns ""
func GetNameFromToken(token string) string {
	if username, ok := tokens[token]; ok {
		if ((users[tokens[token]].Token.Value == token) &&
			(time.Now().Before(users[tokens[token]].Token.Expire))) ||
			((users[tokens[token]].OldToken.Value == token) &&
				(time.Now().Before(users[tokens[token]].OldToken.Expire))) {

			return username
		}
	}
	return ""
}

// WriteAPIToken returns an API token json object from a username
func WriteAPIToken(name string) string {
	encodedToken := APIToken{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
	}
	encodedToken.Status = make(map[string]string)
	// refresh token if it's getting old.
	encodedToken.Status["token"] = GetToken(name)
	encodedToken.Status["expirationTimestamp"] = users[name].Token.Expire.Format(time.RFC3339)

	content, err := json.Marshal(encodedToken)
	if err != nil {
		log.Println(err)
	}
	return string(content)
}

func split(in string) []string {
	return strings.FieldsFunc(in, func(c rune) bool {
		return c == ' ' || c == ','
	})
}

// GetGroups queries the API for a group list and
// adds a slice of strings as a list of groups to the user.
func GetGroups(name string) {
	var GenRes api.GenericHeader
	API.Get("/api"+config.APIGroup+"/namespaces/"+API.Namespace+"/"+config.ResourceType+"/"+name, &GenRes)
	if groupsString, ok := GenRes.Metadata.Annotations["groups"]; ok {
		user := users[name]
		grouplist := split(groupsString)
		user.Groups = &grouplist
		users[name] = user
	}
}

// GetUser returns a user object associated with a user
func GetUser(name string) (user User) {
	if _, ok := users[name]; ok {
		user = users[name]
	}
	return
}

// CheckKey checks an ssh public key for name against the api objects public key
func CheckKey(name string, key ssh.PublicKey) bool {

	var GenRes api.GenericHeader
	var sshKey string

	API.Get("/api"+config.APIGroup+"/namespaces/"+API.Namespace+"/"+config.ResourceType+"/"+name, &GenRes)
	log.Println("Querying user", "/api"+config.APIGroup+"/namespaces/"+API.Namespace+"/"+config.ResourceType+"/"+name)
	if t, ok := GenRes.Metadata.Annotations["ssh"]; ok {
		sshKey = t
	}
	// log.Println("request: ","/api/v1/namespaces/"+Api.namespace+"/"+config.ResourceType+"/"+ name)

	if len(sshKey) > 0 {
		pubkey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(sshKey))
		if string(key.Marshal()) == string(pubkey.Marshal()) {
			return true
		}
	}
	return false
}
