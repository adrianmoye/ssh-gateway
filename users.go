package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const TOKEN_LIFE = 30 * time.Minute
const TOKEN_REFRESH = 10 * time.Minute

// APIToken structured format for JSON api token
type APIToken struct {
	ApiVersion string            `json:"apiVersion"`
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
	Token    Token
	OldToken Token
}

var users map[string]User = make(map[string]User)
var tokens map[string]string = make(map[string]string)
var SATokens map[string]string = make(map[string]string)

func b64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func genToken() (ret Token) {
	buf := make([]byte, 510)
	_, _ = rand.Read(buf)
	ret.Value = b64(string(buf))
	// default expiry time
	ret.Expire = time.Now().Add(TOKEN_LIFE)
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
	if users[name].Token.Expire.Before(time.Now().Add(TOKEN_REFRESH)) {
		// delete the old token from the tokens list
		delete(tokens, users[name].OldToken.Value)
		user := users[name]
		user.OldToken = users[name].Token
		user.Token = genToken()
		users[name] = user
		tokens[users[name].Token.Value] = name
	}

	if config.OperationMode == "serviceaccount" {
		var SA Serviceaccount

		var secret Secret
		config.Api.Get("/api/v1/namespaces/"+config.Api.namespace+"/"+config.ResourceType+"/"+name, &SA)
		config.Api.Get(fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", config.Api.namespace, SA.Secrets[0].Name), &secret)
		saToken, _ := base64.StdEncoding.DecodeString(secret.Data["token"])
		SATokens[name] = "Bearer " + string(saToken)
	}

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

func writeAPIToken(name string) string {
	encodedToken := APIToken{
		ApiVersion: "client.authentication.k8s.io/v1beta1",
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
