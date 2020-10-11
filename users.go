package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"time"
)

/*
type User struct {
	Name  string
	Token string
	Ssh   string
}

var users map[string]User
var tokens map[string]User
*/

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

var users map[string]User
var tokens map[string]string

func b64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func genToken() (ret Token) {
	buf := make([]byte, 510)
	_, _ = rand.Read(buf)
	ret.Value = b64(string(buf))
	// default expiry time set to 1 minute for testing
	ret.Expire = time.Now().Add(1 * time.Minute)
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

	// rotate tokens if they're about to expire (30 seconds for testing)
	if users[name].Token.Expire.Before(time.Now().Add(30 * time.Second)) {
		// delete the old token from the tokens list
		delete(tokens, users[name].OldToken.Value)
		user := users[name]
		user.OldToken = users[name].Token
		user.Token = genToken()
		users[name] = user
		tokens[users[name].Token.Value] = name
	}
	return users[name].Token.Value
}

// GetNameFromToken returns a username for an unexpired token
// otherwise it returns ""
func GetNameFromToken(token string) string {
	if username, ok := tokens[token]; ok {
		if ((users[tokens[token]].Token.Value == token) &&
			(time.Now().Before(users[tokens[token]].Token.Expire))) || (users[tokens[token]].OldToken.Value == token &&
			time.Now().Before(users[tokens[token]].OldToken.Expire)) {

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