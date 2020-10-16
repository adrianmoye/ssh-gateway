package main

/*
env GOOS=linux GOARCH=amd64 go build sshd.go
*/

var config gwConfig

func main() {

	config = setupConfig()

	config.Listener = httpsServer(config.ProxyCert)

	SSHServer()

}
