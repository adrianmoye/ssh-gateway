package main

import (
	"fmt"
	"log"
	"net"
	"regexp"

	"golang.org/x/crypto/ssh"
)

// helpTextTexplate default sshd server text
var helpTextTexplate = `Kubernetes ssh gateway, to use install the kubectl plugin:
  
  ssh <user@host> plugin > kubectl-ssh
  chmod 755 kubectl-ssh
  sudo mv kubectl-ssh /usr/local/bin
  
  kubectl ssh <user@host>
	 This sets up a ssh proxy and auth.
  
  Commands:
	token : provides an authentication token.
	login : provides login information.
	plugin : provides a plugin.
  
`

// SSHServer the ssh server main listener
func SSHServer() {

	// Listen for the raw tcp connections
	listener, err := net.Listen("tcp", "0.0.0.0:"+config.Port)
	if err != nil {
		log.Fatalf("Failed to listen on %s (%s)", config.Port, err)
	}

	// Accept all connections
	log.Printf("Listening on port [%s]...", config.Port)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		// pass the connection through to the ssh handler
		go handleSSHUpgrade(tcpConn)
	}
}

func genSSHServerConfig(privateBytes []byte) *ssh.ServerConfig {

	config := &ssh.ServerConfig{

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

			if CheckKey(conn.User(), key) {
				log.Printf("Login: [%s](%s)", conn.User(), conn.RemoteAddr())
				return &ssh.Permissions{
					CriticalOptions: map[string]string{
						"name": conn.User(),
						"addr": conn.RemoteAddr().String(),
					},
				}, nil
			}

			log.Printf("Failed Login: [%s](%s)", conn.User(), conn.RemoteAddr())

			return nil, fmt.Errorf("unknown public key")

		},

		// NoClientAuth: true,
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	return config
}

func handleSSHUpgrade(tcpConn net.Conn) {
	client, chans, reqs, err := ssh.NewServerConn(tcpConn, config.SSH)
	if err != nil {
		log.Printf("Failed to handshake (%s)", err)
		return
	}
	// Discard all global out-of-band Requests
	go ssh.DiscardRequests(reqs)
	// Accept all channels
	go handleChannels(client, chans)
}

func handleChannels(client *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		t := newChannel.ChannelType()

		switch t {
		case "session":
			go handleSession(client, newChannel)

		case "direct-tcpip":
			go handleDirectTcpip(client, newChannel)

		default:
			log.Printf("unknown new channel [%s]\n", t)
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("ERROR: unsupported channel type: %s", t))
		}
	}
}

/*
  This handles all of the direct tcp proxied connections.
  we treat the incoming connections casually, as they can either
  connect to the API server, or not, which should never happen under
  normal usage.
*/
func handleDirectTcpip(client *ssh.ServerConn, sshChan ssh.NewChannel) {

	/* we should unmarshal the payload to get the destination, but we don't care,
	   we'll just forward it to the api server anyway */
	connection, requests, err := sshChan.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}
	go ssh.DiscardRequests(requests)

	// We dial our local tls/webserver proxy
	// and pass through the ssh channel as though
	// it was a network connection.
	config.Listener.Dialer(client, connection)

}

/*
  This handles all of the normal ssh login and interactive events,
  everything except the tcp forwarding.
  Responsibilities include:
	* human help
	* api token requests
	* download kubectl plugin
	* get config for the plugin
*/
func handleSession(client *ssh.ServerConn, sshChan ssh.NewChannel) {
	connection, requests, err := sshChan.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	help := regexp.MustCompilePOSIX("\\n").ReplaceAllString(helpTextTexplate, "\r\n")
	name := client.Permissions.CriticalOptions["name"]

	for req := range requests {
		switch req.Type {
		case "pty-req":
		case "env":
		case "shell":
			log.Println(name+"@"+client.RemoteAddr().String(), " REQ SHELL HELP")
			if len(req.Payload) == 0 {
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}

			fmt.Fprintf(connection, help)

			connection.Close()
		case "exec":
			// dunno what the null padding is for? - maybe I should read docs?
			cmd := string(req.Payload[4:])
			switch cmd {
			case "plugin":
				log.Println(name+"@"+client.RemoteAddr().String(), " REQ PLUGIN")
				fmt.Fprintf(connection, "%s", PLUGIN)
			case "token":
				log.Println(name+"@"+client.RemoteAddr().String(), " REQ TOKEN")
				fmt.Fprintf(connection, writeAPIToken(name))
			case "login":
				log.Println(name+"@"+client.RemoteAddr().String(), " REQ LOGIN")
				fmt.Fprintf(connection, "%s %s %s %s\n", name, "kubernetes.default:443", "kubernetes.default", config.ProxyCA)
			default:
				log.Println(name+"@"+client.RemoteAddr().String(), " REQ COMMAND HELP")
				fmt.Fprintf(connection, help)
			}

			connection.Close()
		default:
			if req.WantReply {
				req.Reply(true, nil)
			}
			log.Printf("unknown req: [%s][%s]", req.Type, string(req.Payload))
		}

	}

}
