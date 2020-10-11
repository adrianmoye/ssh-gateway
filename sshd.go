package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"

	"golang.org/x/crypto/ssh"
)

var HELP_TEMPLATE = `Kubernetes ssh gateway, to use install the kubectl plugin:
  
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

func SSHServer(port string, config *ssh.ServerConfig) {

	// Listen for the raw tcp connections
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", port))
	if err != nil {
		log.Fatalf("Failed to listen on %s (%s)", port, err)
	}

	// Accept all connections
	log.Printf("Listening on port [%s]...", port)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		// pass the connection through to the ssh handler
		go handleSshUpgrade(tcpConn, config)
	}
}

func genSshServerConfig(privateBytes []byte) *ssh.ServerConfig {

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

			return nil, fmt.Errorf("Unknown public key\n")

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

func handleSshUpgrade(tcpConn net.Conn, config *ssh.ServerConfig) {
	client, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
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
  we treat the incomming connections casually, as they can either
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

	if config.OperationMode == "impersonate" {

		// We dial our local tls/webserver proxy
		// and pass through the ssh channel as though
		// it was a network connection.
		config.Listener.Dialer(client, connection)

		return

	} else {

		dest := fmt.Sprintf("%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))

		destinationConnection, err := net.Dial("tcp", dest)
		if err != nil {
			log.Println("Failed to get tcp connection:", err.Error())
			return
		}

		go func() {
			io.Copy(connection, destinationConnection)
			destinationConnection.Close()
			connection.Close()
		}()
		go func() {
			io.Copy(destinationConnection, connection)
			destinationConnection.Close()
			connection.Close()
		}()

	}

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

	help := regexp.MustCompilePOSIX("\\n").ReplaceAllString(HELP_TEMPLATE, "\r\n")
	name := client.Permissions.CriticalOptions["name"]

	for req := range requests {
		switch req.Type {
		case "pty-req":
		case "env":
		case "shell":
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
				fmt.Fprintf(connection, "%s", PLUGIN)
			case "token":
				fmt.Fprintf(connection, writeAPIToken(GetToken(name)))
			case "login":
				if config.OperationMode == "impersonate" {
					fmt.Fprintf(connection, "%s %s %s %s\n", name, "kubernetes.default:443", "kubernetes.default", config.ProxyCA)
				} else {
					fmt.Fprintf(connection, "%s %s %s %s\n", name, "kubernetes.default:443", "kubernetes.default", b64(config.Api.ca))
				}
			default:
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
