package sshserver

import (
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/adrianmoye/ssh-gateway/src/log"
	"github.com/adrianmoye/ssh-gateway/src/sshnet"
	"github.com/adrianmoye/ssh-gateway/src/users"

	"github.com/prometheus/client_golang/prometheus"
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

// Config sshserver config
type Config struct {
	Port         string
	ServerConfig *ssh.ServerConfig
	Listener     sshnet.Listener
	ProxyCA      string
}

var config Config

// The Metrics that the module produces
type Metrics struct {
	Accept       prometheus.Counter
	LoginSuccess prometheus.Counter
	LoginFail    prometheus.Counter
}

func newMetrics() (ret Metrics) {
	ret = Metrics{
		Accept: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "sshserver",
				Name:      "accept_counter",
				Help:      "Number of accepted connections by listener",
			}),
		LoginSuccess: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "sshserver",
				Name:      "loginsuccess_counter",
				Help:      "Number of successful login attempts",
			}),
		LoginFail: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "sshserver",
				Name:      "loginfail_counter",
				Help:      "Number of failed login attempts",
			}),
	}

	prometheus.MustRegister(ret.Accept)
	prometheus.MustRegister(ret.LoginSuccess)
	prometheus.MustRegister(ret.LoginFail)

	return
}

var met Metrics = newMetrics()

// Server the ssh server main listener
func Server(c Config) {
	config = c

	// Listen for the raw tcp connections
	listener, err := net.Listen("tcp", "0.0.0.0:"+config.Port)
	if err != nil {
		log.Info("Failed to listen on "+config.Port+" "+fmt.Sprint(err), "server")
		os.Exit(1)
	}
	go listen(listener)
}

func listen(l net.Listener) {
	// Accept all connections
	log.Info("Listening on port ["+config.Port+"]...", "server")
	for {
		tcpConn, err := l.Accept()
		met.Accept.Add(1)
		if err != nil {
			log.Info("Failed to accept incoming connection ("+fmt.Sprint(err)+")", "server")
			continue
		}

		// pass the connection through to the ssh handler
		go handleSSHUpgrade(tcpConn)
	}
}

// GenSSHServerConfig generates the ssh server config from a private key
func GenSSHServerConfig(privateBytes []byte) *ssh.ServerConfig {

	config := &ssh.ServerConfig{

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

			if users.CheckKey(conn.User(), key) {
				log.Info("new connection", conn.User()+"@"+conn.RemoteAddr().String())
				met.LoginSuccess.Add(1)
				return &ssh.Permissions{
					CriticalOptions: map[string]string{
						"name": conn.User(),
						"addr": conn.RemoteAddr().String(),
					},
				}, nil
			}

			log.Info("Failed Login:", conn.User()+"@"+conn.RemoteAddr().String())
			met.LoginFail.Add(1)
			return nil, fmt.Errorf("unknown public key")

		},

		// NoClientAuth: true,
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Info("Failed to parse private key", "server")
		os.Exit(1)
	}

	config.AddHostKey(private)

	return config
}

func handleSSHUpgrade(tcpConn net.Conn) {
	client, chans, reqs, err := ssh.NewServerConn(tcpConn, config.ServerConfig)
	if err != nil {
		log.Info("Failed to handshake "+fmt.Sprint(err), client.User()+"@"+client.RemoteAddr().String())
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
			log.Info("unknown new channel ["+fmt.Sprint((t))+"]\n", client.User()+"@"+client.RemoteAddr().String())
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
		log.Info("Could not accept channel ("+fmt.Sprint(err)+")", client.User()+"@"+client.RemoteAddr().String())
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
		log.Info("Could not accept channel ("+fmt.Sprint(err)+")", client.User()+"@"+client.RemoteAddr().String())

		return
	}

	help := regexp.MustCompilePOSIX("\\n").ReplaceAllString(helpTextTexplate, "\r\n")
	name := client.Permissions.CriticalOptions["name"]
	idString := name + "@" + client.RemoteAddr().String()

	for req := range requests {
		switch req.Type {
		case "pty-req":
		case "env":
		case "shell":
			log.Info("help", idString)
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
				log.Info("plugin", idString)
				fmt.Fprintf(connection, "%s", PLUGIN)
			case "token":
				log.Info("token", idString)
				fmt.Fprintf(connection, users.WriteAPIToken(name))
			case "login":
				log.Info("login", idString)
				fmt.Fprintf(connection, "%s %s %s %s\n", name, "kubernetes.default:443", "kubernetes.default", config.ProxyCA)
			default:
				log.Info("default help", idString)
				fmt.Fprintf(connection, help)
			}

			connection.Close()
		default:
			if req.WantReply {
				req.Reply(true, nil)
			}
			log.Info("unknown request ["+req.Type+"]["+string(req.Payload)+"]", idString)
		}

	}

}
