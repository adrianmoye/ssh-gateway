package sshserver

// PLUGIN The default bash kubectl plugin authenticating
// with this server
const PLUGIN = `#!/bin/bash 
#
# kubectl plugin to setup an ssh tcp tunnel to an API server.
# 
# It will connect to a remote ssh server, download some configuration
# information and setup the KUBECONFIG file for connections to the
# cluster via the proxy.
# 
# kubectl will then call the script with some arguments, this will
# automatically setup an ssh tunnel and request an authentication
# token allowing the user to connect.


export LC_ALL=""

function HELP ()
{
	SN=$(basename $0 | sed 's/\-/ /g')
	echo "Use \"${SN} <ssh resource>\" to add a connection to a cluster."
	echo ""
	echo "  This manages ssh proxy/auth to clusters."
	echo ""
	echo "The only command:"
	echo "  ${SN} <ssh_user@ssh_host>"
	echo ""
	echo "This can be more complex, you can use normal ssh syntax as the"
	echo "arguments are passed straight through to ssh:"
	echo "  ${SN} <ssh_host> -l <ssh_user> -p <server_port>"
	echo ""
	exit 1
}

# run ssh to setup a control socket for the connection.
function SSH ()
{
	# control path/mux for ssh
	ssh \
	-o "ControlPath=~/.kube/ssh-%r@%h:%p" \
	-o "ControlMaster=auto" \
	-o "ControlPersist=10m" \
	${@}
}

# spit out the ssh arguments in a way that can be added
# to the kubeconfig via kubectl.
function ADD_ARGS ()
{
        while [[ "$1" ]]; do
                echo -n " --exec-arg=\"$1\" "
                shift
        done
}


case "$1" in
	auth)
		# kubectl <plugin> auth <context> <ssh listen port> <remote api:port> <... ssh args>
		shift
		CONTEXT="$1"
		shift
		PORT="$1"
		shift
		SERVER="$1"
		shift

		# request token from the remote endpoint.
		# this then gets sent back to kubectl.
		SSH $@ token
		# enable forwarding for the local tcp connection
		# to the kubernetes server endpoint via the ssh
		# tunnel.
		SSH $@ -O forward -L "${PORT}:${SERVER}"

		exit 0

	;;
	*)
		# always assume we're adding a new connection
		read USERNAME SERVER TLSNAME CA < <( ssh $@ login 2>/dev/null )

		# if we don't get a response, print the help.
		if [[ -z $USERNAME ]]; then
			echo "Error: unable to login to server." >&2
			HELP
		fi

		# generate a context name to use throughout
		# we use the context name for both the user and server
		# names
		CLUSTERNAME="$1"
		CONTEXT="${CLUSTERNAME}"
		echo "Configuring cluster and adding context: ${CONTEXT}"
		# generate random unused port - sorry, this is for us
		# to use for ssh to forward a local tcp port to the
		# api server.
		PORT=$(awk -F: 'function checkport(pt){for(i=0;i<n;i++)if(p[i]==pt)return 0;return 1}/server: https:\/\/127.0.0.1/{p[n++]=$4}END{while(1){srand(systime());s=sprintf("%d", 10000+rand()*10000);if(checkport(s)){printf s+0;exit 0}}}' ~/.kube/config)
		kubectl config set-cluster "${CONTEXT}" --server="https://127.0.0.1:${PORT}" --tls-server-name="${TLSNAME}"
	      	kubectl config set clusters.${CONTEXT}.certificate-authority-data "${CA}"
		kubectl config set-credentials "${CONTEXT}" \
			--exec-command="$0" \
			--exec-arg="auth" \
			--exec-arg="${CONTEXT}" \
			--exec-arg="${PORT}" \
			--exec-arg="${SERVER}" \
			$( ADD_ARGS $@ ) \
			--exec-api-version="client.authentication.k8s.io/v1beta1"
		kubectl config set-context "${CONTEXT}" --user="${CONTEXT}" --cluster="${CONTEXT}"
		kubectl config use-context "${CONTEXT}"
		echo
		echo "Done, to test: kubectl cluster-info"
	;;
esac`
