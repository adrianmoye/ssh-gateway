ssh-gateway
===========

This provides a simple ssh authentication gateway to kubernetes.

It uses the exec plugin to use ssh portforwarding to the api server, using ssh keys to authenticate usernames.

Installation is as simple as deploying a pod, exposing it to the outside, adding users then deploying relevant RBAC for your users.


How it works
------------


There are two main modes, the serviceaccount mode uses service accounts for authentication, it passes the traffic through directly and you use the service account token for auth.

The impersonate mode uses [Impersonate-User](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation) header using the service account of the pod.

    /ssh-gateway --help
    Usage of /ssh-gateway:
      -config string
        	Config Secret Name (default "ssh-gateway-config")
      -mode string
        	Operating mode (serviceaccount|impersonate) (default "impersonate")
      -port string
        	Listen Port (default "2200")
      -resource string
        	Resource type for user records (default "serviceaccounts")


To use it
---------

Deploy the container in a dedicated namespace and expose the port. Give the container a service account either with "cluster-admin" access for the "impersonate" mode, or with access to read service account and secret resources in it's namespace for the "serviceaccount" mode.

To use it create a resource with the desired username, and then annotate the the resource with the ssh key:

    $ kubectl create sa -n users user
    $ kubectl annotate -n users --overwrite sa user ssh="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQE....7ywzbQ== user@example.com"

    $ ssh user@k8s.example.net -p 2200
    Kubernetes ssh gateway, to use install the kubectl plugin:
      
      ssh <user@host> plugin > kubectl-ssh
      chmod 755 kubectl-ssh
      sudo mv kubectl-ssh /usr/local/bin
      
      kubectl ssh <user@host>
    	 This sets up a ssh proxy and auth.
      
      Commands:
    	token : provides an authentication token.
    	login : provides login information.
    	plugin : provides a plugin.
      
    Shared connection to k8s.example.net closed.

    kubectl ssh user@k8s.example.net -p 2200
    Configuring cluster and adding context: user-user@k8s.example.net
    Cluster "user-user@k8s.example.net" set.
    Property "clusters.user-user@k8s.example.net.certificate-authority-data" set.
    User "user-user@k8s.example.net" set.
    Context "user-user@k8s.example.net" modified.
    Switched to context "user-user@k8s.example.net".
    
    Done, to test: kubectl cluster-info



Building
--------

To build the container:

    ./build_docker.sh

I use for testing:

    ./build.sh


