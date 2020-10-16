ssh-gateway
===========

This provides a quick simple lightweight SSH authentication gateway to Kubernetes.

It uses the [kubectl exec auth plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins), to use ssh port-forwarding to the api server, using ssh keys to authenticate usernames.
This is designed to be easy to setup for end users and makes use of the [kubectl plugins](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/) mechanism.

Installation is as simple as deploying a pod, exposing it to the outside, adding users then deploying relevant RBAC for your users. There is no configuration necessary, however you can change some parameters.

How it works
------------

There are three main modes:

* The "serviceaccount" mode uses [service accounts](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens) for API authentication.
  * supports impersonation
  * requires access to SA and secrets in the namespace.
  * easy to setup.
* The "impersonate" mode uses [Impersonate-User](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation) header using the service account of the pod.
  * no support for impersonation
  * requires access its own secret and user records which could be of any type even a CRD in the namespace.
  * easy to setup.
* The "proxy" mode uses an [Authenticating Proxy](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authenticating-proxy), and sends the recommended "X-Remote-User" etc headers.
  * supports impersonation
  * requires access its own secret and user records which could be of any type even a CRD in the namespace.
  * more complex to setup.

The client proxies the SSH TCP forwarding channel to a local API proxy which then authenticates the connection, and passes the request onto the API server.
The local API proxy will automatically generate it's own CA, and a new cert every time it loads.

    /ssh-gateway --help
    Usage of /ssh-gateway:
      -config string
          Config Secret Name (default "ssh-gateway-config")
      -mode string
          Operating mode (serviceaccount|proxy|impersonate) (default "impersonate")
      -port string
          Listen Port (default "2200")
      -resource string
          Resource type for user records (default "serviceaccounts")

To use it
---------

Deploy the container in a dedicated namespace and expose the port. Give the container a service account either with "cluster-admin" access for the "impersonate" mode, or with access to read service account and secret resources in it's namespace for the "serviceaccount" mode.

If you wish to use the "proxy" mode, you will need to replace the auto-generated CA with the default one created by kubeadm in:

    $ ls /etc/kubernetes/pki/front-proxy-ca.*
    /etc/kubernetes/pki/front-proxy-ca.crt  /etc/kubernetes/pki/front-proxy-ca.key 

To use the gateway create a resource with the desired username, and then annotate the the resource with the ssh key(we use an SA here, but anything will do if you're not using "serviceaccount" mode), and the groups you'd like the user to be a member of:

    $ kubectl create sa -n users user
    $ kubectl annotate -n users --overwrite sa user ssh="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQE....7ywzbQ== user@example.com" groups="system:masters"

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

    $ kubectl ssh user@k8s.example.net -p 2200
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
