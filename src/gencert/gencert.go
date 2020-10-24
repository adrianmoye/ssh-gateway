package gencert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/adrianmoye/ssh-gateway/src/log"
)

// RawPEM just the raw bytes of the certs
type RawPEM struct {
	Key  []byte
	Cert []byte
}

// GenCA generates a generic CA with the CN provided
func GenCA(CN string) (OUT RawPEM) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   CN,
			Organization: []string{"Kubernetes SSH-API PROXY CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		DNSNames:              []string{CN},
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Info(fmt.Sprint(err), "server")
		os.Exit(1)
		return
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Info(fmt.Sprint(err), "server")
		os.Exit(1)
		return
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	OUT.Cert = caPEM.Bytes()
	OUT.Key = caPrivKeyPEM.Bytes()

	return
}

// DecodeCert (CA RawPEM) returns the x509 cert and key from the raw pem files
func DecodeCert(CA RawPEM) (cert *x509.Certificate, key *rsa.PrivateKey) {

	block, _ := pem.Decode(CA.Cert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Info(fmt.Sprint(err), "server")
		os.Exit(1)
	}
	block, _ = pem.Decode(CA.Key)
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Info(fmt.Sprint(err), "server")
		os.Exit(1)
	}

	return
}

// SignedCert pass in the CN of the cert and raw PEM, output the new certs raw PEM
func SignedCert(CN string, CA RawPEM) (OUT RawPEM) {

	CACert, CAKey := DecodeCert(CA)

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			CommonName:   "front-proxy-client",
			Organization: []string{"Kubernetes SSH-API PROXY CA"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		DNSNames:     []string{"front-proxy-client", CN},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//	KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Info(fmt.Sprint(err), "server")
		os.Exit(1)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, CACert, &certPrivKey.PublicKey, CAKey)
	if err != nil {
		log.Info(fmt.Sprint(err), "server")
		os.Exit(1)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	OUT.Cert = certPEM.Bytes()
	OUT.Key = certPrivKeyPEM.Bytes()
	log.Info("Generated server certs/keys", "server")

	return OUT
}
