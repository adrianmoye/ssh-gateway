package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
)

// =======================

// https://gist.github.com/devinodaniel/8f9b8a4f31573f428f29ec0e884e6673
// This shows an example of how to generate a SSH RSA Private/Public key pair and save it locally

// Keys container for public/private ssh keys
type Keys struct {
	BitSize    int
	PublicKey  []byte
	PrivateKey []byte
}

// GenKeys returns a pair of ssh public/private keys
func GenKeys() Keys {
	var keys Keys
	keys.BitSize = 4096
	privateKey, err := generatePrivateKey(keys.BitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	/*
		publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err.Error())
		}
	*/
	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	//	keys.PublicKey = publicKeyBytes
	keys.PrivateKey = privateKeyBytes

	return keys
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

/*
// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

*/
