// https://github.com/salrashid123/signer/blob/master/example/sign_verify_pem/main.go
package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
	"encoding/hex"
)

const ()

var (
	x509Certificate    x509.Certificate
	publicKey          crypto.PublicKey
)

type PEM struct {
	crypto.Signer // implement crypto.Signer

	PublicCertFile string
	PrivatePEMFile string
	privateKey *rsa.PrivateKey
	refreshMutex       sync.Mutex
}

// Just to test crypto.Singer, crypto.Decrypt interfaces
// the following Decrypt and Sign functions uses ordinary private keys

func NewPEMCrypto(conf *PEM) (PEM, error) {
	if conf.PrivatePEMFile == "" {
		return PEM{}, fmt.Errorf("privateKey cannot be empoty")
	}

	privatePEM, err := ioutil.ReadFile(conf.PrivatePEMFile)
	if err != nil {
		return PEM{}, fmt.Errorf("Unable to read keys %v", err)
	}

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return PEM{}, fmt.Errorf("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return PEM{}, fmt.Errorf("Private Key must be RSA PKCS1 format: %v", err)
	}

	conf.privateKey = key
	return *conf, nil
}

func (t PEM) Public() crypto.PublicKey {
	return t.privateKey.Public().(crypto.PublicKey)
}

// Core function to implement crypto.Signer
func (t PEM) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	fmt.Printf("Sign is called\n")

	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("sal: Sign: Digest length doesn't match passed crypto algorithm")
	}

	var signature []byte
	var err error
	// RSA-PSS: https://github.com/golang/go/issues/32425
	
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		fmt.Printf("SignPSS is called\n")
		signature, err = rsa.SignPSS(rand.Reader, t.privateKey, opts.HashFunc(), digest, pssOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	} else {
		fmt.Printf("SignPKCS1v15 is called\n")
		signature, err = rsa.SignPKCS1v15(rand.Reader, t.privateKey, opts.HashFunc(), digest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
	}

	fmt.Printf("digest %s\n", hex.EncodeToString(digest))		
	fmt.Printf("sig %s\n", hex.EncodeToString(signature))		
	return signature, nil
}

func (t PEM) TLSCertificate() tls.Certificate {

	if t.PublicCertFile == "" {
		fmt.Printf("Public X509 certificate not specified")
		return tls.Certificate{}
	}

	pubPEM, err := ioutil.ReadFile(t.PublicCertFile)
	if err != nil {
		fmt.Printf("Unable to read keys %v", err)
		return tls.Certificate{}
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		fmt.Printf("failed to parse PEM block containing the public key")
		return tls.Certificate{}
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse public key: " + err.Error())
		return tls.Certificate{}
	}

	x509Certificate = *pub
	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        &x509Certificate,
		Certificate: [][]byte{x509Certificate.Raw},
	}
}
