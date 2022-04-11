package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"fmt"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func main() {
	// Set up a /hello resource handler
	http.HandleFunc("/hello", helloHandler)

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs: caCertPool,
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// Require client certificates (or VerifyConnection will run anyway and
		// panic accessing cs.PeerCertificates[0]) but don't verify them with the
		// default verifier. This will not disable VerifyConnection.
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			fmt.Printf("VerifyConnection client %s\n", cs.ServerName)
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Roots:         caCertPool,
				// Intermediates: x509.NewCertPool(),
				// KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			for i, cert := range cs.PeerCertificates[0:] {
				cn := cert.Subject.CommonName
				fmt.Printf("cert[%d], CN='%s'\n", i, cn)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}