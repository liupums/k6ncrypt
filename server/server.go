package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"contoso.org/utils"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func RunServer(certFile string, rootFile string) error {
	// Set up a /hello resource handler
	http.HandleFunc("/hello", helloHandler)

	csKey, err := utils.NewWinCert(&utils.WinCert{
		PublicCertFile: certFile,
	})

	if err != nil {
		log.Fatal(err)
		return err
	}

	cert := csKey.TLSCertificate()

	rootCert, err := ioutil.ReadFile(rootFile)
	if err != nil {
		log.Fatal(err)
		return err
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(rootCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// ClientCAs: rootCertPool,
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// Require client certificates (or VerifyConnection will run anyway and
		// panic accessing cs.PeerCertificates[0]) but don't verify them with the
		// default verifier. This will not disable VerifyConnection.
		ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.PeerCertificates[0] == nil {
				return fmt.Errorf("client cert is null.")
			}

			log.Printf("In VerifyConnection, client name: '%s'\n", cs.ServerName)
			for i, cert := range cs.PeerCertificates[0:] {
				cn := cert.Subject.CommonName
				log.Printf("client cert[%d], CN='%s'\n", i, cn)
			}

			err := utils.VerifyCertChainV3Cert(cs.PeerCertificates[0], rootCertPool)
			if err != nil {
				log.Println(err)
			}

			return err
		},
	}

	// tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS("", ""))
	return nil
}
