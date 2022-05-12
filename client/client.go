package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"contoso.org/utils"
)

func RunClient(uri string, certFile string, rootFile string) error {

	csKey, err := utils.NewWinCert(&utils.WinCert{
		PublicCertFile: certFile,
	})

	if err != nil {
		log.Println(err)
		return err
	}
	cert := csKey.TLSCertificate()

	rootCert, err := ioutil.ReadFile(rootFile)
	if err != nil {
		log.Fatal(err)
	}
	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(rootCert)

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				// Set InsecureSkipVerify to skip the default validation we are
				// replacing. This will not disable VerifyConnection.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if cs.PeerCertificates[0] == nil {
						return fmt.Errorf("server cert is null.")
					}

					log.Printf("VerifyConnection server %s\n", cs.ServerName)
					for i, cert := range cs.PeerCertificates[0:] {
						cn := cert.Subject.CommonName
						log.Printf("server cert[%d], CN='%s'\n", i, cn)
					}

					caCertPool := x509.NewCertPool()

					cert := cs.PeerCertificates[0]
					if len(cert.Extensions) > 0 {
						for _, ext := range cert.Extensions {
							if ext.Id.String() == "1.2.840.113556.1.8000.2554.197254.100" {
								log.Printf("client cert contains embedded CA")
								caCertPool.AppendCertsFromPEM(ext.Value)
							}
						}
					}

					opts := x509.VerifyOptions{
						// DNSName:       cs.ServerName, //comment it to ignore DNS name mismatch
						Roots:         rootCertPool,
						Intermediates: caCertPool,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					}

					_, err := cs.PeerCertificates[0].Verify(opts)
					if err != nil {
						log.Println(err)
					}

					return nil //ignore server cert error
				},
			},
		},
	}

	r, err := client.Get(uri)
	if err != nil {
		log.Fatal(err)
		return err
	}

	// Read the response body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response body to stdout
	log.Printf("%s\n", body)
	return nil
}
