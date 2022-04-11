package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"contoso.org/utils" //https://github.com/drov0/GolangLocalModulesExample
)

func main() {
	pemKey, err := utils.NewPEMCrypto(&utils.PEM{
		PrivatePEMFile: "rsakey.pem",
		PublicCertFile: "cert.pem",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	cert := pemKey.TLSCertificate()

	// Read the key pair to create certificate
	// cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
				Certificates: []tls.Certificate{ cert },
				// Set InsecureSkipVerify to skip the default validation we are
				// replacing. This will not disable VerifyConnection.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					fmt.Printf("VerifyConnection server %s\n", cs.ServerName)
					opts := x509.VerifyOptions{
						DNSName:       cs.ServerName,
						Intermediates: x509.NewCertPool(),
					}
					for i, cert := range cs.PeerCertificates[0:] {
						cn := cert.Subject.CommonName
						fmt.Printf("cert[%d], CN='%s'\n", i, cn)
					}

					opts.Roots = caCertPool;
					_, err := cs.PeerCertificates[0].Verify(opts)
					return err
				},
			},
		},
	}

	// Request /hello via the created HTTPS client over port 8443 via GET
	r, err := client.Get("https://localhost:8443/hello")
	if err != nil {
		log.Fatal(err)
	}

	// Read the response body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response body to stdout
	fmt.Printf("%s\n", body)
}