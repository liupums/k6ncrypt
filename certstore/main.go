// The cli application implements the end-user client for the Splice service.
package main

import (
	"fmt"
	"strings"
	"github.com/google/certtostore"
)

var (
	issuers []string
)

func main() {
	issuers = strings.Split("localhost", ",")
	fmt.Println("open cert store")

	// Open the local cert store. Provider generally shouldn't matter, so use Software which is ubiquitous. See comments in getHostKey.
	store, err := certtostore.OpenWinCertStore(certtostore.ProviderMSSoftware, "", issuers, nil, false)
	
	if err != nil {
		fmt.Errorf("OpenWinCertStore: %v", err)
		return
	}	
	
	fmt.Println("get cert from cert store")
	// Obtain the first cert matching all of container/issuers/intermediates in the store.
	// This function is indifferent to the provider the store was opened with, as the store lists certs
	// from all providers.
	crt, context, err := store.CertWithContext()
	if err != nil {
		fmt.Println("failed to get cert from cert store. ", err)
		return
	}
	
	if crt == nil {
		fmt.Println("no cert")
		return
	}

	fmt.Println("get key from cert")
	// Obtain the private key from the cert. This *should* work regardless of provider because
	// the key is directly linked to the certificate.
	key, err := store.CertKey(context)
	if err != nil {
		fmt.Printf("private key not found in %s, %s", store.ProvName, err)
		return
	}

	if key == nil {
		fmt.Println("no key")
		return
	}

	fmt.Printf("find cert %s with private key\n", crt.Subject)

}