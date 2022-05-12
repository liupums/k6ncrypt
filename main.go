package main

import (
	"flag"
	"strings"

	"contoso.org/client"
	"contoso.org/server"
)

func main() {
	// variables declaration
	var action string
	var uri string
	var cert string
	var root string

	// flags declaration using flag package
	flag.StringVar(&action, "a", "server", "Specify action: server | client. Default is server")
	flag.StringVar(&uri, "u", "https://localhost:8443/hello", "Specify uri. Default is https://localhost:443/hello")
	flag.StringVar(&cert, "c", "cert.pem", "Specify client cert file location. Default is cert.pem")
	flag.StringVar(&root, "r", "cert.pem", "Specify root cert file location. Default is cert.pem")

	flag.Parse() // after declaring flags we need to call it

	// check if cli params match
	if strings.EqualFold(action, "server") {
		server.RunServer(cert, root)
	} else if strings.EqualFold(action, "client") {
		client.RunClient(uri, cert, root)
	}

}
