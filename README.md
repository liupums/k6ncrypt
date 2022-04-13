# k6ncrypt
## Prepare cert and private key
### Run as admin
C:\k6ncrypt>createcert.cmd
```
C:\k6ncrypt>.\createcert.cmd

C:\k6ncrypt>openssl req -config openssl.cnf -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -extensions v3_req
Generating a RSA private key
...........................+++++
........................+++++
writing new private key to 'key.pem'
-----

C:\k6ncrypt>openssl pkcs8 -in key.pem -traditional -nocrypt -out rsakey.pem

C:\k6ncrypt>openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -passout pass:

C:\k6ncrypt>CERTUTIL -f -p "" -importpfx cert.pfx
Certificate "localhost" added to store.

CertUtil: -importPFX command completed successfully.
```
### Test cert store
```
C:\k6ncrypt>cd certstore

C:\k6ncrypt\certstore>go run main.go
open cert store
get cert from cert store
get key from cert
find cert CN=localhost,OU=security,O=Contoso,L=Redmond,ST=WA,C=US with private key
```

### NOTE
For the first run, you need to get the module github.com/google/certtostore
```
c:\k6ncrypt> go get github.com/google/certtostore
go: downloading github.com/google/certtostore v1.0.2
go: added github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d
go: added github.com/go-ole/go-ole v1.2.5
go: added github.com/google/certtostore v1.0.2
go: added github.com/google/logger v1.1.0
go: added github.com/hashicorp/errwrap v1.0.0
go: added github.com/hashicorp/go-multierror v1.1.1
go: added golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
go: added golang.org/x/sys v0.0.0-20210223212115-eede4237b368
```

## Start Server
```
C:\k6ncrypt>go run server.go
VerifyConnection client localhost
cert[0], CN='localhost'
```

## Start client
```
C:\k6ncrypt>go run client.go
VerifyConnection server localhost
cert[0], CN='localhost'
Sign is called
Hello, world!
```


