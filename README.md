# k6ncrypt
## Prepare cert and private key
C:\k6ncrypt>createcerts.cmd

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


