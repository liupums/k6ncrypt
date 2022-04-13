module contoso.org/pem

go 1.18

require contoso.org/utils v0.0.0

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/google/certtostore v1.0.2 // indirect
	github.com/google/logger v1.1.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83 // indirect
	golang.org/x/sys v0.0.0-20210223212115-eede4237b368 // indirect
)

replace contoso.org/utils => ./utils
