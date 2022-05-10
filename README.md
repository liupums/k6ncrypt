# k6ncrypt
## Prepare cert and private key
### Run as admin, and the private key is installed into VSM as non-exportable
D:\k6ncrypt>createcert.cmd
```
D:\k6ncrypt>openssl req -config openssl.cnf -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -extensions v3_req
Generating a RSA private key
......................................+++++
.+++++
writing new private key to 'key.pem'
-----

D:\k6ncrypt>openssl pkcs8 -in key.pem -traditional -nocrypt -out rsakey.pem

D:\k6ncrypt>openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -passout pass:

D:\k6ncrypt>CERTUTIL -f -csp KSP -p "" -importpfx cert.pfx "NoExport,VSM"
CertUtil: -importPFX command completed successfully.

D:\k6ncrypt>CERTUTIL -store my localhost   | findstr "Unique container name"
  Unique container name: cad91794ddf50456b13c563fdc9fe9aa_64e6b472-74a5-4eb6-a106-b43815e2d97d

D:\k6ncrypt>REM CERTUTIL -v -csp KSP -key

D:\k6ncrypt>CERTUTIL -v -csp KSP -key cad91794ddf50456b13c563fdc9fe9aa_64e6b472-74a5-4eb6-a106-b43815e2d97d
Microsoft Software Key Storage Provider:
  {92761CBA-52AB-4531-9530-12533B1C9AF5}
  cad91794ddf50456b13c563fdc9fe9aa_64e6b472-74a5-4eb6-a106-b43815e2d97d
  AD(AT_NONE): 52b2f05d52395db4210a8d4dff461479c6869d7e
  AD(AT_KEYEXCHANGE): ca20ba0fffc082ae664ee143d138f4ca6df915bf
  AD(AT_SIGNATURE): f2c5c00635f405aba2110ac12e5d5be0b71b03b2

  RSA
    AT_KEYEXCHANGE:
Key Id Hash(rfc-sha1): 1fa2420cec1949b23a518b4acb079bf74e8dde10
Key Id Hash(sha1): c741bbce2b12fce26afb53720790ab20d5d83f75
Key Id Hash(bcrypt-sha1): c7c1fd262a50475def62698e41515f0384ddf87a
Key Id Hash(bcrypt-sha256): db998f8fbcf1b2287bf0113396fe326a85bc888a488aea3a0b2b962abb000361
Container Public Key:
  0000  30 82 01 0a 02 82 01 01  00 d9 d9 f0 ff 9d 7f b2
  0010  95 82 5a bf 7a d9 d0 54  8b 2e 70 fa ac 08 0c 09
  0020  f1 90 0f e3 3e 9e 2f db  93 1a 57 4d 40 2d a7 76
  0030  76 a0 c1 c8 98 af 55 12  0d 2e c5 59 43 46 58 40
  0040  3c bd 9f ab ac 49 9e 52  69 d5 42 45 51 4e a9 c1
  0050  74 14 6f dc 13 5f e0 fa  89 c8 e8 94 14 85 2b ee
  0060  77 3a be b2 0f bc f9 23  2a 9f 25 79 d5 5c 69 09
  0070  05 6d b6 cd 49 c0 6d 32  bb 6c 16 b4 2c 53 8f 05
  0080  60 2f 0a 37 f7 80 b9 bf  03 ff 15 03 b0 0e 2b 23
  0090  5e b1 3d 61 86 92 64 cc  94 fc d9 ae 70 80 30 8e
  00a0  b5 ed 25 47 bb d8 69 b5  93 6a ec 63 aa f3 9a f3
  00b0  db b5 a3 bd e9 c7 49 a8  37 8f 47 79 54 8e b2 e7
  00c0  ef c9 76 c1 9e ea c7 b1  7d 70 f6 c8 da 1e 9f e7
  00d0  eb 34 fa 5a 25 8f 24 9f  c5 de fc 26 be f6 15 ef
  00e0  44 c9 b7 99 2c 72 c9 83  46 01 60 7e c8 06 6b 4c
  00f0  c4 1b 58 65 b1 75 52 8f  5c 30 14 fc 2f ec 03 ef
  0100  55 87 14 61 8b 71 b7 9a  11 02 03 01 00 01
Cached Key Identifier: {92761CBA-52AB-4531-9530-12533B1C9AF5}: Found exact match
    NCRYPT_ALLOW_DECRYPT_FLAG -- 1
    NCRYPT_ALLOW_SIGNING_FLAG -- 2
    NCRYPT_ALLOW_KEY_AGREEMENT_FLAG -- 4
    NCRYPT_ALLOW_KEY_IMPORT_FLAG -- 8
    NCRYPT_ALLOW_ALL_USAGES -- ffffff (16777215)
  Export Policy = 0
      (NCRYPT_ALLOW_EXPORT_FLAG -- 1)
      (NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG -- 2)
      (NCRYPT_ALLOW_ARCHIVING_FLAG -- 4)
      (NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG -- 8)
  Name: {92761CBA-52AB-4531-9530-12533B1C9AF5}
  Algorithm Group: RSA
  Algorithm Name: RSA
  Length: 2048 (0x800)
  Lengths:
    dwMinLength = 512 (0x200)
    dwMaxLength = 16384 (0x4000)
    dwIncrement = 8 (0x8)
    dwDefaultLength = 1024 (0x400)
  Block Length: 256 (0x100)
  Export Policy: 0 (0x0)
      (NCRYPT_ALLOW_EXPORT_FLAG -- 1)
      (NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG -- 2)
      (NCRYPT_ALLOW_ARCHIVING_FLAG -- 4)
      (NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG -- 8)

  Key Usage: 16777215 (0xffffff)
    NCRYPT_ALLOW_DECRYPT_FLAG -- 1
    NCRYPT_ALLOW_SIGNING_FLAG -- 2
    NCRYPT_ALLOW_KEY_AGREEMENT_FLAG -- 4
    NCRYPT_ALLOW_KEY_IMPORT_FLAG -- 8
    NCRYPT_ALLOW_ALL_USAGES -- ffffff (16777215)

  Security Descr: D:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)
  Modified: 4/13/2022 10:56 AM
  Virtual Iso: 1 (0x1)
  Per Boot Key: 0 (0x0)

Private key is a VSM key
Private key is NOT exportable

CertUtil: -key command completed successfully.
```

### Test cert store
```
D:\k6ncrypt>cd certstore

D:\k6ncrypt\certstore>go run main.go
open cert store
get cert from cert store
get key from cert
find cert 'CN=localhost,OU=security,O=Contoso,L=Redmond,ST=WA,C=US' with private key in container 'C:\ProgramData\Microsoft\Crypto\Keys\cad91794ddf50456b13c563fdc9fe9aa_64e6b472-74a5-4eb6-a106-b43815e2d97d', algo 'RSA'
```

### NOTE
For the first run, you need to get the module github.com/google/certtostore
```
D:\k6ncrypt> go get github.com/google/certtostore
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
D:\k6ncrypt>go run server.go
VerifyConnection client localhost
cert[0], CN='localhost'
```

## Start client
```
D:\k6ncrypt>go run client.go
VerifyConnection server localhost
cert[0], CN='localhost'
WinCert::Sign is called
WinCert::SignPSS is called
--result by WinCert private key
sig 5276f1a25cfbb0baee389c7f4217da89b23760674e12e64ba55658e97f82ce7dda4f720d6d79690c267ef04b5f71e2eb9b042afe443a5e618f216267071800f1810c1056696a0cc15c5872096c49027b6e3290c5f72ae685338dfdd34ec766163f75961c70435b6248f37a1e31db80361aed81e9ae421b5b6ca8a7060448436a703fe9394900685d8f8d4e1eb03c5b86c449f75f1b66e435fd0a0bb2b97e940c7ab6248ea78baf909a8036e8dd591a0fbbbce974bed7855add1a64169072356de59891aab7faabfe664609c721b1e65135d7da82f3dc5bf6c189ab241a50c8ca680a46d9423e5dcfd44622793df048ad9d8274c7a3d644c4b3a18de728f33a6c
-----
Hello, world!
```
### check the key is non-exportable
NOTE: use the key container id showing above 55340bce64ed0049e84ce494a19e1479_0348503b-0232-43a2-a77a-dc83cf95a8c1
```
D:\k6ncrypt>CERTUTIL -v -csp KSP -key 55340bce64ed0049e84ce494a19e1479_0348503b-0232-43a2-a77a-dc83cf95a8c1 | findstr Private
Private key is a VSM key
Private key is NOT exportable
```


