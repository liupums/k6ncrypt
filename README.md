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

## Create testing certs (run as Admin Powershell)
```
PS D:\k6ncrypt\certs> .\CreateChainCerts.ps1 -action create
Save client leaf cert PEM to file system
Save server leaf cert PEM to file system
Save root PEM to file system
Save CA PEM to file system
Remove fake ROOT cert from cert store.
Remove fake CA cert from cert store.
```
## Start Server
```
PS D:\k6ncrypt> go run .\main.go -a server -c .\certs\FakeServer-chained.pem -r .\certs\FakeRoot.pem
2022/05/12 08:08:33 Trying to find cert in the cert store with thumbprint 'b35c55f7118cee27083818f8c4f0c5aee3b536df'
2022/05/12 08:08:33 Found cert with thumbprint 'b35c55f7118cee27083818f8c4f0c5aee3b536df'
2022/05/12 08:08:53 WinCert::Sign is called
2022/05/12 08:08:53 WinCert::signPSS is called
2022/05/12 08:08:53 --result by WinCert private key
2022/05/12 08:08:53 sig 6a7608bc47e24af084379d50b30b97fc4b39f1e031b863e526feaa1f1109d1a6e012245da053477d6b0c0a4305e4b11c62ba63ef64e4e21a475a310d835c89060802f86f6d9e549d1b61b4e4b744ac26f85e2fb6748c959c73d6263c559c828340beaf951223168c3593fff84313eca61f8b6891463f9ba3a3fbbb8885225ae39cbb10f395e7023d5a87ce569b835ddcf82ab2ee582c44ac9ae7a96fdb7a228b2eb2c27f7e987e0646c66407714addef0e279b8ea3b4a226d82600fc0fa06258e4efb9a957b2ebe6deda708d03ce63b182cba8c57a85284971d265f5ac426a3c7f1e5033c7dfa242e6a921c23b00995f344beb198e65a44fbe30ba33784b39df
2022/05/12 08:08:53 VerifyConnection client name: 'localhost'
2022/05/12 08:08:53 client cert[0], CN='FakeClient'
2022/05/12 08:08:53 client cert contains embedded CA
exit status 0xc000013a
```

## Start client
```
D:\k6ncrypt>go run main.go -a client -c certs\FakeClient-chained.pem -r certs\FakeRoot.pem
2022/05/12 08:08:53 Trying to find cert in the cert store with thumbprint 'bab51f3553a5a43eaec0fa3d77517706f969e5d2'
2022/05/12 08:08:53 Found cert with thumbprint 'bab51f3553a5a43eaec0fa3d77517706f969e5d2'
2022/05/12 08:08:53 VerifyConnection server localhost
2022/05/12 08:08:53 server cert[0], CN='FakeServer'
2022/05/12 08:08:53 client cert contains embedded CA
2022/05/12 08:08:53 WinCert::Sign is called
2022/05/12 08:08:53 WinCert::signPSS is called
2022/05/12 08:08:53 --result by WinCert private key
2022/05/12 08:08:53 sig 13fe75d815d85a2156c35be8e8cf96476d681f3bd9f4577cb242c9341753b42198f0d541d4a2117a815dfd6581b8ad40d363166eca81d49bcabf29a09e53cacdca7dd8970926cdf91ab0c2c5f7620d43cc40d0de1106a2c57820098db2eabd7a4378a10e33ac362018f0133334abbce33a7afa1ca4ba4dc00cb30c39488608bee0ff4ebe98a3868e6aab74a23552ea7a6442a7481bc6a0346ec11722f64ca9e3f9197e70597d818fabc0086bd773ce7e8738a7ba899e61e5d3e54d081db5a1dc01279d25b5de6759875c7b4e3059b36411591eea86bf5e3f9736cd900531cb4eab866c5ca0b651efbf7cdead563ca6a5077e0c2f6d1d6bdf6d65a9477db00c21
2022/05/12 08:08:53 Hello, world!
```

## clean up (run as Admin Powershell)
```
PS D:\k6ncrypt\certs> .\CreateChainCerts.ps1 -action clean
Remove leaf server and client cert from cert store.
Remove fake ROOT pem from file system.
Remove fake CA pem from file system.
Remove fake server pem from file system.
Remove fake server chained PEM from file system.
Remove fake client pem from file system.
Remove fake client chained PEM from file system.
```
### check the key is non-exportable
NOTE: use the key container id showing above 55340bce64ed0049e84ce494a19e1479_0348503b-0232-43a2-a77a-dc83cf95a8c1
```
D:\k6ncrypt>CERTUTIL -v -csp KSP -key 55340bce64ed0049e84ce494a19e1479_0348503b-0232-43a2-a77a-dc83cf95a8c1 | findstr Private
Private key is a VSM key
Private key is NOT exportable
```


