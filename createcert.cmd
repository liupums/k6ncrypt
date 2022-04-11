openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -subj "/C=US/ST=WA/L=Redmond/O=Contoso/OU=security/CN=localhost"  -addext "subjectAltName = DNS:localhost"
openssl pkcs8 -in key.pem -traditional -nocrypt -out rsakey.pem
