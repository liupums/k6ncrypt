openssl req -config openssl.cnf -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -extensions v3_req
openssl pkcs8 -in key.pem -traditional -nocrypt -out rsakey.pem
