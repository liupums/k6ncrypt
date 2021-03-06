openssl req -config openssl.cnf -newkey rsa:2048 -new -nodes -x509 -days 3650 -out cert.pem -keyout key.pem -extensions v3_req
openssl pkcs8 -in key.pem -traditional -nocrypt -out rsakey.pem
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -passout pass:
CERTUTIL -f -csp KSP -p "" -importpfx cert.pfx "NoExport,VSM"
CERTUTIL -store my localhost | findstr "Unique container name"
REM CERTUTIL -v -csp KSP -key