#!/bin/sh
# Generate a lab TLS material for the Fineract container.
# SAN: DNS:localhost, IP:127.0.0.1 — so Python ssl check_hostname can stay on.
# Not a Fineract patch. Spring Boot loads this via FINERACT_SERVER_SSL_KEY_STORE.
set -eu
cd /tls
if [ -f fineract.p12 ] && [ -f cert.pem ]; then
  exit 0
fi
apk add --no-cache openssl
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout key.pem -out cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
openssl pkcs12 -export -out fineract.p12 \
  -inkey key.pem -in cert.pem \
  -passout pass:openmf -name fineract
chmod 644 fineract.p12 cert.pem
rm -f key.pem
