#!/bin/sh
# Crea un certificado autofirmado para a.test y b.test si no existe y arranca NGINX en primer plano
set -e
D=/etc/nginx/lab-certs
if [ ! -f "$D/cert.pem" ]; then
    mkdir -p "$D"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "/CN=a.test" -addext "subjectAltName=DNS:a.test,DNS:b.test" \
        -keyout "$D/key.pem" -out "$D/cert.pem" 2>/dev/null
fi
nginx -t
exec nginx -g 'daemon off;'
