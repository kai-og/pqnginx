# Banco de pruebas: NGINX y OpenSSL 3.5 de Debian 13 en el mismo contenedor que el comprobador
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx openssl python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default \
 && mkdir -p /etc/nginx/banco \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj /CN=banco \
      -keyout /etc/nginx/banco/key.pem -out /etc/nginx/banco/cert.pem 2>/dev/null \
 && cp -a /etc/nginx /etc/nginx.orig
