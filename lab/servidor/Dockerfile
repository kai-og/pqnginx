# Servidor como lo tendría el usuario: NGINX y OpenSSL 3.5 de los paquetes de Debian 13
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default
COPY registro.conf /etc/nginx/conf.d/registro.conf
COPY sitio.conf /etc/nginx/sites-available/lab
RUN ln -s /etc/nginx/sites-available/lab /etc/nginx/sites-enabled/lab
COPY arrancar.sh /usr/local/bin/arrancar.sh
RUN chmod +x /usr/local/bin/arrancar.sh
EXPOSE 443
CMD ["/usr/local/bin/arrancar.sh"]
