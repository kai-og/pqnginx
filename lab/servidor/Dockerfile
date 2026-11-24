# Servidor como lo tendría el usuario: NGINX y OpenSSL 3.5 de los paquetes de Debian 13,
# más SSH y el ayudante de pqnginx, que es lo único que el usuario pqnginx puede ejecutar con sudo.
# Se construye desde la raíz del repositorio (ver compose.yaml).
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx openssl ca-certificates openssh-server sudo python3 \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default \
 && useradd -m -s /bin/bash pqnginx && usermod -p '*' pqnginx \
 && echo 'pqnginx ALL=(root) NOPASSWD: /usr/local/sbin/pqnginx-ayudante' > /etc/sudoers.d/pqnginx \
 && chmod 440 /etc/sudoers.d/pqnginx \
 && mkdir -p /run/sshd \
 && sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
COPY lab/servidor/registro.conf /etc/nginx/conf.d/registro.conf
COPY lab/servidor/sitio.conf /etc/nginx/sites-available/lab
RUN ln -s /etc/nginx/sites-available/lab /etc/nginx/sites-enabled/lab
COPY pqnginx/ayudante.py /usr/local/sbin/pqnginx-ayudante
COPY lab/servidor/arrancar.sh /usr/local/bin/arrancar.sh
RUN sed -i 's/\r$//' /usr/local/sbin/pqnginx-ayudante /usr/local/bin/arrancar.sh \
 && chmod 755 /usr/local/sbin/pqnginx-ayudante /usr/local/bin/arrancar.sh
EXPOSE 443 22
CMD ["/usr/local/bin/arrancar.sh"]
