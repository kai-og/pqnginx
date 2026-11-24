#!/bin/sh
# Arranque del servidor del laboratorio:
#  1. certificado autofirmado para a.test y b.test;
#  2. clave SSH del laboratorio (el servidor la crea en el volumen compartido y la herramienta la lee);
#  3. SSH;
#  4. si un cambio quedó a medias (reinicio), el ayudante lo termina o lo deshace;
#  5. NGINX en primer plano.
set -e
D=/etc/nginx/lab-certs
if [ ! -f "$D/cert.pem" ]; then
    mkdir -p "$D"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "/CN=a.test" -addext "subjectAltName=DNS:a.test,DNS:b.test" \
        -keyout "$D/key.pem" -out "$D/cert.pem" 2>/dev/null
fi
if [ ! -f /claves/id_ed25519 ]; then
    ssh-keygen -q -t ed25519 -N '' -C pqnginx-lab -f /claves/id_ed25519
fi
chmod 600 /claves/id_ed25519
install -d -m 700 -o pqnginx -g pqnginx /home/pqnginx/.ssh
install -m 600 -o pqnginx -g pqnginx /claves/id_ed25519.pub /home/pqnginx/.ssh/authorized_keys
ssh-keygen -A >/dev/null
/usr/sbin/sshd
/usr/local/sbin/pqnginx-ayudante recuperar || true
nginx -t
exec nginx -g 'daemon off;'
