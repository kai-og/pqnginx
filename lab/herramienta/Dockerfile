# Entorno de la herramienta: Python y el cliente de OpenSSL 3.5 para las pruebas de handshake
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 openssl ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*
