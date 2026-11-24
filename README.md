# pqnginx

Herramienta para activar en NGINX el intercambio de claves híbrido post-cuántico (X25519MLKEM768), comprobar desde fuera que el servidor lo usa de verdad y deshacer el cambio si algo falla.

Es el trabajo de fin de grado de Kai Oliveros (Grau en Enginyeria Informàtica, Universitat de Barcelona, curso 2026-27). Está en desarrollo.

## Estado

| Parte | Estado |
|---|---|
| Laboratorio (Debian 13: NGINX 1.26 y OpenSSL 3.5) | Hecho |
| Comprobador del grupo negociado | Hecho |
| Aplicar el cambio con copia, registro y temporizador | Hecho |
| Confirmar o deshacer según la comprobación externa | Hecho |
| Recuperación tras un corte y cambios de otro programa | Hecho, en pruebas |
| Pruebas sistemáticas de interrupción y de cambios por otro programa | Pendiente |

## Cómo funciona

Hay dos piezas:

- **El ayudante** (`pqnginx/ayudante.py`, instalado en el servidor como `/usr/local/sbin/pqnginx-ayudante`) es lo único que corre como administrador. El usuario `pqnginx` solo puede ejecutar el ayudante con `sudo`, y el ayudante solo cambia líneas `ssl_ecdh_curve` y `ssl_protocols` dentro de `/etc/nginx`. Hace las partes delicadas en el propio servidor: comprueba que el archivo no ha cambiado, guarda una copia y un registro del paso, escribe de golpe, pasa `nginx -t`, deja un temporizador y recarga. Si nadie confirma a tiempo, deshace solo. Al deshacer no pisa los cambios de otros programas: quita solo su línea, y si otro programa tocó esa misma línea, no toca nada y lo deja como conflicto.
- **La herramienta** (`pqnginx/aplicar.py`) mide el estado de partida, lee la configuración a través del ayudante y propone los cambios: el híbrido en su propia tupla, conservando los grupos que ya había, y TLS 1.3 si falta. Los muestra, los aplica cuando el administrador confirma, comprueba desde fuera y confirma o deshace.

```bash
docker compose -f lab/compose.yaml exec herramienta python3 -m pqnginx.aplicar servidor --sni a.test --sni b.test --sin-comprobar-host --simular
docker compose -f lab/compose.yaml exec herramienta python3 -m pqnginx.aplicar servidor --sni a.test --sni b.test --sin-comprobar-host
```

`--sin-comprobar-host` es solo para el laboratorio: no comprueba la clave SSH del servidor.

## Comprobador

Se conecta al servidor como un cliente más, sin permisos, con cuatro perfiles:

| Perfil | Qué ofrece |
|---|---|
| `clasico` | Solo X25519 |
| `navegador` | El híbrido y X25519, con las dos claves adelantadas |
| `anuncia_hibrido` | El híbrido y X25519, pero solo adelanta la clave de X25519 |
| `solo_hibrido` | Solo el híbrido |

Para cada dominio da uno de estos estados:

- `elige_hibrido`: el servidor prefiere el híbrido. Lo usa con el navegador y se lo pide al cliente que no lo adelanta.
- `acepta_hibrido`: lo admite, pero no lo prefiere.
- `solo_clasico`: no lo admite.
- `sin_servicio`: no conecta ningún perfil.

El resultado es correcto si el servidor elige el híbrido y los clientes clásicos siguen conectando.

## Laboratorio

Requiere Docker.

```bash
docker compose -f lab/compose.yaml up -d --build
docker compose -f lab/compose.yaml exec herramienta python3 -m pqnginx.verificar servidor --sni a.test --sni b.test
```

El servidor arranca con `ssl_ecdh_curve X25519:prime256v1:secp384r1;`, una lista solo clásica como la de las guías antiguas. Anula el híbrido que OpenSSL 3.5 trae activado por defecto. El comprobador da `solo_clasico`, y tras cambiar la línea a `X25519MLKEM768/X25519:prime256v1:secp384r1` da `elige_hibrido`.

El servidor registra en `/var/log/nginx/pq.log` el grupo negociado (`$ssl_curve`) y los que ofrece el cliente (`$ssl_curves`). Con NGINX 1.26.3 el híbrido aparece como `0x11ec`.

## Pruebas de robustez

`evaluacion/robustez.py` corre en el equipo y maneja el laboratorio con `docker compose`. Provoca fallos en cada paso del cambio:

- se mata la herramienta o el ayudante;
- se corta la conexión SSH;
- se reinicia el servidor;
- otro programa cambia otra parte del archivo, o la misma línea.

En cada caso comprueba que el servicio sigue respondiendo, que la configuración pasa `nginx -t`, que el estado final es el esperado (configuración original, cambio confirmado o conflicto anotado) y que no se pierde el cambio del otro programa.

```bash
python evaluacion/robustez.py --repeticiones 3
```

## Pruebas

```bash
python -m unittest -v
```
