# pqnginx

Herramienta para activar en NGINX el intercambio de claves híbrido post-cuántico (X25519MLKEM768), comprobar desde fuera que el servidor lo usa de verdad y deshacer el cambio si algo falla.

Es el trabajo de fin de grado de Kai Oliveros (Grau en Enginyeria Informàtica, Universitat de Barcelona, curso 2026-27). Está en desarrollo.

## Estado

| Parte | Estado |
|---|---|
| Laboratorio (Debian 13: NGINX 1.26 y OpenSSL 3.5) | Hecho |
| Comprobador del grupo negociado | Hecho |
| Aplicar el cambio con copia, registro y temporizador | En curso |
| Deshacer el cambio, también si la herramienta se interrumpe | Pendiente |
| Pruebas de interrupción y de cambios por otro programa | Pendiente |

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

## Medición en Internet

Para estimar a cuántos servidores podría servir la herramienta, se mide una muestra aleatoria de dominios de la [lista Tranco](https://tranco-list.eu/list/947W2) (`medicion/medir.py`).

- **Conexiones:** cada dominio recibe como máximo siete conexiones TLS 1.3 y una sola petición HTTP a `/`, con pausas entre ellas, como haría un navegador.
- **Identificación:** el User-Agent es `pqnginx-medicion/0.1 (estudio academico; +https://github.com/kai-og/pqnginx)`.
- **Qué no se hace:** no se prueban vulnerabilidades ni se cambia nada en ningún servidor.
- **Publicación:** solo se publican resultados agregados. No se publica qué dominio está en cada categoría.

Los servidores NGINX sin CDN delante se clasifican así:

| Categoría | Qué se ve desde fuera |
|---|---|
| A | Elige el híbrido |
| B | Acepta el híbrido pero no lo elige |
| C1 | No admite el híbrido y usa la lista de grupos por defecto: biblioteca antigua |
| C2 | No admite el híbrido y tiene una lista restringida: la configuración lo bloquea |

C1 y C2 se distinguen porque la lista por defecto de OpenSSL acepta X448 y secp521r1, y las listas copiadas de las guías no. Es una deducción y puede equivocarse.

**Para quedar fuera de la medición,** abre un issue en este repositorio con el dominio. Se añadirá a `medicion/excluidos.txt`.

## Pruebas

```bash
python -m unittest -v
```
