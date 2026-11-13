"""Medición en Internet: cuántos servidores NGINX podrían beneficiarse de la herramienta.

Se conecta a cada dominio como un cliente más (handshakes TLS 1.3 y una sola petición HTTP a /),
sin probar vulnerabilidades ni cambiar nada. Los resultados por dominio no se publican.

Clasificación de los servidores NGINX sin CDN delante:
  A   elige el híbrido: no hace falta nada
  B   acepta el híbrido pero no lo elige: lista mal escrita
  C1  sin híbrido y con la lista de grupos por defecto (acepta X448 o secp521r1): biblioteca antigua
  C2  sin híbrido y con una lista restringida: la configuración lo bloquea

C1 y C2 se distinguen por deducción: la lista por defecto de OpenSSL acepta X448 y secp521r1,
y las listas copiadas de las guías (p. ej. X25519:prime256v1:secp384r1) no.

Uso (dentro del contenedor `herramienta` del laboratorio):
  python3 -m medicion.medir muestra --tranco medicion/datos/top-1m.csv.zip --n 50 --semilla 1 --salida medicion/datos/muestra50.txt
  python3 -m medicion.medir medir --muestra medicion/datos/muestra50.txt --salida medicion/datos/prueba50.jsonl
  python3 -m medicion.medir resumen medicion/datos/prueba50.jsonl
"""
import argparse
import json
import random
import re
import subprocess
import sys
import threading
import time
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pqnginx.verificar import HIBRIDO, PERFILES, analizar

UA = "pqnginx-medicion/0.1 (estudio academico; +https://github.com/kai-og/pqnginx)"
EXCLUIDOS = Path(__file__).with_name("excluidos.txt")

# Primera conexión: como un navegador, pero ofreciendo también los grupos clásicos habituales,
# para obtener las cabeceras aunque el servidor tenga una lista restringida (p. ej. solo secp384r1).
AMPLIO = f"*{HIBRIDO}:*X25519:prime256v1:secp384r1:secp521r1:X448"

# Cabeceras que delatan una CDN o un proxy de terceros delante del servidor.
CABECERAS_CDN = ("cf-ray", "x-amz-cf-id", "x-amz-cf-pop", "x-served-by", "x-fastly-request-id",
                 "x-akamai-transformed", "akamai-grn", "x-azure-ref", "x-vercel-id", "x-nf-request-id",
                 "x-sucuri-id", "x-iinfo", "x-cdn", "x-edge-location", "x-bunny-cache", "cdn-pullzone")
VIA_CDN = re.compile(r"varnish|cloudfront|akamai|fastly|cdn|incapsula", re.I)
PAUSA = 0.3  # segundos entre conexiones al mismo servidor

# Antivirus y proxies que interceptan HTTPS firman con su propia raíz: si aparece en la cadena,
# el handshake medido es el del interceptor y no el del servidor.
# Se mira el emisor del certificado ("i:" en la cadena, "issuer=" o "depth=N"): el interceptor
# a veces solo envía el certificado final, firmado por su raíz.
INTERCEPTOR = re.compile(r"^\s*(?:depth=\d+ |i:|issuer=).*(Norton|Avast|AVG|Kaspersky|ESET|Bitdefender|Sophos|"
                         r"Fortinet|Zscaler|for SSL/TLS scanning)", re.MULTILINE | re.IGNORECASE)


def conectar(host: str, grupos: str, peticion: str = "", espera: float = 8) -> dict:
    """Un handshake TLS 1.3 con la lista de grupos dada; si hay petición, la envía y lee la respuesta."""
    orden = ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host,
             "-tls1_3", "-groups", grupos, "-msg"]
    if peticion:
        orden.append("-ign_eof")
    try:
        r = subprocess.run(orden, input=peticion, capture_output=True, text=True,
                           errors="replace", timeout=espera)
        salida = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return {"tcp": False, "grupo": None, "hrr": False, "cabeceras": {}, "interceptado": False}
    grupo, hrr, _ = analizar(salida)
    return {"tcp": "CONNECTED(" in salida, "grupo": grupo, "hrr": hrr, "cabeceras": cabeceras(salida),
            "interceptado": interceptado(salida)}


def interceptado(salida: str) -> bool:
    """True si la cadena de certificados la firma un antivirus o un proxy que intercepta HTTPS."""
    return bool(INTERCEPTOR.search(salida))


def cabeceras(salida: str) -> dict:
    """Cabeceras de la respuesta HTTP que aparezca en la salida de s_client (nombres en minúscula)."""
    m = re.search(r"^HTTP/1\.[01] \d{3}.*?$(.*?)(?:\r?\n\r?\n|\Z)", salida, re.MULTILINE | re.DOTALL)
    if not m:
        return {}
    res = {}
    for linea in m.group(1).splitlines():
        if ":" in linea:
            k, v = linea.split(":", 1)
            res[k.strip().lower()] = v.strip()[:80]
    return res


def es_cdn(cab: dict) -> bool:
    return any(k.startswith(CABECERAS_CDN) for k in cab) or bool(VIA_CDN.search(cab.get("via", "")))


def clasificar(r: dict) -> str:
    """Categoría A, B, C1 o C2 de un servidor NGINX ya medido."""
    g = r["grupos"]
    if g.get("amplio") == HIBRIDO and g.get("anuncia_hibrido") == HIBRIDO:
        return "A"
    if g.get("solo_hibrido") == HIBRIDO:
        return "B"
    if g.get("X448") or g.get("secp521r1"):
        return "C1"
    return "C2"


def medir_dominio(dominio: str) -> dict:
    res = {"dominio": dominio}
    for host in (dominio, f"www.{dominio}"):
        peticion = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n"
        primera = conectar(host, AMPLIO, peticion)
        if primera["tcp"]:
            break
        time.sleep(PAUSA)
    else:
        return res | {"estado": "sin_conexion"}
    res["host"] = host
    if primera["interceptado"]:
        return res | {"estado": "interceptado"}
    if not primera["grupo"]:
        return res | {"estado": "sin_tls13"}
    cab = primera["cabeceras"]
    res["server"] = cab.get("server", "")
    if "nginx" not in res["server"].lower():
        return res | {"estado": "no_nginx"}
    if es_cdn(cab):
        return res | {"estado": "cdn"}
    grupos = {"amplio": primera["grupo"]}
    hrr = {"amplio": primera["hrr"]}
    pruebas = {"anuncia_hibrido": PERFILES["anuncia_hibrido"], "solo_hibrido": PERFILES["solo_hibrido"],
               "clasico": PERFILES["clasico"], "X448": "X448", "secp521r1": "secp521r1"}
    for nombre, lista in pruebas.items():
        time.sleep(PAUSA)
        c = conectar(host, lista)
        grupos[nombre], hrr[nombre] = c["grupo"], c["hrr"]
    res |= {"estado": "nginx", "grupos": grupos, "hrr": hrr}
    res["categoria"] = clasificar(res)
    return res


def cmd_muestra(a):
    with zipfile.ZipFile(a.tranco) as z:
        lineas = z.read(z.namelist()[0]).decode().splitlines()
    dominios = [l.split(",", 1)[1] for l in lineas if "," in l]
    elegidos = random.Random(a.semilla).sample(dominios, a.n)
    Path(a.salida).write_text("\n".join(elegidos) + "\n", encoding="utf-8")
    print(f"{len(elegidos)} dominios de {len(dominios)} (semilla {a.semilla}) en {a.salida}")


def cmd_medir(a):
    excluidos = {l.strip() for l in EXCLUIDOS.read_text().splitlines() if l.strip() and not l.startswith("#")}
    dominios = [d for d in Path(a.muestra).read_text().split() if d not in excluidos]
    hechos = set()
    salida = Path(a.salida)
    if salida.exists():  # permite reanudar
        hechos = {json.loads(l)["dominio"] for l in salida.read_text().splitlines() if l.strip()}
    pendientes = [d for d in dominios if d not in hechos]
    if conectar("github.com", AMPLIO)["interceptado"]:
        sys.exit("Este equipo intercepta HTTPS (antivirus o proxy): lo medido sería el interceptor. No se mide nada.")
    print(f"{len(pendientes)} dominios pendientes ({len(hechos)} ya medidos)", flush=True)
    cerrojo = threading.Lock()
    with salida.open("a", encoding="utf-8") as f, ThreadPoolExecutor(a.hilos) as ex:
        for i, r in enumerate(ex.map(medir_dominio, pendientes), 1):
            with cerrojo:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                f.flush()
            if i % 100 == 0:
                print(f"{i}/{len(pendientes)}", flush=True)


def resumir(resultados: list[dict]) -> str:
    est = Counter(r["estado"] for r in resultados)
    cat = Counter(r["categoria"] for r in resultados if r["estado"] == "nginx")
    n, nn = len(resultados), sum(cat.values())
    pct = lambda x, t: f"{100 * x / t:.1f}%" if t else "-"
    out = [f"Dominios medidos: {n}", "", "| Estado | Dominios | % |", "|---|---|---|"]
    out += [f"| {k} | {v} | {pct(v, n)} |" for k, v in est.most_common()]
    out += ["", f"Servidores NGINX sin CDN: {nn}", "", "| Categoría | Servidores | % de NGINX sin CDN |", "|---|---|---|"]
    out += [f"| {k} | {cat.get(k, 0)} | {pct(cat.get(k, 0), nn)} |" for k in ("A", "B", "C1", "C2")]
    util = cat.get("B", 0) + cat.get("C2", 0)
    out += ["", f"Utilidad estimada (B + C2): {util} de {nn} ({pct(util, nn)})"]
    return "\n".join(out)


def cmd_resumen(a):
    resultados = [json.loads(l) for l in Path(a.archivo).read_text().splitlines() if l.strip()]
    print(resumir(resultados))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="orden", required=True)
    m = sub.add_parser("muestra")
    m.add_argument("--tranco", required=True)
    m.add_argument("--n", type=int, required=True)
    m.add_argument("--semilla", type=int, default=1)
    m.add_argument("--salida", required=True)
    m.set_defaults(f=cmd_muestra)
    d = sub.add_parser("medir")
    d.add_argument("--muestra", required=True)
    d.add_argument("--salida", required=True)
    d.add_argument("--hilos", type=int, default=16)
    d.set_defaults(f=cmd_medir)
    r = sub.add_parser("resumen")
    r.add_argument("archivo")
    r.set_defaults(f=cmd_resumen)
    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    sys.exit(main())
