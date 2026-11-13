"""Banco de pruebas: ¿funciona el arreglo ingenuo en configuraciones reales de NGINX?

Para cada configuración descargada de GitHub (ver recolectar.py):
  1. La adapta para que arranque en el laboratorio: certificados de prueba, registros locales,
     destinos de proxy hacia 127.0.0.1 y archivos incluidos que faltan como archivos vacíos.
  2. Mide el estado de partida de cada (puerto, dominio) con el comprobador de pqnginx.
  3. Aplica cada arreglo ingenuo sobre la configuración adaptada, recarga y vuelve a medir.

Un arreglo tiene éxito si, en todos los dominios, el servidor elige el híbrido, los clientes
clásicos conectan y el servicio responde con el mismo código HTTP que antes.

Corre dentro del contenedor `banco` del laboratorio, que tiene NGINX y OpenSSL 3.5 de Debian 13:
    docker compose -f lab/compose.yaml run --rm banco python3 -m evaluacion.banco --parte 0 --partes 1 --max 20
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from pqnginx.verificar import PERFILES, probar, veredicto

DATOS = Path(__file__).parent / "datos"
ORIG = Path("/etc/nginx.orig")
HOSTS_ORIG = Path("/etc/hosts.orig")
CERT = "/etc/nginx/banco/cert.pem"
CLAVE = "/etc/nginx/banco/key.pem"

LISTA_BUENA = "X25519MLKEM768/X25519:prime256v1:secp384r1"   # híbrido en su propia tupla
LISTA_PLANA = "X25519MLKEM768:X25519:prime256v1:secp384r1"   # la de Mozilla 5.8/6.0: una sola tupla
SERVICIO = "X25519:prime256v1:secp384r1:secp521r1"           # para saber si el servicio responde
MAX_OBJETIVOS = 6

# ---------------------------------------------------------------- análisis de la configuración

_TOK = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};"\']+')


def sin_comentarios(texto: str) -> str:
    return "\n".join(codigo(l) for l in texto.splitlines())


def codigo(linea: str) -> str:
    """Parte de la línea antes de un comentario (# fuera de comillas)."""
    dentro = None
    for i, c in enumerate(linea):
        if c in "\"'" and (dentro is None or dentro == c):
            dentro = None if dentro else c
        elif c == "#" and dentro is None and (i == 0 or linea[i - 1] in " \t;{}"):
            return linea[:i]
    return linea


def arbol(texto: str) -> list:
    """Lista de (nombre, argumentos, hijos o None)."""
    toks = _TOK.findall(sin_comentarios(texto))

    def bloque(i):
        hijos, actual = [], []
        while i < len(toks):
            t = toks[i]
            if t == ";":
                if actual:
                    hijos.append((actual[0], actual[1:], None))
                actual = []
            elif t == "{":
                sub, i = bloque(i + 1)
                hijos.append((actual[0] if actual else "", actual[1:], sub))
                actual = []
            elif t == "}":
                return hijos, i
            else:
                actual.append(t.strip("\"'"))
            i += 1
        return hijos, i

    return bloque(0)[0]


def servidores(nodos: list) -> list:
    """Bloques server de http (o de primer nivel en un archivo de sitio), sin stream ni mail."""
    res = []
    for nombre, _, hijos in nodos:
        if hijos is None or nombre in ("stream", "mail", "upstream", "map", "types", "events"):
            continue
        if nombre == "server":
            res.append(hijos)
        elif nombre == "http":
            res += servidores(hijos)
    return res


def puerto(arg: str) -> int | None:
    if arg.startswith("unix:"):
        return None
    m = re.search(r"(\d+)$", arg)
    return int(m.group(1)) if m else (80 if not arg[:1].isdigit() else None)


def objetivos(texto: str) -> list[tuple[int, str]]:
    """(puerto, nombre) de cada server con un listen TLS."""
    res = []
    for srv in servidores(arbol(texto)):
        nombres = [a for n, args, h in srv if n == "server_name" and h is None for a in args]
        nombres = [x for x in nombres if re.fullmatch(r"[A-Za-z0-9.-]+", x) and x not in ("_", "localhost")]
        nombre = nombres[0] if nombres else "sin-nombre.invalid"
        for n, args, h in srv:
            if n == "listen" and h is None and "ssl" in args:
                p = puerto(args[0])
                if p and (p, nombre) not in res:
                    res.append((p, nombre))
    return res[:MAX_OBJETIVOS]


def destinos(texto: str) -> set[str]:
    """Nombres de host de proxy_pass, fastcgi_pass, etc. y de los upstream, para resolverlos a 127.0.0.1."""
    hosts = set()
    for m in re.finditer(r"\b(?:proxy|fastcgi|uwsgi|grpc|scgi|memcached)_pass\s+([^;\s]+)", sin_comentarios(texto)):
        v = re.sub(r"^[a-z]+://", "", m.group(1))
        hosts.add(re.split(r"[:/]", v)[0])

    def visitar(nodos, en_upstream=False):
        for nombre, args, hijos in nodos:
            if hijos is not None:
                visitar(hijos, nombre == "upstream")
            elif en_upstream and nombre == "server" and args:
                hosts.add(re.split(r":", args[0])[0])

    visitar(arbol(texto))
    return {h for h in hosts if h and "$" not in h and not h.startswith("unix")
            and not re.fullmatch(r"[\d.]+|\[.*", h) and re.fullmatch(r"[A-Za-z0-9._-]+", h)}


# ---------------------------------------------------------------- adaptación al laboratorio

def adaptar(texto: str) -> tuple[str, str]:
    """Devuelve (texto adaptado, tipo), con tipo 'completo' (nginx.conf) o 'sitio' (bloques server)."""
    completo = bool(re.search(r"(?m)^\s*http\s*\{", sin_comentarios(texto)))
    ssl_on = bool(re.search(r"(?m)^\s*ssl\s+on\s*;", sin_comentarios(texto)))
    lineas = []
    for linea in texto.splitlines():
        c = codigo(linea)
        resto = linea[len(c):]
        c = re.sub(r"\bssl_certificate\s+[^;]+;", f"ssl_certificate {CERT};", c)
        c = re.sub(r"\bssl_certificate_key\s+[^;]+;", f"ssl_certificate_key {CLAVE};", c)
        c = re.sub(r"\bssl_(?:trusted|client)_certificate\s+[^;]+;", lambda m: m.group(0).split()[0] + f" {CERT};", c)
        c = re.sub(r"\bssl_(?:dhparam|crl|password_file|session_ticket_key|stapling_file|ecdh_curve_x)\s+[^;]+;", "", c)
        c = re.sub(r"\bssl\s+on\s*;", "", c)
        c = re.sub(r"\b(access_log)\s+(?!off\b)[^;]+;", r"\1 /var/log/nginx/banco_access.log;", c)
        c = re.sub(r"\berror_log\s+[^;]+;", "error_log /var/log/nginx/banco_error.log;", c)
        c = re.sub(r"\buser\s+[^;]+;", "user www-data;", c)
        c = re.sub(r"\bpid\s+[^;]+;", "pid /run/nginx.pid;", c)
        c = re.sub(r"\b(?:load_module|daemon)\s+[^;]+;", "", c)
        c = re.sub(r"\blisten\s+([^;]+);", lambda m: escuchar(m.group(1), ssl_on), c)
        lineas.append(c + resto)
    t = "\n".join(lineas) + "\n"
    if completo and not re.search(r"(?m)^\s*events\s*\{", sin_comentarios(t)):
        t = "events {}\n" + t
    return t, "completo" if completo else "sitio"


def escuchar(args: str, ssl_on: bool) -> str:
    partes = args.split()
    if partes and partes[0].startswith("["):        # IPv6: el contenedor no lo tiene
        return ""
    if partes and ":" in partes[0] and not partes[0].startswith("unix:"):
        partes[0] = partes[0].rsplit(":", 1)[1]       # quitar la IP
    partes = ["http2" if p == "spdy" else p for p in partes]
    if ssl_on and partes and partes[0] == "443" and "ssl" not in partes:
        partes.insert(1, "ssl")
    return f"listen {' '.join(partes)};"


# ---------------------------------------------------------------- arreglos ingenuos

_DIRECTIVA = re.compile(r"\bssl_ecdh_curve\s+[^;]+;")


def _sustituir(texto: str, nuevo, solo_primera: bool) -> str:
    hecho, salida = False, []
    for linea in texto.splitlines():
        c = codigo(linea)
        if not (solo_primera and hecho) and _DIRECTIVA.search(c):
            c = _DIRECTIVA.sub(nuevo, c, count=1 if solo_primera else 0)
            hecho = True
        salida.append(c + linea[len(codigo(linea)):])
    return "\n".join(salida) + "\n"


def arreglos(texto: str, tipo: str) -> dict:
    """Cada arreglo devuelve (texto del archivo, contenido extra a nivel http o None)."""
    en_http = f"ssl_ecdh_curve {LISTA_BUENA};"
    if tipo == "completo":
        n5 = (re.sub(r"(?m)^(\s*http\s*\{)", r"\1\n    " + en_http, texto, count=1), None)
    else:
        n5 = (texto, en_http + "\n")
    return {
        "N1_primera_plana": (_sustituir(texto, f"ssl_ecdh_curve {LISTA_PLANA};", True), None),
        "N2_todas_plana": (_sustituir(texto, f"ssl_ecdh_curve {LISTA_PLANA};", False), None),
        "N3_quitar_todas": (_sustituir(texto, "", False), None),
        "N4_todas_tuplas": (_sustituir(texto, f"ssl_ecdh_curve {LISTA_BUENA};", False), None),
        "N5_anadir_en_http": n5,
        # Referencia "informada": tuplas correctas y TLS 1.3 activado. Lo mínimo que haría la herramienta.
        "R_tuplas_y_tls13": (con_tls13(_sustituir(texto, f"ssl_ecdh_curve {LISTA_BUENA};", False)), None),
    }


def con_tls13(texto: str) -> str:
    """Añade TLSv1.3 a las directivas ssl_protocols que no lo tienen."""
    salida = []
    for linea in texto.splitlines():
        c = codigo(linea)
        c = re.sub(r"\bssl_protocols\s+([^;]+);", lambda m: m.group(0) if "TLSv1.3" in m.group(1)
                   else f"ssl_protocols {m.group(1).strip()} TLSv1.3;", c)
        salida.append(c + linea[len(codigo(linea)):])
    return "\n".join(salida) + "\n"


# ---------------------------------------------------------------- ejecución

def sh(*orden, espera=20):
    return subprocess.run(orden, capture_output=True, text=True, errors="replace", timeout=espera)


def preparar(texto: str, tipo: str, extra: str | None, hosts: set[str]):
    sh("nginx", "-s", "stop")
    time.sleep(0.3)
    shutil.rmtree("/etc/nginx", ignore_errors=True)
    shutil.copytree(ORIG, "/etc/nginx", symlinks=True)
    Path("/etc/hosts").write_text(HOSTS_ORIG.read_text() + "".join(f"127.0.0.1 {h}\n" for h in sorted(hosts)))
    destino = Path("/etc/nginx/nginx.conf") if tipo == "completo" else Path("/etc/nginx/conf.d/banco.conf")
    destino.write_text(texto, encoding="utf-8")
    if extra:
        Path("/etc/nginx/conf.d/00-pq.conf").write_text(extra)
    for m in re.finditer(r"\binclude\s+([^;]+);", sin_comentarios(texto)):
        ruta = m.group(1).strip().strip("\"'")
        if any(x in ruta for x in "*?[$"):
            continue
        p = Path(ruta if ruta.startswith("/") else f"/etc/nginx/{ruta}")
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("")


def medir(objs: list[tuple[int, str]]) -> list[dict]:
    res = []
    for p, sni in objs:
        pruebas = [probar("127.0.0.1", p, sni, perfil, espera=5) for perfil in PERFILES]
        servicio = probar("127.0.0.1", p, sni, "clasico", espera=5, grupos=SERVICIO)
        tls12 = probar("127.0.0.1", p, sni, "clasico", espera=5, grupos=SERVICIO, version="-tls1_2")
        v = veredicto(pruebas)
        res.append({"puerto": p, "sni": sni, "estado": v["estado"], "clasicos": v["clasicos_conectan"],
                    "http": servicio.http, "http_tls12": tls12.http,
                    "grupos": {x.perfil: x.grupo for x in pruebas}})
    return res


def arrancar() -> str | None:
    """Comprueba la sintaxis y arranca NGINX. Devuelve el error o None."""
    t = sh("nginx", "-t")
    if t.returncode != 0:
        return (t.stderr.strip().splitlines() or ["?"])[-2 if len(t.stderr.strip().splitlines()) > 1 else -1][:200]
    with open("/tmp/arranque.log", "w") as err:
        a = subprocess.run(["nginx"], stdout=subprocess.DEVNULL, stderr=err, timeout=20)
    if a.returncode != 0:
        return ("arranque: " + Path("/tmp/arranque.log").read_text(errors="replace").strip())[:200]
    time.sleep(0.3)
    return None


def resultado(base: list[dict], despues: list[dict]) -> str:
    for b, d in zip(base, despues):
        if b["http"] is not None and d["http"] != b["http"]:
            return "rompe_servicio"
    if all(d["estado"] == "elige_hibrido" and d["clasicos"] for d in despues):
        return "exito"
    estados = {d["estado"] for d in despues}
    if estados <= {"elige_hibrido", "acepta_hibrido"}:
        return "acepta_sin_elegir"
    if "elige_hibrido" in estados:
        return "parcial"
    return "sin_efecto"


def probar_config(nombre: str, original: str) -> dict:
    r = {"archivo": nombre}
    if not _DIRECTIVA.search(sin_comentarios(original)):
        return r | {"fase": "sin_directiva"}
    if re.search(r"\{\{|\{%|<%", original):
        return r | {"fase": "plantilla"}
    texto, tipo = adaptar(original)
    objs = objetivos(texto)
    r |= {"tipo": tipo, "objetivos": objs, "directivas": len(_DIRECTIVA.findall(sin_comentarios(original)))}
    if not objs:
        return r | {"fase": "sin_tls"}
    hosts = destinos(texto)
    preparar(texto, tipo, None, hosts)
    error = arrancar()
    if error:
        return r | {"fase": "no_arranca", "error": error}
    base = medir(objs)
    r |= {"fase": "medido", "base": base}
    if all(b["estado"] == "elige_hibrido" for b in base):
        r["ya_correcto"] = True
    r["arreglos"] = {}
    for clave, (t2, extra) in arreglos(texto, tipo).items():
        preparar(t2, tipo, extra, hosts)
        error = arrancar()
        if error:
            r["arreglos"][clave] = {"resultado": "rompe_config", "error": error}
            continue
        despues = medir(objs)
        r["arreglos"][clave] = {"resultado": resultado(base, despues), "estados": [d["estado"] for d in despues]}
    sh("nginx", "-s", "stop")
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--parte", type=int, default=0)
    ap.add_argument("--partes", type=int, default=1)
    ap.add_argument("--max", type=int, default=0)
    a = ap.parse_args(argv)
    if not HOSTS_ORIG.exists():
        HOSTS_ORIG.write_text(Path("/etc/hosts").read_text())
    archivos = sorted((DATOS / "configs").glob("*.conf"))
    archivos = [f for i, f in enumerate(archivos) if i % a.partes == a.parte]
    if a.max:
        archivos = archivos[: a.max]
    salida = DATOS / f"banco_{a.parte}de{a.partes}.jsonl"
    hechos = {json.loads(l)["archivo"] for l in salida.read_text().splitlines() if l.strip()} if salida.exists() else set()
    with salida.open("a", encoding="utf-8") as f:
        for i, arch in enumerate(archivos, 1):
            if arch.name in hechos:
                continue
            try:
                r = probar_config(arch.name, arch.read_text(encoding="utf-8", errors="replace"))
            except Exception as e:  # una configuración rara no debe parar el banco
                r = {"archivo": arch.name, "fase": "error_banco", "error": repr(e)[:200]}
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            f.flush()
            if i % 20 == 0:
                print(f"parte {a.parte}: {i}/{len(archivos)}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
