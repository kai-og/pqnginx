#!/usr/bin/env python3
"""Ayudante de pqnginx en el servidor: la única parte que corre con permisos de administrador.

Solo puede cambiar líneas `ssl_ecdh_curve` y `ssl_protocols` de archivos dentro de /etc/nginx.
La herramienta lo llama por SSH con `sudo` (el usuario de pqnginx no puede ejecutar nada más).

Cada cambio es una transacción con un diario en /var/lib/pqnginx/transaccion.json:

    preparado -> escrito -> recargado -> confirmado
                                     \\-> deshecho | conflicto

- Antes de escribir comprueba que el archivo sigue siendo el que leyó la herramienta.
- Guarda una copia y escribe cada archivo de golpe (archivo temporal y renombrado).
- Comprueba la sintaxis con `nginx -t` y deja un temporizador antes de recargar: si nadie
  confirma a tiempo, deshace el cambio solo.
- Al deshacer no restaura el archivo entero si otro programa lo ha cambiado entretanto: quita solo
  su línea, y si otro programa cambió esa misma línea, no toca nada y lo deja como conflicto.
- `recuperar` (al arrancar el servidor) termina o deshace lo que quedó pendiente.

Uso: pqnginx-ayudante {leer|aplicar|confirmar ID|deshacer ID|estado|recuperar|vencer ID}
(`aplicar` lee la petición en JSON por la entrada estándar). Responde siempre en JSON.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # solo para poder importar las funciones puras en Windows
    fcntl = None

ESTADO = Path(os.environ.get("PQNGINX_ESTADO", "/var/lib/pqnginx"))
DIARIO = ESTADO / "transaccion.json"
REGISTRO = ESTADO / "registro.log"
CERROJO = Path(os.environ.get("PQNGINX_CERROJO", "/run/pqnginx.lock"))
RAIZ = os.environ.get("PQNGINX_RAIZ", "/etc/nginx")
PENDIENTES = ("preparado", "escrito", "recargado")
LINEA_PERMITIDA = re.compile(r"^\s*(ssl_ecdh_curve|ssl_protocols)\s+[^;#{}]+;\s*(#.*)?$")


class Error(Exception):
    pass


# ------------------------------------------------------------------ funciones puras (probadas en tests)

def sha(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def directiva(linea: str) -> str:
    m = LINEA_PERMITIDA.match(linea)
    if not m:
        raise Error(f"línea no permitida: {linea.strip()[:80]!r}")
    return m.group(1)


def validar(cambio: dict, raiz: str = RAIZ):
    ruta = os.path.realpath(cambio["archivo"])
    raiz = os.path.realpath(raiz)
    if ruta != raiz and not ruta.startswith(raiz + os.sep):
        raise Error(f"archivo fuera de {raiz}: {cambio['archivo']}")
    if directiva(cambio["antes"]) != directiva(cambio["despues"]):
        raise Error("el cambio no puede convertir una directiva en otra")


def aplicar_cambios(contenido: bytes, cambios: list[dict]) -> bytes:
    """Sustituye cada línea `antes` (en su posición) por `despues`. Falla si no coincide."""
    lineas = contenido.decode("utf-8").splitlines(keepends=True)
    for c in cambios:
        i = c["linea"]
        if i >= len(lineas) or lineas[i].rstrip("\r\n") != c["antes"]:
            raise Error(f"la línea {i + 1} de {c['archivo']} ya no es la esperada")
        fin = lineas[i][len(lineas[i].rstrip("\r\n")):]
        lineas[i] = c["despues"] + fin
    return "".join(lineas).encode("utf-8")


def revertir_cambios(actual: bytes, cambios: list[dict]) -> tuple[bytes | None, str]:
    """Deshace solo las líneas propias en un archivo que otro programa ha modificado.

    Devuelve (contenido, "solo_sus_lineas") o (None, motivo) si alguna línea propia ya no está.
    """
    lineas = actual.decode("utf-8").splitlines(keepends=True)
    for c in cambios:
        candidatas = [i for i, l in enumerate(lineas) if l.rstrip("\r\n") == c["despues"]]
        if c["linea"] in candidatas:
            i = c["linea"]
        elif len(candidatas) == 1:
            i = candidatas[0]  # otro programa ha añadido o quitado líneas antes de la nuestra
        elif not candidatas:
            return None, f"otro programa cambió la línea {c['linea'] + 1} de {c['archivo']}"
        else:
            return None, f"la línea de {c['archivo']} aparece repetida y no se sabe cuál es la propia"
        fin = lineas[i][len(lineas[i].rstrip("\r\n")):]
        lineas[i] = c["antes"] + fin
    return "".join(lineas).encode("utf-8"), "solo_sus_lineas"


# ------------------------------------------------------------------ sistema

def escribir_atomico(ruta: str, datos: bytes):
    """Escribe en un temporal del mismo directorio y lo renombra: el archivo nunca queda a medias.
    Sigue los enlaces simbólicos (sites-enabled -> sites-available) y conserva dueño y permisos."""
    real = Path(os.path.realpath(ruta))
    fd, tmp = tempfile.mkstemp(dir=real.parent, prefix=".pqnginx-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(datos)
            f.flush()
            os.fsync(f.fileno())
        if real.exists():
            st = real.stat()
            os.chmod(tmp, st.st_mode & 0o7777)
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, real)
        dfd = os.open(real.parent, os.O_DIRECTORY)
        os.fsync(dfd)
        os.close(dfd)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def leer_diario() -> dict | None:
    return json.loads(DIARIO.read_text()) if DIARIO.exists() else None


def guardar_diario(d: dict):
    ESTADO.mkdir(parents=True, exist_ok=True)
    escribir_atomico(str(DIARIO), json.dumps(d, ensure_ascii=False, indent=1).encode())


def anotar(texto: str):
    ESTADO.mkdir(parents=True, exist_ok=True)
    with REGISTRO.open("a") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {texto}\n")


PRUEBA = ESTADO / "prueba.json"


def prueba(punto: str):
    """Solo para las pruebas de robustez. Si existe /var/lib/pqnginx/prueba.json (solo lo puede crear
    root) y nombra este punto, el ayudante muere aquí ("salir") o se detiene unos segundos ("pausa")
    para que la batería corte el SSH, reinicie el servidor o cambie el archivo. Sin ese archivo no hace nada."""
    try:
        p = json.loads(PRUEBA.read_text())
    except (OSError, ValueError):
        return
    if p.get("punto") != punto:
        return
    if p.get("accion") == "salir":
        os._exit(97)
    time.sleep(float(p.get("segundos", 5)))


class Cerrojo:
    """Una sola operación a la vez (herramienta, temporizador o recuperación)."""

    def __enter__(self):
        CERROJO.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(CERROJO, "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def con_systemd() -> bool:
    return Path("/run/systemd/system").exists() and shutil.which("systemctl") is not None


def sintaxis() -> tuple[bool, str]:
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()[-500:]


def recargar() -> str:
    if con_systemd():
        r = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    elif Path("/run/nginx.pid").exists():
        r = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
    else:
        return "NGINX no está en marcha: no se recarga"
    return "recargado" if r.returncode == 0 else f"error al recargar: {r.stderr.strip()[-200:]}"


def armar_temporizador(ident: str, segundos: float) -> dict:
    """El temporizador vive en el servidor y no depende de la conexión de la herramienta."""
    if con_systemd() and shutil.which("systemd-run"):
        unidad = f"pqnginx-{ident[:12]}"
        subprocess.run(["systemd-run", "--unit", unidad, f"--on-active={max(1, int(segundos))}",
                        os.path.realpath(__file__), "vencer", ident], check=True, capture_output=True)
        return {"tipo": "systemd", "unidad": unidad}
    p = subprocess.Popen([sys.executable, os.path.realpath(__file__), "vencer", ident],
                         start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    return {"tipo": "proceso", "pid": p.pid}


def cancelar_temporizador(d: dict):
    t = d.get("temporizador") or {}
    try:
        if t.get("tipo") == "systemd":
            subprocess.run(["systemctl", "stop", f"{t['unidad']}.timer"], capture_output=True)
        elif t.get("tipo") == "proceso":
            cmd = Path(f"/proc/{t['pid']}/cmdline").read_bytes()
            if b"vencer" in cmd and d["id"].encode() in cmd:
                os.kill(t["pid"], signal.SIGTERM)
    except (OSError, KeyError):
        pass  # ya había terminado; además, al ver el estado confirmado no haría nada


def deshacer_interno(d: dict, motivo: str) -> dict:
    """Deshace los archivos de la transacción. Llamar con el cerrojo tomado."""
    resultados, conflicto = {}, False
    for ruta, a in d["archivos"].items():
        actual = Path(ruta).read_bytes()
        if sha(actual) == a["hash_previo"]:
            resultados[ruta] = "sin_cambios"          # el cambio no llegó a escribirse
        elif sha(actual) == a["hash_nuevo"]:
            escribir_atomico(ruta, Path(a["copia"]).read_bytes())
            resultados[ruta] = "copia_restaurada"
        else:
            nuevo, que = revertir_cambios(actual, a["cambios"])
            if nuevo is None:
                resultados[ruta] = "conflicto: " + que
                conflicto = True
            else:
                escribir_atomico(ruta, nuevo)
                resultados[ruta] = que
    ok, salida = sintaxis()
    recarga = recargar() if ok else "no se recarga: la configuración no pasa nginx -t"
    d.update(estado="conflicto" if conflicto or not ok else "deshecho", motivo=motivo,
             resultado_deshacer=resultados, recarga=recarga, nginx_t=salida if not ok else "ok")
    guardar_diario(d)
    anotar(f"{d['id']} {d['estado']} ({motivo}) {resultados}")
    return d


# ------------------------------------------------------------------ acciones

def accion_leer(_args) -> dict:
    """Archivos que forman la configuración efectiva (según nginx -T), con su contenido y su hash."""
    r = subprocess.run(["nginx", "-T"], capture_output=True, text=True)
    if r.returncode != 0:
        raise Error("nginx -T falla: " + r.stderr.strip()[-300:])
    rutas = re.findall(r"^# configuration file (.+):$", r.stdout, re.MULTILINE)
    archivos = {}
    for ruta in dict.fromkeys(rutas):
        datos = Path(ruta).read_bytes()
        archivos[ruta] = {"contenido": datos.decode("utf-8", errors="replace"), "hash": sha(datos)}
    v = subprocess.run(["nginx", "-V"], capture_output=True, text=True).stderr
    o = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    return {"ok": True, "archivos": archivos, "nginx_V": v.strip()[:400], "openssl": o}


def accion_aplicar(_args) -> dict:
    peticion = json.loads(sys.stdin.read())
    ident, plazo, cambios = peticion["id"], float(peticion.get("plazo", 120)), peticion["cambios"]
    if not re.fullmatch(r"[A-Za-z0-9-]{8,64}", ident):
        raise Error("identificador no válido")
    for c in cambios:
        validar(c)
    with Cerrojo():
        d = leer_diario()
        if d and d["estado"] in PENDIENTES:
            return {"ok": False, "error": "pendiente", "detalle": "hay otra transacción sin terminar", "transaccion": d}
        por_archivo: dict[str, list] = {}
        for c in cambios:
            por_archivo.setdefault(os.path.realpath(c["archivo"]), []).append(c)
        carpeta = ESTADO / ident
        carpeta.mkdir(parents=True, exist_ok=False)
        archivos = {}
        for n, (ruta, cs) in enumerate(por_archivo.items()):
            original = Path(ruta).read_bytes()
            if sha(original) != cs[0]["hash_previo"]:
                return {"ok": False, "error": "cambiado", "detalle": f"{ruta} ha cambiado desde que se leyó"}
            copia = carpeta / f"{n}.copia"
            copia.write_bytes(original)
            nuevo = aplicar_cambios(original, cs)
            archivos[ruta] = {"copia": str(copia), "hash_previo": sha(original), "hash_nuevo": sha(nuevo),
                              "cambios": cs, "_nuevo": nuevo}
        # El temporizador se arma antes de tocar ningún archivo: desde aquí, si este proceso muere en
        # cualquier punto, el servidor deshará el cambio solo cuando venza el plazo.
        d = {"id": ident, "estado": "preparado", "plazo": plazo, "fecha_limite": time.time() + plazo,
             "inicio": time.time(),
             "archivos": {r: {k: v for k, v in a.items() if k != "_nuevo"} for r, a in archivos.items()}}
        guardar_diario(d)
        d["temporizador"] = armar_temporizador(ident, plazo)
        guardar_diario(d)
        anotar(f"{ident} preparado: {len(cambios)} cambios en {len(archivos)} archivos; "
               f"se deshace solo si no se confirma en {plazo:.0f} s")
        prueba("tras_preparar")
        for ruta, a in archivos.items():
            escribir_atomico(ruta, a["_nuevo"])
        d["estado"] = "escrito"
        guardar_diario(d)
        prueba("tras_escribir")
        ok, salida = sintaxis()
        if not ok:
            cancelar_temporizador(d)
            deshacer_interno(d, "la configuración nueva no pasa nginx -t")
            return {"ok": False, "error": "sintaxis", "detalle": salida, "transaccion": d}
        prueba("antes_de_recargar")
        d["recarga"] = recargar()
        d["estado"] = "recargado"
        guardar_diario(d)
        anotar(f"{ident} recargado")
        prueba("tras_recargar")
        return {"ok": True, "transaccion": d}


def accion_confirmar(args) -> dict:
    with Cerrojo():
        d = leer_diario()
        if not d or d["id"] != args[0]:
            raise Error("no existe esa transacción")
        if d["estado"] != "recargado":
            return {"ok": False, "error": "estado", "detalle": f"la transacción está {d['estado']}", "transaccion": d}
        d["estado"] = "confirmado"
        guardar_diario(d)
        cancelar_temporizador(d)
        anotar(f"{d['id']} confirmado")
        return {"ok": True, "transaccion": d}


def accion_deshacer(args) -> dict:
    with Cerrojo():
        d = leer_diario()
        if not d or d["id"] != args[0]:
            raise Error("no existe esa transacción")
        if d["estado"] not in PENDIENTES + ("confirmado",):
            return {"ok": False, "error": "estado", "detalle": f"la transacción está {d['estado']}", "transaccion": d}
        cancelar_temporizador(d)
        return {"ok": True, "transaccion": deshacer_interno(d, args[1] if len(args) > 1 else "pedido por la herramienta")}


def accion_estado(_args) -> dict:
    return {"ok": True, "transaccion": leer_diario()}


def accion_vencer(args) -> dict:
    """Lo ejecuta el temporizador: si al llegar el plazo nadie ha confirmado, deshace."""
    ident = args[0]
    while True:
        d = leer_diario()
        if not d or d["id"] != ident or d["estado"] not in PENDIENTES:
            return {"ok": True, "detalle": "nada que hacer"}
        falta = (d["fecha_limite"] or 0) - time.time()
        if falta <= 0:
            break
        time.sleep(min(falta, 1.0))
    with Cerrojo():
        d = leer_diario()
        if d and d["id"] == ident and d["estado"] in PENDIENTES:
            return {"ok": True, "transaccion": deshacer_interno(d, "venció el plazo sin confirmación")}
    return {"ok": True, "detalle": "confirmado a tiempo"}


def accion_recuperar(_args) -> dict:
    """Al arrancar el servidor: si quedó algo pendiente, deshace si el plazo pasó o rearma el temporizador."""
    with Cerrojo():
        d = leer_diario()
        if not d or d["estado"] not in PENDIENTES:
            return {"ok": True, "detalle": "nada pendiente"}
        falta = (d["fecha_limite"] or 0) - time.time()
        if d["estado"] == "preparado" or falta <= 0:
            return {"ok": True, "transaccion": deshacer_interno(d, "recuperación al arrancar")}
        d["temporizador"] = armar_temporizador(d["id"], falta)
        guardar_diario(d)
        anotar(f"{d['id']} recuperado: temporizador rearmado ({falta:.0f} s)")
        return {"ok": True, "transaccion": d}


ACCIONES = {"leer": accion_leer, "aplicar": accion_aplicar, "confirmar": accion_confirmar,
            "deshacer": accion_deshacer, "estado": accion_estado, "vencer": accion_vencer,
            "recuperar": accion_recuperar}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ACCIONES:
        print(json.dumps({"ok": False, "error": "uso", "detalle": "acciones: " + ", ".join(ACCIONES)}))
        return 2
    try:
        res = ACCIONES[argv[0]](argv[1:])
    except Error as e:
        res = {"ok": False, "error": "rechazado", "detalle": str(e)}
    except Exception as e:  # nunca dejar al llamante sin respuesta legible
        res = {"ok": False, "error": "interno", "detalle": repr(e)[:300]}
    print(json.dumps(res, ensure_ascii=False))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
