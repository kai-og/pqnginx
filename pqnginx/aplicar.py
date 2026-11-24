"""Activa el híbrido post-cuántico en un servidor NGINX, comprueba que funciona y, si no, lo deshace.

Pasos:
  1. Si quedó una transacción pendiente (la herramienta se cortó), la resuelve: comprueba el
     servidor y confirma o deshace.
  2. Mide el estado de partida desde fuera, con el comprobador.
  3. Lee la configuración a través del ayudante y prepara los cambios:
       - ssl_ecdh_curve: el híbrido en su propia tupla, conservando los grupos que ya había;
       - ssl_protocols: añade TLSv1.3 si falta (sin él, el híbrido no puede usarse).
  4. Muestra los cambios (simulación) y pide confirmación.
  5. El ayudante los aplica con copia, registro, nginx -t, temporizador y recarga.
  6. Comprueba desde fuera: si todo está bien, confirma; si no, deshace y vuelve a comprobar.

Uso:
  python3 -m pqnginx.aplicar HOST --sni a.test [--sni b.test] [--simular] [--si]
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

from pqnginx.verificar import HIBRIDO, comprobar

AYUDANTE = "/usr/local/sbin/pqnginx-ayudante"
_LINEA = re.compile(r"^(\s*)(ssl_ecdh_curve|ssl_protocols)(\s+)([^;#{}]+?)(\s*;)(\s*(?:#.*)?)$")


class ErrorHerramienta(Exception):
    pass


# ------------------------------------------------------------------ reglas de cambio (funciones puras)

def nueva_lista_grupos(valor: str) -> str | None:
    """Lista con el híbrido en su propia tupla, conservando el resto. None si no hay que cambiarla."""
    v = valor.strip()
    if v.lower() == "auto" or "DEFAULT" in v.upper():
        return None  # la lista por defecto de OpenSSL 3.5 ya incluye el híbrido
    tuplas = []
    for t in v.split("/"):
        grupos = [g for g in t.split(":") if g and g.lstrip("?*-").upper() != HIBRIDO.upper()]
        if grupos:
            tuplas.append(":".join(grupos))
    nueva = "/".join([HIBRIDO] + tuplas)
    return None if nueva == v else nueva


def nuevos_protocolos(valor: str) -> str | None:
    return None if "TLSv1.3" in valor.split() else f"{valor.strip()} TLSv1.3"


def planificar(archivos: dict) -> tuple[list[dict], list[str]]:
    """Cambios a partir de lo que devuelve `ayudante leer`. Devuelve (cambios, avisos)."""
    cambios, avisos = [], []
    for ruta, a in archivos.items():
        for i, linea in enumerate(a["contenido"].splitlines()):
            sin_coment = linea.split("#", 1)[0]
            if not re.search(r"\b(ssl_ecdh_curve|ssl_protocols)\b", sin_coment):
                continue
            m = _LINEA.match(linea)
            if not m:
                avisos.append(f"{ruta}:{i + 1}: la directiva comparte línea con otras; no se toca")
                continue
            sangria, nombre, esp, valor, cierre, comentario = m.groups()
            nuevo = nueva_lista_grupos(valor) if nombre == "ssl_ecdh_curve" else nuevos_protocolos(valor)
            if nuevo is None:
                continue
            cambios.append({"archivo": ruta, "linea": i, "hash_previo": a["hash"], "antes": linea,
                            "despues": f"{sangria}{nombre}{esp}{nuevo}{cierre}{comentario}"})
    return cambios, avisos


def evaluar(base: dict, despues: dict) -> tuple[bool, list[str]]:
    """El cambio es correcto si en cada dominio el servidor elige el híbrido, sigue conectando
    cada perfil que conectaba antes y la respuesta HTTP no cambia."""
    problemas = []
    for sni, d in despues.items():
        if d["veredicto"]["estado"] != "elige_hibrido":
            problemas.append(f"{sni}: {d['veredicto']['estado']}")
        antes = {p["perfil"]: p for p in base[sni]["pruebas"]}
        for p in d["pruebas"]:
            a = antes[p["perfil"]]
            if a["conecta"] and not p["conecta"]:
                problemas.append(f"{sni}: el perfil {p['perfil']} conectaba y ya no")
            elif a["conecta"] and p["conecta"] and a["http"] != p["http"]:
                problemas.append(f"{sni}: la respuesta HTTP cambia ({a['http']} -> {p['http']})")
    return not problemas, problemas


# ------------------------------------------------------------------ comunicación con el ayudante

class Servidor:
    def __init__(self, host: str, usuario: str, clave: str, comprobar_host: bool):
        self.host, self.usuario, self.clave = host, usuario, clave
        self.opciones = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        self.opciones += (["-o", "StrictHostKeyChecking=accept-new"] if comprobar_host else
                          ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])

    def ayudante(self, accion: str, *args: str, entrada: dict | None = None) -> dict:
        # ssh pasa la orden remota por el intérprete del servidor: cada argumento va entrecomillado
        remota = " ".join(shlex.quote(x) for x in ("sudo", "-n", AYUDANTE, accion, *args))
        orden = ["ssh", "-i", self.clave, *self.opciones, f"{self.usuario}@{self.host}", remota]
        r = subprocess.run(orden, input=json.dumps(entrada) if entrada else "", capture_output=True,
                           text=True, timeout=120)
        try:
            return json.loads(r.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            raise ErrorHerramienta(f"el ayudante no responde ({r.returncode}): {r.stderr.strip()[-300:]}")


# ------------------------------------------------------------------ ciclo

def punto_de_corte(nombre: str):
    """Para las pruebas de robustez: PQNGINX_CORTE=<punto> mata la herramienta en ese punto, y
    PQNGINX_PAUSA=<punto>:<segundos> la detiene ahí para que la batería provoque un fallo."""
    if os.environ.get("PQNGINX_CORTE") == nombre:
        print(f"[prueba] la herramienta se interrumpe en «{nombre}»", flush=True)
        os._exit(99)
    pausa = os.environ.get("PQNGINX_PAUSA", "").split(":")
    if pausa[0] == nombre:
        print(f"[prueba] pausa en «{nombre}»", flush=True)
        time.sleep(float(pausa[1]) if len(pausa) > 1 else 5)


class Registro:
    def __init__(self, ruta: str):
        self.ruta = Path(ruta)

    def __call__(self, evento: str, **datos):
        print(f"- {evento}" + (f": {datos['texto']}" if "texto" in datos else ""), flush=True)
        with self.ruta.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"hora": time.strftime("%Y-%m-%dT%H:%M:%S"), "evento": evento, **datos},
                               ensure_ascii=False) + "\n")


def resolver_pendiente(srv: Servidor, host: str, puerto: int, snis: list[str], log: Registro):
    t = srv.ayudante("estado").get("transaccion")
    if not t or t["estado"] not in ("preparado", "escrito", "recargado"):
        return
    log("pendiente", texto=f"la transacción {t['id']} quedó en «{t['estado']}»; se comprueba el servidor")
    actual = comprobar(host, puerto, snis)
    bien = all(r["veredicto"]["estado"] == "elige_hibrido" and r["veredicto"]["clasicos_conectan"]
               for r in actual.values())
    if t["estado"] == "recargado" and bien:
        r = srv.ayudante("confirmar", t["id"])
        log("pendiente_confirmada", texto="el servidor ya elegía el híbrido: confirmada", respuesta=r)
    else:
        r = srv.ayudante("deshacer", t["id"], "pendiente al arrancar la herramienta")
        log("pendiente_deshecha", texto=f"deshecha: {r.get('transaccion', {}).get('resultado_deshacer')}", respuesta=r)


def ejecutar(a) -> int:
    log = Registro(a.registro)
    srv = Servidor(a.host, a.usuario, a.clave, not a.sin_comprobar_host)
    resolver_pendiente(srv, a.host, a.puerto, a.sni, log)

    base = comprobar(a.host, a.puerto, a.sni)
    log("estado_inicial", texto=", ".join(f"{s}: {r['veredicto']['estado']}" for s, r in base.items()), base=base)
    if all(r["veredicto"]["estado"] == "elige_hibrido" for r in base.values()):
        log("nada_que_hacer", texto="el servidor ya elige el híbrido en todos los dominios")
        return 0

    for intento in range(1, 4):
        leido = srv.ayudante("leer")
        if not leido.get("ok"):
            raise ErrorHerramienta(f"no se pudo leer la configuración: {leido}")
        cambios, avisos = planificar(leido["archivos"])
        for av in avisos:
            log("aviso", texto=av)
        if not cambios:
            log("sin_cambios", texto="no hay nada que cambiar en ssl_ecdh_curve ni en ssl_protocols; "
                                    f"el bloqueo está en otra parte (OpenSSL: {leido.get('openssl')})")
            return 3
        print("\nCambios propuestos:", flush=True)
        for c in cambios:
            print(f"  {c['archivo']}:{c['linea'] + 1}\n    - {c['antes'].strip()}\n    + {c['despues'].strip()}", flush=True)
        if a.simular:
            log("simulacion", texto="no se aplica nada", cambios=cambios)
            return 0
        if intento == 1 and not a.si and input("\n¿Aplicar estos cambios? [s/N] ").strip().lower() not in ("s", "si", "sí"):
            log("cancelado", texto="el administrador no confirma")
            return 4
        ident = str(uuid.uuid4())
        punto_de_corte("antes_de_aplicar")
        r = srv.ayudante("aplicar", entrada={"id": ident, "plazo": a.plazo, "cambios": cambios})
        if r.get("ok"):
            break
        if r.get("error") == "cambiado":
            log("archivo_cambiado", texto=f"{r['detalle']}; se vuelve a leer (intento {intento})")
            continue
        log("no_aplicado", texto=f"{r.get('error')}: {r.get('detalle')}", respuesta=r)
        return 5
    else:
        log("no_aplicado", texto="la configuración cambió tres veces seguidas mientras se preparaba el cambio")
        return 5

    log("aplicado", texto=f"transacción {ident}; el servidor la deshará solo en {a.plazo:.0f} s si no se confirma")
    punto_de_corte("tras_aplicar")
    time.sleep(a.espera)
    despues = comprobar(a.host, a.puerto, a.sni)
    bien, problemas = evaluar(base, despues)
    if os.environ.get("PQNGINX_FORZAR_FALLO"):  # solo para probar la vuelta atrás
        bien, problemas = False, ["fallo de verificación forzado (prueba)"]
    punto_de_corte("tras_verificar")
    if bien:
        r = srv.ayudante("confirmar", ident)
        if r.get("ok"):
            log("confirmado", texto="el servidor elige el híbrido en todos los dominios y nada se ha roto",
                despues=despues)
            return 0
        log("no_confirmado", texto=f"no se pudo confirmar: {r.get('detalle')}", respuesta=r)
        return 6
    log("verificacion_fallida", texto="; ".join(problemas), despues=despues)
    r = srv.ayudante("deshacer", ident, "la verificación externa falló")
    t = r.get("transaccion", {})
    log("deshecho", texto=f"{t.get('estado')}: {t.get('resultado_deshacer')}", respuesta=r)
    time.sleep(a.espera)
    final = comprobar(a.host, a.puerto, a.sni)
    igual = all(final[s]["veredicto"]["estado"] == base[s]["veredicto"]["estado"] for s in a.sni)
    log("estado_final", texto="vuelve al estado inicial" if igual else "NO coincide con el estado inicial",
        final=final)
    return 7


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host")
    ap.add_argument("--sni", action="append", required=True)
    ap.add_argument("--puerto", type=int, default=443)
    ap.add_argument("--usuario", default="pqnginx")
    ap.add_argument("--clave", default="/claves/id_ed25519")
    ap.add_argument("--plazo", type=float, default=120, help="segundos hasta que el servidor deshace solo")
    ap.add_argument("--espera", type=float, default=1.0, help="segundos entre recargar y comprobar")
    ap.add_argument("--simular", action="store_true", help="solo muestra los cambios")
    ap.add_argument("--si", action="store_true", help="no pide confirmación")
    ap.add_argument("--registro", default="registro_pqnginx.jsonl")
    ap.add_argument("--sin-comprobar-host", action="store_true", help="solo en el laboratorio")
    a = ap.parse_args(argv)
    try:
        return ejecutar(a)
    except ErrorHerramienta as e:
        print(f"Error: {e}", file=sys.stderr)
        return 8


if __name__ == "__main__":
    sys.exit(main())
