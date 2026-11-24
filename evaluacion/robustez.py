"""Batería de robustez: cortes en cada paso y cambios de otro programa en el mismo archivo.

Corre en el equipo (no en un contenedor) y maneja el laboratorio con `docker compose`.
Para cada escenario y repetición:
  1. recrea el servidor (estado inicial: solo clásico);
  2. lanza la herramienta y provoca el fallo en el punto indicado;
  3. espera a que el servidor quede estable (sin transacción pendiente) y mide cuánto tarda;
  4. comprueba: el servicio responde, el estado final es el esperado y, si hubo otro programa,
     su cambio sigue ahí;
  5. relanza la herramienta sin fallos y comprueba que termina eligiendo el híbrido.

Uso:
    python evaluacion/robustez.py --repeticiones 3 [--solo NOMBRE]
"""
import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DATOS = Path(__file__).parent / "datos"
COMPOSE = ["docker", "compose", "-f", str(RAIZ / "lab" / "compose.yaml")]
SITIO = "/etc/nginx/sites-available/lab"
LINEA_ORIGINAL = "ssl_ecdh_curve X25519:prime256v1:secp384r1;"
LINEA_OTRO = "ssl_ecdh_curve prime256v1:X25519;"
MARCA_OTRO = "add_header X-Otro-Programa 1;"
PLAZO = 10
PENDIENTES = ("preparado", "escrito", "recargado")
PUNTO_A_ESTADO = {"tras_preparar": "preparado", "tras_escribir": "escrito",
                  "antes_de_recargar": "escrito", "tras_recargar": "recargado"}

# nombre: (tipo de fallo, lado, punto, forzar fallo de verificación, finales aceptables)
#   tipos: matar (el proceso muere), ssh (se corta la conexión), reinicio (se reinicia el servidor),
#          otro_parte / otro_linea (otro programa cambia otra parte del archivo o la misma línea)
ESCENARIOS = {
    "matar_herramienta_antes_de_aplicar": ("matar", "herramienta", "antes_de_aplicar", False, {"original"}),
    "matar_herramienta_tras_aplicar": ("matar", "herramienta", "tras_aplicar", False, {"original"}),
    "matar_herramienta_tras_verificar": ("matar", "herramienta", "tras_verificar", False, {"original"}),
    "matar_ayudante_tras_preparar": ("matar", "ayudante", "tras_preparar", False, {"original"}),
    "matar_ayudante_tras_escribir": ("matar", "ayudante", "tras_escribir", False, {"original"}),
    "matar_ayudante_antes_de_recargar": ("matar", "ayudante", "antes_de_recargar", False, {"original"}),
    "matar_ayudante_tras_recargar": ("matar", "ayudante", "tras_recargar", False, {"original"}),
    "ssh_tras_preparar": ("ssh", "ayudante", "tras_preparar", False, {"original"}),
    "ssh_tras_escribir": ("ssh", "ayudante", "tras_escribir", False, {"original"}),
    "ssh_antes_de_recargar": ("ssh", "ayudante", "antes_de_recargar", False, {"original"}),
    "ssh_tras_recargar": ("ssh", "ayudante", "tras_recargar", False, {"original"}),
    "reinicio_tras_preparar": ("reinicio", "ayudante", "tras_preparar", False, {"original"}),
    "reinicio_tras_escribir": ("reinicio", "ayudante", "tras_escribir", False, {"original"}),
    "reinicio_antes_de_recargar": ("reinicio", "ayudante", "antes_de_recargar", False, {"original"}),
    "reinicio_tras_recargar": ("reinicio", "ayudante", "tras_recargar", False, {"original"}),
    # tras reiniciar, la herramienta sigue: puede confirmar (si el servidor ya responde) o deshacer
    "reinicio_herramienta_tras_aplicar": ("reinicio", "herramienta", "tras_aplicar", False, {"original", "nuevo"}),
    "reinicio_herramienta_tras_verificar": ("reinicio", "herramienta", "tras_verificar", False, {"original", "nuevo"}),
    "otro_parte_antes_de_aplicar": ("otro_parte", "herramienta", "antes_de_aplicar", False, {"nuevo"}),
    "otro_linea_antes_de_aplicar": ("otro_linea", "herramienta", "antes_de_aplicar", False, {"nuevo"}),
    "otro_parte_y_verificacion_fallida": ("otro_parte", "herramienta", "tras_aplicar", True, {"original"}),
    "otro_linea_y_verificacion_fallida": ("otro_linea", "herramienta", "tras_aplicar", True, {"conflicto"}),
    "otro_parte_y_plazo_vencido": ("otro_parte", "corte", "tras_aplicar", False, {"original"}),
    "otro_linea_y_plazo_vencido": ("otro_linea", "corte", "tras_aplicar", False, {"conflicto"}),
}


def dc(*args, entrada=None, espera=60) -> subprocess.CompletedProcess:
    return subprocess.run([*COMPOSE, *args], input=entrada, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=espera)


def en_servidor(codigo: str, espera=30) -> str:
    return dc("exec", "-T", "servidor", "python3", "-c", codigo, espera=espera).stdout.strip()


def diario() -> dict | None:
    s = en_servidor("import json,os;p='/var/lib/pqnginx/transaccion.json';"
                    "print(json.dumps(json.load(open(p))) if os.path.exists(p) else 'null')")
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def linea_actual() -> str:
    s = en_servidor("import json;print(json.dumps([l.strip() for l in open('" + SITIO + "') "
                    "if 'ssl_ecdh_curve' in l and not l.strip().startswith('#')]))")
    try:
        lineas = json.loads(s)
    except json.JSONDecodeError:
        return "?"
    return lineas[0] if lineas else "(ninguna)"


def verificar() -> dict:
    r = dc("exec", "-T", "herramienta", "python3", "-m", "pqnginx.verificar", "servidor",
           "--sni", "a.test", "--sni", "b.test", "--json", espera=90)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}


def servicio_ok(v: dict) -> bool:
    """El servicio responde 200 a un cliente clásico en los dos dominios."""
    return bool(v) and all(any(p["perfil"] == "clasico" and p["http"] == 200 for p in r["pruebas"]) for r in v.values())


def elige(v: dict) -> bool:
    return bool(v) and all(r["veredicto"]["estado"] == "elige_hibrido" for r in v.values())


def esperar_servidor(limite=60):
    t0 = time.time()
    while time.time() - t0 < limite:
        r = dc("exec", "-T", "servidor", "sh", "-c", "test -f /run/nginx.pid && test -f /run/sshd.pid", espera=20)
        if r.returncode == 0:
            return True
        time.sleep(0.5)
    return False


def recrear():
    dc("up", "-d", "--force-recreate", "servidor", espera=120)
    esperar_servidor()
    time.sleep(1)


def matar_ssh():
    """Corta la conexión: mata el cliente ssh dentro del contenedor de la herramienta."""
    dc("exec", "-T", "herramienta", "python3", "-c",
       "import os,signal\n"
       "for p in os.listdir('/proc'):\n"
       "  if p.isdigit():\n"
       "    try:\n"
       "      c=open(f'/proc/{p}/cmdline','rb').read().split(b'\\0')[0]\n"
       "      if c.endswith(b'ssh'): os.kill(int(p), signal.SIGKILL)\n"
       "    except OSError: pass\n")


def otro_programa(tipo: str):
    if tipo == "otro_parte":  # como certbot o un panel: añade una línea en otra parte del archivo
        en_servidor(f"p='{SITIO}';t=open(p).read();"
                    f"t=t.replace('server_name a.test;','server_name a.test;\\n    {MARCA_OTRO}',1);open(p,'w').write(t)")
    else:                     # cambia la misma línea que la herramienta
        en_servidor(f"import re;p='{SITIO}';t=open(p).read();"
                    f"t=re.sub(r'ssl_ecdh_curve [^;]+;','{LINEA_OTRO}',t,count=1);open(p,'w').write(t)")


def herramienta(env: dict) -> subprocess.Popen:
    e = [x for k, v in env.items() for x in ("-e", f"{k}={v}")]
    return subprocess.Popen([*COMPOSE, "exec", "-T", *e, "herramienta", "python3", "-m", "pqnginx.aplicar",
                             "servidor", "--sni", "a.test", "--sni", "b.test", "--sin-comprobar-host", "--si",
                             "--plazo", str(PLAZO), "--registro", "/tmp/robustez.jsonl"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace")


def esperar_salida(proc: subprocess.Popen, texto: str, limite=60) -> list[str]:
    lineas, t0 = [], time.time()
    while time.time() - t0 < limite:
        l = proc.stdout.readline()
        if not l:
            break
        lineas.append(l.rstrip())
        if texto in l:
            break
    return lineas


def esperar_estado(estados: tuple, desde: float, limite=60) -> dict | None:
    t0 = time.time()
    while time.time() - t0 < limite:
        d = diario()
        if d and d.get("inicio", 0) >= desde - 2 and d["estado"] in estados:
            return d
        time.sleep(0.3)
    return None


def clasificar(d: dict | None, linea: str, v: dict) -> str:
    estado = d["estado"] if d else None
    if estado in PENDIENTES:
        return "pendiente"
    if estado == "conflicto":
        return "conflicto"
    if linea == LINEA_ORIGINAL:
        return "original"
    if estado == "confirmado" and elige(v):
        return "nuevo"
    return f"inesperado({estado}, {linea})"


def ejecutar(nombre: str) -> dict:
    tipo, lado, punto, forzar, esperados = ESCENARIOS[nombre]
    recrear()
    en_servidor("import os;p='/var/lib/pqnginx/prueba.json';os.path.exists(p) and os.remove(p)")
    t0 = time.time()
    env = {}
    if forzar:
        env["PQNGINX_FORZAR_FALLO"] = "1"
    salida = []
    if lado == "ayudante":
        accion = "salir" if tipo == "matar" else "pausa"
        en_servidor("import json,os;os.makedirs('/var/lib/pqnginx',exist_ok=True);"
                    f"json.dump({{'punto':'{punto}','accion':'{accion}','segundos':6}},open('/var/lib/pqnginx/prueba.json','w'))")
        proc = herramienta(env)
        if tipo != "matar":
            esperar_estado((PUNTO_A_ESTADO[punto],), t0, limite=60)
    elif lado == "corte" or (lado == "herramienta" and tipo == "matar"):
        env["PQNGINX_CORTE"] = punto
        proc = herramienta(env)
        if lado == "corte":
            salida += esperar_salida(proc, "se interrumpe")
    else:
        env["PQNGINX_PAUSA"] = f"{punto}:6"
        proc = herramienta(env)
        salida += esperar_salida(proc, "[prueba] pausa")
    t_fallo = time.time()
    if tipo == "ssh":
        matar_ssh()
    elif tipo == "reinicio":
        dc("restart", "-t", "1", "servidor", espera=120)
        esperar_servidor()
    elif tipo in ("otro_parte", "otro_linea"):
        otro_programa(tipo)
    try:
        resto, _ = proc.communicate(timeout=120)
        salida += resto.splitlines()
    except subprocess.TimeoutExpired:
        proc.kill()
        salida.append("(la herramienta no terminó en 120 s)")
    en_servidor("import os;p='/var/lib/pqnginx/prueba.json';os.path.exists(p) and os.remove(p)")
    # esperar a que no quede nada pendiente (el temporizador tarda como mucho el plazo)
    t_estable = None
    limite = time.time() + PLAZO + 30
    while time.time() < limite:
        d = diario()
        if not d or d["estado"] not in PENDIENTES:
            t_estable = time.time() - t_fallo
            break
        time.sleep(0.5)
    d = diario()
    linea = linea_actual()
    v = verificar()
    final = clasificar(d, linea, v)
    otro_conservado = None
    if tipo == "otro_parte":
        otro_conservado = MARCA_OTRO in en_servidor(f"print(open('{SITIO}').read())")
    elif tipo == "otro_linea" and final == "conflicto":
        otro_conservado = linea == LINEA_OTRO
    nginx_t = dc("exec", "-T", "servidor", "nginx", "-t").returncode == 0
    correcto = (final in esperados and servicio_ok(v) and nginx_t and otro_conservado is not False)
    # relanzar la herramienta sin fallos
    r2 = herramienta({})
    salida2, _ = r2.communicate(timeout=180)
    v2 = verificar()
    d2 = diario()
    relanzar_ok = elige(v2) and servicio_ok(v2) and (d2 is None or d2["estado"] not in PENDIENTES)
    if tipo == "otro_parte":
        relanzar_ok = relanzar_ok and MARCA_OTRO in en_servidor(f"print(open('{SITIO}').read())")
    return {"escenario": nombre, "final": final, "esperados": sorted(esperados), "correcto": correcto,
            "servicio": servicio_ok(v), "nginx_t": nginx_t, "otro_conservado": otro_conservado,
            "segundos_hasta_estable": round(t_estable, 1) if t_estable is not None else None,
            "estado_diario": d["estado"] if d else None,
            "resultado_deshacer": d.get("resultado_deshacer") if d else None,
            "relanzar_ok": relanzar_ok, "salida": salida[-8:], "salida_relanzar": salida2.splitlines()[-3:]}


def resumir(filas: list[dict]) -> str:
    out = ["| Escenario | Correcto | Al relanzar | Final | Segundos hasta estable (mediana) |",
           "|---|---|---|---|---|"]
    for nombre in ESCENARIOS:
        fs = [f for f in filas if f["escenario"] == nombre]
        if not fs:
            continue
        t = [f["segundos_hasta_estable"] for f in fs if f["segundos_hasta_estable"] is not None]
        finales = sorted({f["final"] for f in fs})
        out.append(f"| {nombre} | {sum(f['correcto'] for f in fs)}/{len(fs)} | {sum(f['relanzar_ok'] for f in fs)}/{len(fs)} "
                   f"| {', '.join(finales)} | {statistics.median(t) if t else '-'} |")
    n = len(filas)
    out.append(f"\nTotal: {sum(f['correcto'] for f in filas)}/{n} correctos; "
               f"{sum(f['relanzar_ok'] for f in filas)}/{n} terminan bien al relanzar.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repeticiones", type=int, default=3)
    ap.add_argument("--solo", action="append")
    ap.add_argument("--salida", default=str(DATOS / "robustez.jsonl"))
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    nombres = a.solo or list(ESCENARIOS)
    salida = Path(a.salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    filas = []
    for rep in range(1, a.repeticiones + 1):
        for nombre in nombres:
            t = time.time()
            f = ejecutar(nombre) | {"repeticion": rep}
            filas.append(f)
            with salida.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")
            print(f"[{rep}] {nombre}: {'OK' if f['correcto'] else 'FALLO'} final={f['final']} "
                  f"estable={f['segundos_hasta_estable']} s relanzar={'OK' if f['relanzar_ok'] else 'FALLO'} "
                  f"({time.time() - t:.0f} s)", flush=True)
    print()
    print(resumir(filas))


if __name__ == "__main__":
    main()
