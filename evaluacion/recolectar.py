"""Descarga configuraciones reales de NGINX publicadas en GitHub que fijan `ssl_ecdh_curve`.

Usa la búsqueda de código de GitHub (con `gh`, autenticado) y descarga cada archivo de
raw.githubusercontent.com. Quita duplicados por contenido. Los archivos no se publican:
se guardan en evaluacion/datos/, que git ignora.

Uso (en el equipo, no en el contenedor):
    python evaluacion/recolectar.py --consulta "ssl_ecdh_curve language:Nginx" --paginas 10
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DATOS = Path(__file__).parent / "datos"


def buscar(consulta: str, pagina: int) -> list[dict]:
    r = subprocess.run(["gh", "api", "-X", "GET", "search/code", "-f", f"q={consulta}",
                        "-f", "per_page=100", "-f", f"page={pagina}"],
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print(f"página {pagina}: {r.stderr.strip()[:200]}", file=sys.stderr)
        return []
    return json.loads(r.stdout).get("items", [])


def bruto(html_url: str) -> str:
    # https://github.com/o/r/blob/<commit>/ruta -> https://raw.githubusercontent.com/o/r/<commit>/ruta
    return html_url.replace("https://github.com/", "https://raw.githubusercontent.com/", 1).replace("/blob/", "/", 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--consulta", default="ssl_ecdh_curve language:Nginx")
    ap.add_argument("--paginas", type=int, default=10)
    a = ap.parse_args()
    carpeta = DATOS / "configs"
    carpeta.mkdir(parents=True, exist_ok=True)
    indice_ruta = DATOS / "indice.json"
    indice = json.loads(indice_ruta.read_text(encoding="utf-8")) if indice_ruta.exists() else {}
    vistos = {v["hash"] for v in indice.values()}
    for p in range(1, a.paginas + 1):
        items = buscar(a.consulta, p)
        print(f"página {p}: {len(items)} resultados", flush=True)
        if not items:
            break
        for it in items:
            url = bruto(it["html_url"])
            if any(v["url"] == url for v in indice.values()):
                continue
            try:
                with urllib.request.urlopen(url, timeout=20) as resp:
                    texto = resp.read(500_000).decode("utf-8", errors="replace")
            except Exception as e:
                print(f"  fallo {url}: {e}", file=sys.stderr)
                continue
            h = hashlib.sha256(texto.encode()).hexdigest()[:16]
            if h in vistos or "ssl_ecdh_curve" not in texto:
                continue
            vistos.add(h)
            nombre = f"{len(indice):04d}.conf"
            (carpeta / nombre).write_text(texto, encoding="utf-8")
            indice[nombre] = {"repo": it["repository"]["full_name"], "ruta": it["path"], "url": url, "hash": h}
        indice_ruta.write_text(json.dumps(indice, ensure_ascii=False, indent=1), encoding="utf-8")
        time.sleep(7)  # la búsqueda de código admite unas 10 peticiones por minuto
    print(f"{len(indice)} configuraciones únicas en {carpeta}")


if __name__ == "__main__":
    main()
