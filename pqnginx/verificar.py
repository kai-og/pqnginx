"""Comprueba desde fuera qué grupo negocia un servidor TLS, con varios perfiles de cliente y por dominio.

No necesita permisos sobre el servidor: se conecta como un cliente más, con `openssl s_client`
(OpenSSL 3.5 o superior), y lee del handshake el grupo negociado y si hubo HelloRetryRequest.

Uso:
    python3 -m pqnginx.verificar HOST [--puerto 443] --sni a.test [--sni b.test] [--json]
"""
import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass

HIBRIDO = "X25519MLKEM768"

# Perfiles de cliente, con la sintaxis de grupos de OpenSSL 3.5: '*' marca los grupos
# cuya clave se adelanta en el primer mensaje (key_share).
PERFILES = {
    # Cliente antiguo: solo conoce X25519.
    "clasico": "X25519",
    # Navegador actual: ofrece y adelanta las dos claves.
    "navegador": f"*{HIBRIDO}:*X25519",
    # Ofrece el híbrido pero solo adelanta X25519: el servidor debe pedirle la otra clave
    # (HelloRetryRequest) si de verdad prefiere el híbrido. Distingue elegir de aceptar.
    "anuncia_hibrido": f"{HIBRIDO}:*X25519",
    # Solo híbrido: si conecta, el servidor al menos lo admite.
    "solo_hibrido": HIBRIDO,
}

# En TLS 1.3 OpenSSL escribe "Negotiated TLS1.3 group: X"; con curvas NIST, "Peer Temp Key: ECDH, prime256v1".
_GRUPO = re.compile(r"(?:Negotiated TLS1\.3 group|Peer Temp Key|Server Temp Key): (?:ECDH, )?([A-Za-z0-9_]+)")
_HTTP = re.compile(r"^HTTP/1\.[01] (\d{3})", re.MULTILINE)


@dataclass
class Prueba:
    sni: str
    perfil: str
    conecta: bool
    grupo: str | None
    hrr: bool
    http: int | None


def analizar(salida: str) -> tuple[str | None, bool, int | None]:
    """Extrae de la salida de `s_client -msg` el grupo, si hubo HelloRetryRequest y el código HTTP."""
    m = _GRUPO.search(salida)
    grupo = m.group(1) if m else None
    # Con HelloRetryRequest el cliente envía un segundo ClientHello.
    hrr = salida.count("ClientHello") >= 2
    h = _HTTP.search(salida)
    return grupo, hrr, int(h.group(1)) if h else None


def probar(host: str, puerto: int, sni: str, perfil: str, espera: float = 10) -> Prueba:
    """Hace un handshake TLS 1.3 con un perfil y una petición HTTP mínima."""
    orden = [
        "openssl", "s_client", "-connect", f"{host}:{puerto}", "-servername", sni,
        "-tls1_3", "-groups", PERFILES[perfil], "-msg", "-ign_eof",
    ]
    peticion = f"GET / HTTP/1.0\r\nHost: {sni}\r\n\r\n"
    try:
        r = subprocess.run(orden, input=peticion, capture_output=True, text=True, timeout=espera)
        salida = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return Prueba(sni, perfil, False, None, False, None)
    grupo, hrr, http = analizar(salida)
    return Prueba(sni, perfil, grupo is not None and http is not None, grupo, hrr, http)


def veredicto(pruebas: list[Prueba]) -> dict:
    """Resume las pruebas de un dominio.

    estado:
      elige_hibrido   el servidor prefiere el híbrido: lo usa con el navegador y lo pide al que no lo adelanta
      acepta_hibrido  lo admite si el cliente solo ofrece eso, pero no lo prefiere
      solo_clasico    no lo admite
      sin_servicio    no conecta ningún perfil
    """
    p = {x.perfil: x for x in pruebas}
    usa = lambda nombre: nombre in p and p[nombre].conecta and p[nombre].grupo == HIBRIDO
    if not any(x.conecta for x in pruebas):
        estado = "sin_servicio"
    elif usa("navegador") and usa("anuncia_hibrido"):
        estado = "elige_hibrido"
    elif usa("solo_hibrido"):
        estado = "acepta_hibrido"
    else:
        estado = "solo_clasico"
    clasico_ok = "clasico" in p and p["clasico"].conecta
    return {"estado": estado, "clasicos_conectan": clasico_ok, "correcto": estado == "elige_hibrido" and clasico_ok}


def comprobar(host: str, puerto: int, snis: list[str]) -> dict:
    resultado = {}
    for sni in snis:
        pruebas = [probar(host, puerto, sni, perfil) for perfil in PERFILES]
        resultado[sni] = {"veredicto": veredicto(pruebas), "pruebas": [asdict(x) for x in pruebas]}
    return resultado


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host")
    ap.add_argument("--puerto", type=int, default=443)
    ap.add_argument("--sni", action="append", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    res = comprobar(a.host, a.puerto, a.sni)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        for sni, r in res.items():
            v = r["veredicto"]
            print(f"{sni}: {v['estado']}, clásicos conectan: {'sí' if v['clasicos_conectan'] else 'no'}")
            for x in r["pruebas"]:
                print(f"  {x['perfil']:<16} conecta={'sí' if x['conecta'] else 'no':<3} "
                      f"grupo={x['grupo'] or '-':<15} hrr={'sí' if x['hrr'] else 'no':<3} http={x['http'] or '-'}")
    return 0 if all(r["veredicto"]["correcto"] for r in res.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
