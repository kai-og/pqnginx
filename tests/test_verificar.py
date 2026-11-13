"""Pruebas del comprobador con salidas reales de `openssl s_client` (prueba de laboratorio del 6 nov 2026)."""
import unittest
from pathlib import Path

from pqnginx.verificar import HIBRIDO, Prueba, analizar, veredicto

DATOS = Path(__file__).parent / "datos"


def leer(nombre):
    return (DATOS / nombre).read_text(encoding="utf-8", errors="replace")


class Analizar(unittest.TestCase):
    def test_hibrido_tras_hello_retry_request(self):
        self.assertEqual(analizar(leer("hibrido_con_hrr.txt")), (HIBRIDO, True, 200))

    def test_lista_plana_da_x25519_sin_hrr(self):
        self.assertEqual(analizar(leer("x25519_sin_hrr.txt")), ("X25519", False, 200))

    def test_cliente_clasico_lee_peer_temp_key(self):
        self.assertEqual(analizar(leer("clasico_peer_temp_key.txt")), ("X25519", False, 200))

    def test_handshake_fallido(self):
        self.assertEqual(analizar(leer("falla_solo_hibrido.txt")), (None, False, None))


def pruebas(**grupos):
    """grupos: perfil -> grupo negociado, o None si no conecta."""
    return [Prueba("a.test", p, g is not None, g, False, 200 if g else None) for p, g in grupos.items()]


class Veredicto(unittest.TestCase):
    def test_elige(self):
        v = veredicto(pruebas(clasico="X25519", navegador=HIBRIDO, anuncia_hibrido=HIBRIDO, solo_hibrido=HIBRIDO))
        self.assertEqual(v, {"estado": "elige_hibrido", "clasicos_conectan": True, "correcto": True})

    def test_acepta_pero_no_elige(self):
        # Lista plana X25519MLKEM768:X25519: al que solo adelanta X25519 le da X25519
        v = veredicto(pruebas(clasico="X25519", navegador=HIBRIDO, anuncia_hibrido="X25519", solo_hibrido=HIBRIDO))
        self.assertEqual(v["estado"], "acepta_hibrido")
        self.assertFalse(v["correcto"])

    def test_solo_clasico(self):
        v = veredicto(pruebas(clasico="X25519", navegador="X25519", anuncia_hibrido="X25519", solo_hibrido=None))
        self.assertEqual(v["estado"], "solo_clasico")

    def test_hibrido_que_deja_fuera_a_los_clasicos_no_es_correcto(self):
        v = veredicto(pruebas(clasico=None, navegador=HIBRIDO, anuncia_hibrido=HIBRIDO, solo_hibrido=HIBRIDO))
        self.assertEqual(v["estado"], "elige_hibrido")
        self.assertFalse(v["correcto"])

    def test_sin_servicio(self):
        v = veredicto(pruebas(clasico=None, navegador=None, anuncia_hibrido=None, solo_hibrido=None))
        self.assertEqual(v["estado"], "sin_servicio")


if __name__ == "__main__":
    unittest.main()
