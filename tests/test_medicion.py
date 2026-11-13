"""Pruebas de la clasificación de la medición en Internet."""
import unittest

from medicion.medir import cabeceras, clasificar, es_cdn
from pqnginx.verificar import HIBRIDO


def r(**grupos):
    return {"grupos": grupos}


class Clasificar(unittest.TestCase):
    def test_elige_el_hibrido(self):
        self.assertEqual(clasificar(r(amplio=HIBRIDO, anuncia_hibrido=HIBRIDO, solo_hibrido=HIBRIDO)), "A")

    def test_lista_plana_acepta_sin_elegir(self):
        self.assertEqual(clasificar(r(amplio=HIBRIDO, anuncia_hibrido="X25519", solo_hibrido=HIBRIDO)), "B")

    def test_biblioteca_antigua_con_lista_por_defecto(self):
        self.assertEqual(clasificar(r(amplio="X25519", anuncia_hibrido="X25519", solo_hibrido=None,
                                      X448="X448", secp521r1="secp521r1")), "C1")

    def test_lista_de_mozilla_bloquea(self):
        self.assertEqual(clasificar(r(amplio="X25519", anuncia_hibrido="X25519", solo_hibrido=None,
                                      X448=None, secp521r1=None)), "C2")

    def test_solo_secp384r1(self):
        self.assertEqual(clasificar(r(amplio="secp384r1", anuncia_hibrido=None, solo_hibrido=None,
                                      X448=None, secp521r1=None)), "C2")


class Cabeceras(unittest.TestCase):
    SALIDA = "algo\r\nHTTP/1.1 301 Moved Permanently\r\nServer: nginx/1.18.0 (Ubuntu)\r\nVia: 1.1 varnish\r\n\r\ncuerpo"

    def test_lee_server_y_via(self):
        c = cabeceras(self.SALIDA)
        self.assertEqual(c["server"], "nginx/1.18.0 (Ubuntu)")
        self.assertTrue(es_cdn(c))

    def test_sin_cdn(self):
        self.assertFalse(es_cdn({"server": "nginx", "content-type": "text/html"}))

    def test_cloudflare(self):
        self.assertTrue(es_cdn({"server": "nginx", "cf-ray": "abc"}))


if __name__ == "__main__":
    unittest.main()
