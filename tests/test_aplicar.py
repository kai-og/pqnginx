"""Pruebas de las reglas de cambio (herramienta) y de aplicar y deshacer (ayudante)."""
import unittest

from pqnginx.aplicar import evaluar, nueva_lista_grupos, nuevos_protocolos, planificar
from pqnginx.ayudante import Error, aplicar_cambios, revertir_cambios, sha, validar


class Reglas(unittest.TestCase):
    def test_lista_de_mozilla(self):
        self.assertEqual(nueva_lista_grupos("X25519:prime256v1:secp384r1"),
                         "X25519MLKEM768/X25519:prime256v1:secp384r1")

    def test_conserva_lo_que_habia(self):
        self.assertEqual(nueva_lista_grupos("secp384r1"), "X25519MLKEM768/secp384r1")

    def test_lista_plana_pasa_a_tuplas(self):
        self.assertEqual(nueva_lista_grupos("X25519MLKEM768:X25519"), "X25519MLKEM768/X25519")

    def test_ya_correcta_o_por_defecto(self):
        self.assertIsNone(nueva_lista_grupos("X25519MLKEM768/X25519"))
        self.assertIsNone(nueva_lista_grupos("auto"))

    def test_tls13(self):
        self.assertEqual(nuevos_protocolos("TLSv1.2"), "TLSv1.2 TLSv1.3")
        self.assertIsNone(nuevos_protocolos("TLSv1.2 TLSv1.3"))


CONF = """server {
    listen 443 ssl;
    ssl_protocols TLSv1.2;   # comentario
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    # ssl_ecdh_curve secp521r1;
    ssl_protocols TLSv1.2; ssl_ecdh_curve secp384r1;
}
"""


class Planificar(unittest.TestCase):
    def setUp(self):
        self.cambios, self.avisos = planificar({"/etc/nginx/a.conf": {"contenido": CONF, "hash": "h"}})

    def test_cambia_las_dos_directivas_y_conserva_sangria_y_comentario(self):
        self.assertEqual([c["linea"] for c in self.cambios], [2, 3])
        self.assertEqual(self.cambios[0]["despues"], "    ssl_protocols TLSv1.2 TLSv1.3;   # comentario")
        self.assertEqual(self.cambios[1]["despues"], "    ssl_ecdh_curve X25519MLKEM768/X25519:prime256v1:secp384r1;")

    def test_no_toca_comentarios_ni_lineas_compuestas(self):
        self.assertEqual(len(self.avisos), 1)
        self.assertIn(":6:", self.avisos[0])


def cambio(linea, antes, despues, archivo="/etc/nginx/a.conf"):
    return {"archivo": archivo, "linea": linea, "antes": antes, "despues": despues}


ORIG = b"server {\n    ssl_ecdh_curve secp384r1;\n}\n"
C = cambio(1, "    ssl_ecdh_curve secp384r1;", "    ssl_ecdh_curve X25519MLKEM768/secp384r1;")


class AplicarYDeshacer(unittest.TestCase):
    def test_aplicar(self):
        self.assertEqual(aplicar_cambios(ORIG, [C]), b"server {\n    ssl_ecdh_curve X25519MLKEM768/secp384r1;\n}\n")

    def test_aplicar_falla_si_la_linea_cambio(self):
        with self.assertRaises(Error):
            aplicar_cambios(b"server {\n    ssl_ecdh_curve X25519;\n}\n", [C])

    def test_deshacer_solo_su_linea_si_otro_programa_cambio_otra_parte(self):
        nuevo = aplicar_cambios(ORIG, [C])
        tocado = b"# certbot\n" + nuevo.replace(b"}", b"    ssl_certificate /x.pem;\n}")
        revertido, que = revertir_cambios(tocado, [C])
        self.assertEqual(que, "solo_sus_lineas")
        self.assertEqual(revertido, b"# certbot\nserver {\n    ssl_ecdh_curve secp384r1;\n    ssl_certificate /x.pem;\n}\n")

    def test_conflicto_si_otro_programa_cambio_la_misma_linea(self):
        nuevo = aplicar_cambios(ORIG, [C]).replace(b"X25519MLKEM768/secp384r1", b"prime256v1")
        revertido, que = revertir_cambios(nuevo, [C])
        self.assertIsNone(revertido)
        self.assertIn("otro programa cambió la línea 2", que)

    def test_conserva_finales_de_linea_windows(self):
        orig = ORIG.replace(b"\n", b"\r\n")
        self.assertEqual(revertir_cambios(aplicar_cambios(orig, [C]), [C])[0], orig)


class Validar(unittest.TestCase):
    def test_solo_dentro_de_la_raiz(self):
        with self.assertRaises(Error):
            validar(cambio(0, "ssl_protocols TLSv1.2;", "ssl_protocols TLSv1.3;", "/etc/passwd"), raiz="/etc/nginx")

    def test_solo_directivas_permitidas(self):
        with self.assertRaises(Error):
            validar(cambio(0, "ssl_protocols TLSv1.2;", "include /tmp/x.conf;"), raiz="/etc/nginx")
        with self.assertRaises(Error):
            validar(cambio(0, "ssl_protocols TLSv1.2;", "ssl_ecdh_curve X25519;"), raiz="/etc/nginx")


def resultado(estado, conectan, http=200):
    perfiles = ("clasico", "navegador", "anuncia_hibrido", "solo_hibrido")
    return {"veredicto": {"estado": estado},
            "pruebas": [{"perfil": p, "conecta": c, "http": http if c else None} for p, c in zip(perfiles, conectan)]}


class Evaluar(unittest.TestCase):
    BASE = {"a.test": resultado("solo_clasico", (True, True, True, False))}

    def test_correcto(self):
        ok, _ = evaluar(self.BASE, {"a.test": resultado("elige_hibrido", (True, True, True, True))})
        self.assertTrue(ok)

    def test_cliente_clasico_deja_de_conectar(self):
        ok, p = evaluar(self.BASE, {"a.test": resultado("elige_hibrido", (False, True, True, True))})
        self.assertFalse(ok)
        self.assertIn("clasico", p[0])

    def test_respuesta_distinta(self):
        ok, p = evaluar(self.BASE, {"a.test": resultado("elige_hibrido", (True, True, True, True), http=502)})
        self.assertFalse(ok)

    def test_sin_efecto(self):
        ok, _ = evaluar(self.BASE, self.BASE)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
