"""Pruebas del analizador, la adaptación y los arreglos ingenuos del banco."""
import unittest

from evaluacion.banco import LISTA_BUENA, LISTA_PLANA, adaptar, arreglos, destinos, objetivos, resultado

SITIO = """
upstream app { server backend:8080; }
server {
    listen 80;
    server_name ejemplo.org www.ejemplo.org;
    return 301 https://$host$request_uri;
}
server {
    listen 1.2.3.4:443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ejemplo.org;   # comentario con ssl_ecdh_curve secp521r1;
    ssl_certificate /etc/letsencrypt/live/ejemplo.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ejemplo.org/privkey.pem;
    ssl_dhparam /etc/ssl/dhparam.pem;
    ssl_ecdh_curve secp384r1;
    access_log /var/www/logs/a.log combined;
    location / { proxy_pass http://app; }
    location /api { proxy_pass http://api.interno:9000/; }
}
"""

COMPLETO = """
user nginx;
http {
    ssl_ecdh_curve secp384r1;
    server {
        listen 443;
        ssl on;
        server_name _;
        ssl_ecdh_curve X25519:prime256v1;
    }
}
"""


class Adaptar(unittest.TestCase):
    def test_sitio(self):
        t, tipo = adaptar(SITIO)
        self.assertEqual(tipo, "sitio")
        self.assertIn("listen 443 ssl http2;", t)
        self.assertNotIn("[::]", t)
        self.assertIn("ssl_certificate /etc/nginx/banco/cert.pem;", t)
        self.assertNotIn("dhparam", t)
        self.assertIn("access_log /var/log/nginx/banco_access.log;", t)
        self.assertEqual(objetivos(t), [(443, "ejemplo.org")])
        self.assertEqual(destinos(t), {"app", "backend", "api.interno"})

    def test_completo_con_ssl_on(self):
        t, tipo = adaptar(COMPLETO)
        self.assertEqual(tipo, "completo")
        self.assertTrue(t.startswith("events {}"))
        self.assertIn("listen 443 ssl;", t)
        self.assertIn("user www-data;", t)
        self.assertEqual(objetivos(t), [(443, "sin-nombre.invalid")])


class Arreglos(unittest.TestCase):
    def test_variantes(self):
        t, tipo = adaptar(COMPLETO)
        a = arreglos(t, tipo)
        self.assertEqual(a["N1_primera_plana"][0].count(LISTA_PLANA), 1)
        self.assertIn("X25519:prime256v1;", a["N1_primera_plana"][0])
        self.assertEqual(a["N2_todas_plana"][0].count(LISTA_PLANA), 2)
        self.assertNotIn("ssl_ecdh_curve", a["N3_quitar_todas"][0])
        self.assertEqual(a["N4_todas_tuplas"][0].count(LISTA_BUENA), 2)
        self.assertEqual(a["N5_anadir_en_http"][0].count("ssl_ecdh_curve"), 3)

    def test_referencia_activa_tls13(self):
        t, tipo = adaptar(COMPLETO.replace("http {", "http {\n    ssl_protocols TLSv1 TLSv1.2;", 1))
        r = arreglos(t, tipo)["R_tuplas_y_tls13"][0]
        self.assertIn("ssl_protocols TLSv1 TLSv1.2 TLSv1.3;", r)
        self.assertEqual(r.count(LISTA_BUENA), 2)

    def test_comentarios_intactos(self):
        t, tipo = adaptar(SITIO)
        self.assertIn("# comentario con ssl_ecdh_curve secp521r1;", arreglos(t, tipo)["N3_quitar_todas"][0])

    def test_sitio_anade_en_archivo_aparte(self):
        t, tipo = adaptar(SITIO)
        texto, extra = arreglos(t, tipo)["N5_anadir_en_http"]
        self.assertEqual(texto, t)
        self.assertIn(LISTA_BUENA, extra)


class Resultado(unittest.TestCase):
    B = [{"estado": "solo_clasico", "clasicos": True, "http": 200}]

    def test_exito(self):
        self.assertEqual(resultado(self.B, [{"estado": "elige_hibrido", "clasicos": True, "http": 200}]), "exito")

    def test_rompe_servicio(self):
        self.assertEqual(resultado(self.B, [{"estado": "elige_hibrido", "clasicos": True, "http": None}]), "rompe_servicio")

    def test_sin_efecto(self):
        self.assertEqual(resultado(self.B, [{"estado": "solo_clasico", "clasicos": True, "http": 200}]), "sin_efecto")

    def test_acepta(self):
        self.assertEqual(resultado(self.B, [{"estado": "acepta_hibrido", "clasicos": True, "http": 200}]), "acepta_sin_elegir")


if __name__ == "__main__":
    unittest.main()
