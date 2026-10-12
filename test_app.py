"""Pruebas del portal. Ejecutar: python3 -I -m unittest -v test_app (desde esta carpeta)."""
import http.client
import os
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

TMP = tempfile.mkdtemp()
os.environ["DATA_DIR"] = TMP
import app  # noqa: E402


class Client:
    def __init__(self, port, headers=None):
        self.port, self.cookie, self.headers = port, "", headers or {}

    def req(self, method, path, data=None, extra=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": "127.0.0.1:%d" % self.port, **self.headers, **(extra or {})}
        if self.cookie:
            h["Cookie"] = "pm_session=" + self.cookie
        body = None
        if data is not None:
            body = urlencode(data)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body, h)
        r = c.getresponse()
        text = r.read().decode()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie" and v.startswith("pm_session="):
                self.cookie = v.split(";")[0].split("=", 1)[1]
        return r.status, text, r

    def csrf(self, path="/cuenta"):
        return re.search(r'name="csrf" value="([0-9a-f]+)"', self.req("GET", path)[1]).group(1)


class PortalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_data()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_1_instalacion_y_login(self):
        c = Client(self.port)
        self.assertEqual(c.req("GET", "/")[0], 303)  # sin usuarios -> /setup
        s, _, _ = c.req("POST", "/setup", {"code": "mal", "name": "A", "email": "a@x.mx", "password": "contrasena-larga"})
        self.assertEqual(s, 200)
        self.assertTrue(app.no_users())
        code = open(os.path.join(TMP, "setup_code.txt")).read().strip()
        s, _, _ = c.req("POST", "/setup", {"code": code, "name": "Admin", "email": "admin@x.mx", "password": "contrasena-larga"})
        self.assertEqual(s, 303)
        self.assertFalse(os.path.exists(os.path.join(TMP, "setup_code.txt")))
        s, t, _ = c.req("POST", "/entrar", {"email": "admin@x.mx", "password": "incorrecta"})
        self.assertEqual(s, 401)
        s, _, _ = c.req("POST", "/entrar", {"email": "admin@x.mx", "password": "contrasena-larga"})
        self.assertEqual(s, 303)
        s, t, _ = c.req("GET", "/")
        self.assertEqual(s, 200)
        self.assertIn("Riego (RainMachine)", t)
        self.assertNotIn("Administración de medidores", t)  # sin dirección y oculto

    def test_2_registro_aprobacion_y_roles(self):
        adm = Client(self.port)
        adm.req("POST", "/entrar", {"email": "admin@x.mx", "password": "contrasena-larga"})
        nuevo = Client(self.port)
        s, t, _ = nuevo.req("POST", "/registro", {"name": "Ana", "email": "ana@x.mx", "password": "otra-contrasena"})
        self.assertIn("Solicitud enviada", t)
        s, t, _ = nuevo.req("POST", "/entrar", {"email": "ana@x.mx", "password": "otra-contrasena"})
        self.assertEqual(s, 403)  # pendiente
        uid = app.db().execute("SELECT id FROM users WHERE email='ana@x.mx'").fetchone()[0]
        csrf = adm.csrf("/admin/usuarios")
        adm.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "aprobar", "id": uid})
        adm.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "rol", "id": uid, "role": "usuario"})
        s, _, _ = nuevo.req("POST", "/entrar", {"email": "ana@x.mx", "password": "otra-contrasena"})
        self.assertEqual(s, 303)
        s, t, _ = nuevo.req("GET", "/")
        self.assertIn("Riego (RainMachine)", t)
        self.assertNotIn("Synology (DSM)", t)  # solo admin
        self.assertEqual(nuevo.req("GET", "/admin/usuarios")[0], 403)

    def test_3_csrf_y_origen(self):
        adm = Client(self.port)
        adm.req("POST", "/entrar", {"email": "admin@x.mx", "password": "contrasena-larga"})
        s, _, _ = adm.req("POST", "/admin/usuarios", {"act": "crear", "name": "X", "email": "x@x.mx", "role": "admin"})
        self.assertEqual(s, 403)  # sin token
        csrf = adm.csrf("/admin/usuarios")
        s, _, _ = adm.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "crear", "name": "X", "email": "y@x.mx", "role": "admin"},
                          {"Origin": "http://otro.sitio"})
        self.assertEqual(s, 403)  # origen ajeno
        self.assertIsNone(app.db().execute("SELECT 1 FROM users WHERE email='y@x.mx'").fetchone())

    def test_4_bloqueo_por_intentos(self):
        c = Client(self.port, {"X-Forwarded-For": "9.9.9.9"})
        for _ in range(app.MAX_FAILS):
            c.req("POST", "/entrar", {"email": "admin@x.mx", "password": "mala"})
        s, _, _ = c.req("POST", "/entrar", {"email": "admin@x.mx", "password": "contrasena-larga"})
        self.assertEqual(s, 429)

    def test_5_usuario_creado_debe_cambiar_password(self):
        adm = Client(self.port)
        adm.req("POST", "/entrar", {"email": "admin@x.mx", "password": "contrasena-larga"})
        csrf = adm.csrf("/admin/usuarios")
        s, t, _ = adm.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "crear", "name": "Beto", "email": "beto@x.mx", "role": "invitado"})
        temp = re.search(r"<code>([^<]+)</code>", t).group(1)
        b = Client(self.port)
        b.req("POST", "/entrar", {"email": "beto@x.mx", "password": temp})
        s, _, r = b.req("GET", "/")
        self.assertEqual((s, r.getheader("Location")), (303, "/cuenta"))

    def test_6_escape_html_y_url_segura(self):
        adm = Client(self.port)
        adm.req("POST", "/entrar", {"email": "admin@x.mx", "password": "contrasena-larga"})
        csrf = adm.csrf("/admin/equipos")
        s, t, _ = adm.req("POST", "/admin/equipos", {"csrf": csrf, "act": "crear", "name": "Mal", "url": "javascript:alert(1)", "r_admin": "1", "enabled": "1"})
        self.assertIn("http://", t)
        adm.req("POST", "/admin/equipos", {"csrf": csrf, "act": "crear", "name": "<b>x</b>", "url": "https://a.mx", "r_admin": "1", "enabled": "1"})
        t = adm.req("GET", "/")[1]
        self.assertNotIn("<b>x</b>", t)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", t)

    def test_7_modo_cloudflare(self):
        app.AUTH_MODE = "cloudflare"
        try:
            c = Client(self.port, {"Cf-Access-Authenticated-User-Email": "nuevo@x.mx"})
            self.assertEqual(c.req("GET", "/")[0], 403)  # queda pendiente
            self.assertEqual(Client(self.port).req("GET", "/")[0], 403)  # sin cabecera
            app.db().execute("UPDATE users SET status='activo', role='usuario' WHERE email='nuevo@x.mx'").connection.commit()
            s, t, _ = c.req("GET", "/")
            self.assertEqual(s, 200)
            self.assertIn("Riego", t)
        finally:
            app.AUTH_MODE = "local"


if __name__ == "__main__":
    unittest.main()
