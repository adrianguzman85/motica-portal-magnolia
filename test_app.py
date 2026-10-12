"""Pruebas del portal. Ejecutar: python3 -I -m unittest -v test_app (desde esta carpeta)."""
import http.client
import os
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
        text = r.read().decode(errors="replace")
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


class DosEnlacesTest(unittest.TestCase):
    """Cada equipo puede tener enlace local y remoto; el portal muestra un botón por cada uno."""

    @classmethod
    def setUpClass(cls):
        cls.old = app.DATA_DIR
        app.DATA_DIR = tempfile.mkdtemp()
        app.init_data()
        with app.db() as c:
            c.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES('a@x.mx','A',?,'admin','activo',1)",
                      (app.hash_pw("contrasena-larga"),))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        app.DATA_DIR = cls.old

    def test_dos_botones_y_validacion(self):
        c = Client(self.port)
        c.req("POST", "/entrar", {"email": "a@x.mx", "password": "contrasena-larga"})
        csrf = c.csrf("/admin/equipos")
        base = {"csrf": csrf, "act": "crear", "name": "Doble", "r_admin": "1", "enabled": "1"}
        c.req("POST", "/admin/equipos", {**base, "url_local": "http://192.168.11.5:8081", "url": "https://remoto.x.mx"})
        t = c.req("GET", "/")[1]
        self.assertIn("Abrir local", t)
        self.assertIn("Abrir remoto", t)
        self.assertIn("http://192.168.11.5:8081", t)
        remotos = t.count("Abrir remoto")
        # solo local
        c.req("POST", "/admin/equipos", {**base, "name": "Solo local", "url_local": "http://192.168.11.37", "url": ""})
        t = c.req("GET", "/")[1]
        self.assertIn("Solo local", t)
        self.assertEqual(t.count("Abrir remoto"), remotos)  # el equipo "Solo local" no añade botón remoto
        # direcciones peligrosas se rechazan
        s, t, _ = c.req("POST", "/admin/equipos", {**base, "name": "Malo", "url_local": "javascript:alert(1)", "url": ""})
        self.assertIn("http://", t)
        self.assertNotIn("Malo", c.req("GET", "/")[1])


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def post_multipart(port, cookie, path, fields, filename=None, content=b"", ctype="image/png"):
    boundary = "----pruebaFoto123"
    body = b""
    for k, v in fields.items():
        body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (boundary, k, v)).encode()
    if filename is not None:
        body += ("--%s\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
                 % (boundary, filename, ctype)).encode() + content + b"\r\n"
    body += ("--%s--\r\n" % boundary).encode()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", path, body, {"Host": "127.0.0.1:%d" % port, "Cookie": "pm_session=" + cookie,
                                   "Content-Type": "multipart/form-data; boundary=" + boundary})
    r = c.getresponse()
    return r.status, r.read().decode()


class FotosTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = app.DATA_DIR
        app.DATA_DIR = tempfile.mkdtemp()
        app.init_data()
        with app.db() as c:
            c.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES('a@x.mx','A',?,'admin','activo',1)", (app.hash_pw("contrasena-larga"),))
            c.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES('u@x.mx','U',?,'usuario','activo',1)", (app.hash_pw("contrasena-larga"),))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.adm, cls.usr = Client(cls.port), Client(cls.port)
        cls.adm.req("POST", "/entrar", {"email": "a@x.mx", "password": "contrasena-larga"})
        cls.usr.req("POST", "/entrar", {"email": "u@x.mx", "password": "contrasena-larga"})

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        app.DATA_DIR = cls.old

    def test_1_subir_y_ver_foto(self):
        csrf = self.adm.csrf("/admin/equipos")
        s, _ = post_multipart(self.port, self.adm.cookie, "/admin/foto", {"csrf": csrf, "id": "1", "act": "subir"}, "r.png", PNG)
        self.assertEqual(s, 303)
        s, body, r = self.adm.req("GET", "/foto/1")
        self.assertEqual((s, r.getheader("Content-Type")), (200, "image/png"))
        self.assertIn('src="/foto/1"', self.adm.req("GET", "/")[1])
        self.assertIn('class="foto mini"', self.adm.req("GET", "/admin/equipos")[1])

    def test_2_solo_imagenes(self):
        csrf = self.adm.csrf("/admin/equipos")
        s, t = post_multipart(self.port, self.adm.cookie, "/admin/foto", {"csrf": csrf, "id": "2", "act": "subir"},
                              "x.svg", b"<svg onload=alert(1)></svg>", "image/svg+xml")
        self.assertIn("Solo se aceptan imágenes", t)
        self.assertEqual(self.adm.req("GET", "/foto/2")[0], 404)
        s, t = post_multipart(self.port, self.adm.cookie, "/admin/foto", {"csrf": csrf, "id": "2", "act": "subir"}, "x.png",
                              PNG + b"0" * app.MAX_PHOTO)
        self.assertIn("más de 2 MB", t)

    def test_3_permisos_por_rol(self):
        csrf = self.adm.csrf("/admin/equipos")
        post_multipart(self.port, self.adm.cookie, "/admin/foto", {"csrf": csrf, "id": "2", "act": "subir"}, "s.png", PNG)
        self.assertEqual(self.usr.req("GET", "/foto/1")[0], 200)  # Riego: admin y usuario
        self.assertEqual(self.usr.req("GET", "/foto/2")[0], 404)  # Synology: solo admin
        ucsrf = self.usr.csrf("/cuenta")
        s, _ = post_multipart(self.port, self.usr.cookie, "/admin/foto", {"csrf": ucsrf, "id": "1", "act": "subir"}, "m.png", PNG)
        self.assertEqual(s, 403)

    def test_4_quitar_y_csrf(self):
        s, _ = post_multipart(self.port, self.adm.cookie, "/admin/foto", {"csrf": "falso", "id": "1", "act": "quitar"})
        self.assertEqual(s, 403)
        csrf = self.adm.csrf("/admin/equipos")
        post_multipart(self.port, self.adm.cookie, "/admin/foto", {"csrf": csrf, "id": "1", "act": "quitar"})
        self.assertEqual(self.adm.req("GET", "/foto/1")[0], 404)


class FakeDevice(BaseHTTPRequestHandler):
    """Un equipo de la red local: página con enlaces absolutos, cookie con Domain, redirección y eco."""
    port = 0

    def log_message(self, *a):
        pass

    def reply(self, status, body, headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        origin = "http://127.0.0.1:%d" % FakeDevice.port
        if self.path == "/redir":
            return self.reply(302, b"", [("Location", origin + "/destino")])
        if self.path == "/ui/":
            return self.reply(200, b"ui", [("Content-Type", "text/plain")])
        if self.path == "/corto":  # declara 100 bytes y envía 10 (como algunos equipos reales)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"0123456789")
            self.close_connection = True
            return
        body = ('<a href="%s/x">x</a> host=%s ref=%s' % (origin, self.headers.get("Host"), self.headers.get("Origin", ""))).encode()
        self.reply(200, body, [("Content-Type", "text/html"), ("Set-Cookie", "dev=1; Domain=127.0.0.1; Path=/")])

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.reply(200, self.rfile.read(n), [("Content-Type", "application/octet-stream")])


def raw(port, method, path, host, cookie="", body=None, extra=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host, **(extra or {})}
    if cookie:
        h["Cookie"] = cookie
    c.request(method, path, body, h)
    r = c.getresponse()
    return r.status, r.getheaders(), r.read()


def hdr(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


class PuenteTest(unittest.TestCase):
    PORTAL, PROXY = "magnolia.motica.test", "tablero.motica.test"

    @classmethod
    def setUpClass(cls):
        cls.old = (app.DATA_DIR, app.PROXY_DOMAIN, app.PORTAL_HOST)
        app.DATA_DIR, app.PROXY_DOMAIN, app.PORTAL_HOST = tempfile.mkdtemp(), "motica.test", cls.PORTAL
        app.init_data()
        cls.dev = ThreadingHTTPServer(("127.0.0.1", 0), FakeDevice)
        FakeDevice.port = cls.dev.server_address[1]
        threading.Thread(target=cls.dev.serve_forever, daemon=True).start()
        with app.db() as c:
            for mail, role in (("a@x.mx", "admin"), ("u@x.mx", "usuario")):
                c.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES(?,?,?,?,'activo',1)",
                          (mail, mail, app.hash_pw("contrasena-larga"), role))
            c.execute("INSERT INTO devices(name,url_local,slug,proxy,roles,enabled,sort) VALUES('Tablero',?,'tablero',1,'admin',1,50)",
                      ("http://127.0.0.1:%d" % FakeDevice.port,))
            c.execute("INSERT INTO devices(name,url_local,slug,proxy,roles,enabled,sort) VALUES('Otro',?,'otro',1,'admin,usuario',1,60)",
                      ("http://127.0.0.1:%d/ui/" % FakeDevice.port,))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.dev.shutdown()
        app.DATA_DIR, app.PROXY_DOMAIN, app.PORTAL_HOST = cls.old

    def portal(self, mail):
        c = Client(self.port, {"Host": self.PORTAL})
        c.req("POST", "/entrar", {"email": mail, "password": "contrasena-larga"})
        return c

    def ticket(self, mail, slug="tablero", nxt="/"):
        c = self.portal(mail)
        s, _, r = c.req("GET", "/acceso?d=%s&n=%s" % (slug, nxt.replace("/", "%2F")))
        return s, r.getheader("Location")

    def cookie_for(self, mail="a@x.mx", slug="tablero", host=None):
        host = host or self.PROXY
        s, loc = self.ticket(mail, slug)
        self.assertEqual(s, 303)
        path = loc.split(host, 1)[1]
        s, h, _ = raw(self.port, "GET", path, host)
        self.assertEqual(s, 303)
        return hdr(h, "Set-Cookie")[0].split(";")[0]

    def test_1_sin_sesion_va_al_portal(self):
        s, h, _ = raw(self.port, "GET", "/pagina?q=1", self.PROXY)
        self.assertEqual(s, 303)
        loc = hdr(h, "Location")[0]
        self.assertTrue(loc.startswith("https://%s/acceso?d=tablero&n=" % self.PORTAL), loc)
        self.assertIn("%2Fpagina%3Fq%3D1", loc)

    def test_2_flujo_completo_y_reescritura(self):
        ck = self.cookie_for()
        s, h, body = raw(self.port, "GET", "/", self.PROXY, ck)
        self.assertEqual(s, 200)
        self.assertIn(b'href="https://tablero.motica.test/x"', body)  # dirección del equipo reescrita
        self.assertNotIn(b"127.0.0.1:%d/x" % FakeDevice.port, body)
        self.assertIn(("host=127.0.0.1:%d" % FakeDevice.port).encode(), body)  # el equipo ve su propio Host
        self.assertNotIn("domain", hdr(h, "Set-Cookie")[0].lower())  # cookie sin Domain
        s, h, _ = raw(self.port, "GET", "/redir", self.PROXY, ck)
        self.assertEqual((s, hdr(h, "Location")[0]), (302, "https://tablero.motica.test/destino"))
        s, _, body = raw(self.port, "POST", "/eco", self.PROXY, ck, b"hola", {"Content-Type": "text/plain"})
        self.assertEqual((s, body), (200, b"hola"))

    def test_2b_respuesta_cortada_del_equipo(self):
        ck = self.cookie_for()
        s, h, body = raw(self.port, "GET", "/corto", self.PROXY, ck)
        self.assertEqual((s, body), (200, b"0123456789"))
        self.assertEqual(hdr(h, "Content-Length"), ["10"])  # largo corregido

    def test_3_el_rol_manda(self):
        s, _ = self.ticket("u@x.mx", "tablero")  # solo admin
        self.assertEqual(s, 403)
        s, loc = self.ticket("u@x.mx", "otro")  # admin y usuario
        self.assertEqual(s, 303)

    def test_4_boleto_manipulado_o_de_otro_equipo(self):
        s, loc = self.ticket("a@x.mx", "tablero")
        path = loc.split(self.PROXY, 1)[1]
        s, _, _ = raw(self.port, "GET", path[:-3] + "AAA", self.PROXY)
        self.assertEqual(s, 403)
        # un boleto del equipo «tablero» no abre «otro»
        s, _, _ = raw(self.port, "GET", path, "otro.motica.test")
        self.assertEqual(s, 403)
        s, _, _ = raw(self.port, "GET", "/_pm/ticket?t=basura", self.PROXY)
        self.assertEqual(s, 403)

    def test_5_cookie_de_otro_equipo_no_sirve(self):
        ck = self.cookie_for("a@x.mx", "tablero")
        s, h, _ = raw(self.port, "GET", "/", "otro.motica.test", ck)
        self.assertEqual(s, 303)  # vuelve a pedir el boleto en el portal

    def test_6_direccion_inexistente_y_equipo_caido(self):
        self.assertEqual(raw(self.port, "GET", "/", "nada.motica.test")[0], 404)
        with app.db() as c:
            c.execute("UPDATE devices SET url_local='http://127.0.0.1:9' WHERE slug='otro'")
        ck = self.cookie_for("a@x.mx", "otro", "otro.motica.test")
        s, _, body = raw(self.port, "GET", "/", "otro.motica.test", ck)
        self.assertEqual(s, 503)
        self.assertIn("no respondió".encode(), body)

    def test_7_bloquear_al_usuario_corta_el_acceso(self):
        ck = self.cookie_for("a@x.mx", "tablero")
        self.assertEqual(raw(self.port, "GET", "/", self.PROXY, ck)[0], 200)
        with app.db() as c:
            c.execute("UPDATE users SET status='bloqueado' WHERE email='a@x.mx'")
        try:
            self.assertEqual(raw(self.port, "GET", "/", self.PROXY, ck)[0], 303)
        finally:
            with app.db() as c:
                c.execute("UPDATE users SET status='activo' WHERE email='a@x.mx'")

    def test_8_login_regresa_al_equipo(self):
        c = Client(self.port, {"Host": self.PORTAL})
        s, _, r = c.req("GET", "/acceso?d=tablero&n=%2F")
        self.assertEqual((s, r.getheader("Location")), (303, "/entrar"))
        nxt = [v for k, v in r.getheaders() if k.lower() == "set-cookie"][0].split(";")[0]
        s, _, r = c.req("POST", "/entrar", {"email": "a@x.mx", "password": "contrasena-larga"}, {"Cookie": nxt})
        self.assertEqual(s, 303)
        self.assertTrue(r.getheader("Location").startswith("/acceso?d=tablero"), r.getheader("Location"))

    def test_9_redireccion_abierta_y_metodos(self):
        s, loc = self.ticket("a@x.mx", "tablero", "//evil.com")
        path = loc.split(self.PROXY, 1)[1]
        s, h, _ = raw(self.port, "GET", path, self.PROXY)
        self.assertEqual((s, hdr(h, "Location")[0]), (303, "/"))  # //evil.com se descarta
        self.assertEqual(raw(self.port, "DELETE", "/", self.PORTAL)[0], 405)


class FotoUrlTest(unittest.TestCase):
    def test_direcciones_no_permitidas(self):
        for url in ("http://example.com/a.png", "https://127.0.0.1/a.png", "https://localhost/a.png",
                    "https://192.168.11.37/a.png", "https://10.0.0.5/a.png", "https://169.254.169.254/latest",
                    "https://[::1]/a.png", "ftp://example.com/a.png", "https://user:pw@example.com/a.png", "", "no es url"):
            with self.assertRaises(ValueError, msg=url):
                app.fetch_image(url)

    def test_flujo_admin_con_descarga(self):
        old = (app.DATA_DIR, app.fetch_image)
        app.DATA_DIR = tempfile.mkdtemp()
        app.init_data()
        with app.db() as c:
            c.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES('a@x.mx','A',?,'admin','activo',1)", (app.hash_pw("contrasena-larga"),))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = Client(port)
            c.req("POST", "/entrar", {"email": "a@x.mx", "password": "contrasena-larga"})
            csrf = c.csrf("/admin/equipos")
            app.fetch_image = lambda url: (PNG, "image/png")
            s, _ = post_multipart(port, c.cookie, "/admin/foto", {"csrf": csrf, "id": "1", "act": "url", "photo_url": "https://ejemplo.mx/a.png"})
            self.assertEqual(s, 303)
            self.assertEqual(c.req("GET", "/foto/1")[0], 200)
            def malo(url):
                raise ValueError("Esa dirección no es pública.")
            app.fetch_image = malo
            s, t = post_multipart(port, c.cookie, "/admin/foto", {"csrf": csrf, "id": "2", "act": "url", "photo_url": "https://192.168.1.1/x"})
            self.assertIn("no es pública", t)
            self.assertEqual(c.req("GET", "/foto/2")[0], 404)
        finally:
            srv.shutdown()
            app.DATA_DIR, app.fetch_image = old


import json  # noqa: E402
from http.server import BaseHTTPRequestHandler  # noqa: E402
from urllib.parse import parse_qs  # noqa: E402

FAKE_USERS = {"boss": "pw-boss", "ana": "pw-ana", "otto": "pw-otto", "carlos": "pw-carlos", "off": "pw-off"}
FAKE_OTP = {"otto": "123456"}
FAKE_DISABLED = {"off"}
FAKE_LIST = []


class FakeDSM(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        p = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        if self.path == "/webapi/auth.cgi" and p.get("method") == "login":
            acc = p.get("account")
            if acc not in FAKE_USERS or FAKE_USERS[acc] != p.get("passwd"):
                return self.reply({"success": False, "error": {"code": 400}})
            if acc in FAKE_DISABLED:
                return self.reply({"success": False, "error": {"code": 401}})
            if acc in FAKE_OTP:
                if not p.get("otp_code"):
                    return self.reply({"success": False, "error": {"code": 403}})
                if p["otp_code"] != FAKE_OTP[acc]:
                    return self.reply({"success": False, "error": {"code": 404}})
            return self.reply({"success": True, "data": {"sid": "sid-" + acc}})
        if self.path == "/webapi/auth.cgi":
            return self.reply({"success": True})
        if self.path == "/webapi/entry.cgi" and p.get("method") == "list":
            if p.get("_sid") != "sid-boss":
                return self.reply({"success": False, "error": {"code": 105}})
            return self.reply({"success": True, "data": {"users": FAKE_LIST, "total": len(FAKE_LIST)}})
        self.reply({"success": False, "error": {"code": 103}})


class DsmModeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsm = ThreadingHTTPServer(("127.0.0.1", 0), FakeDSM)
        threading.Thread(target=cls.dsm.serve_forever, daemon=True).start()
        cls.old = (app.AUTH_MODE, app.DSM_URL, app.ADMIN_USERS, app.DATA_DIR)
        app.DATA_DIR = tempfile.mkdtemp()
        app.AUTH_MODE, app.DSM_URL, app.ADMIN_USERS = "dsm", "http://127.0.0.1:%d" % cls.dsm.server_address[1], ["boss"]
        app.init_data()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.dsm.shutdown()
        app.AUTH_MODE, app.DSM_URL, app.ADMIN_USERS, app.DATA_DIR = cls.old

    def login(self, user, pw, otp=None):
        c = Client(self.port)
        data = {"username": user, "password": pw}
        if otp:
            data["otp"] = otp
        return c, c.req("POST", "/entrar", data)

    def test_1_login_y_roles(self):
        c, (s, _, _) = self.login("ana", "pw-ana")
        self.assertEqual(s, 303)
        self.assertIn("No tienes equipos", c.req("GET", "/")[1])  # invitado sin equipos
        self.assertEqual(c.req("GET", "/admin/usuarios")[0], 403)
        b, (s, _, _) = self.login("boss", "pw-boss")
        self.assertEqual(s, 303)
        self.assertIn("Riego", b.req("GET", "/")[1])  # admin por ADMIN_USERS
        self.assertEqual(app.db().execute("SELECT role FROM users WHERE dsm_user='boss'").fetchone()[0], "admin")

    def test_2_errores_de_dsm(self):
        self.assertEqual(self.login("ana", "mala")[1][0], 401)
        s, t, _ = self.login("off", "pw-off")[1]
        self.assertEqual(s, 401)
        self.assertIn("deshabilitada", t)
        self.assertEqual(self.login("no;existe", "x")[1][0], 401)  # nombre con caracteres no válidos

    def test_3_dos_pasos(self):
        c, (s, t, _) = self.login("otto", "pw-otto")
        self.assertEqual(s, 200)
        self.assertIn("verificación", t)
        self.assertEqual(self.login("otto", "pw-otto", "000000")[1][0], 401)
        self.assertEqual(self.login("otto", "pw-otto", "123456")[1][0], 303)

    def test_4_sincronizacion(self):
        FAKE_LIST[:] = [
            {"name": "boss", "email": "boss@x.mx", "description": "Jefe", "expired": "normal"},
            {"name": "ana", "email": "ana@x.mx", "description": "Ana", "expired": "normal"},
            {"name": "carlos", "email": "carlos@x.mx", "description": "Carlos", "expired": "normal"},
            {"name": "off", "email": "", "description": "Baja", "expired": "now"},
        ]
        b, _ = self.login("boss", "pw-boss")
        page_ = b.req("GET", "/admin/usuarios")[1]
        self.assertIn("Sincronizar con el DSM", page_)
        self.assertNotIn("Crear usuario", page_)
        csrf = b.csrf("/admin/usuarios")
        s, t, _ = b.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "sync"})
        self.assertIn("Sincronizado: 4 usuarios", t)
        q = lambda u: app.db().execute("SELECT status, role FROM users WHERE dsm_user=?", (u,)).fetchone()
        self.assertEqual(tuple(q("carlos")), ("activo", "usuario"))  # activo en el DSM -> usuario
        self.assertEqual(tuple(q("off")), ("bloqueado", "invitado"))  # deshabilitado en el DSM -> invitado
        # ana desaparece del DSM -> se bloquea y su sesión deja de valer
        a, _ = self.login("ana", "pw-ana")
        FAKE_LIST[:] = [u for u in FAKE_LIST if u["name"] != "ana"]
        csrf = b.csrf("/admin/usuarios")
        s, t, _ = b.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "sync"})
        self.assertEqual(q("ana")[0], "bloqueado")
        self.assertEqual(a.req("GET", "/")[0], 303)  # sesión caducada -> a /entrar

    def test_4b_rol_manual_se_respeta(self):
        b, _ = self.login("boss", "pw-boss")
        csrf = b.csrf("/admin/usuarios")
        uid = app.db().execute("SELECT id FROM users WHERE dsm_user='carlos'").fetchone()[0]
        b.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "rol", "id": uid, "role": "invitado"})
        b.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "sync"})
        self.assertEqual(app.db().execute("SELECT role FROM users WHERE dsm_user='carlos'").fetchone()[0], "invitado")

    def test_4c_sync_automatica_al_entrar_un_admin(self):
        FAKE_LIST[:] = [
            {"name": "boss", "email": "", "description": "Jefe", "expired": "normal"},
            {"name": "nuevo1", "email": "n1@x.mx", "description": "Nuevo 1", "expired": "normal"},
            {"name": "baja1", "email": "", "description": "Baja 1", "expired": "now"},
        ]
        self.login("boss", "pw-boss")
        import time as _t
        for _ in range(30):
            if app.db().execute("SELECT 1 FROM users WHERE dsm_user='baja1'").fetchone():
                break
            _t.sleep(0.1)
        q = lambda u: tuple(app.db().execute("SELECT status, role FROM users WHERE dsm_user=?", (u,)).fetchone())
        self.assertEqual(q("nuevo1"), ("activo", "usuario"))
        self.assertEqual(q("baja1"), ("bloqueado", "invitado"))

    def test_4d_lista_vacia_no_bloquea_a_nadie(self):
        FAKE_LIST[:] = [{"name": "boss", "email": "", "description": "Jefe", "expired": "normal"}]
        b, _ = self.login("boss", "pw-boss")
        import time as _t
        _t.sleep(0.5)
        csrf = b.csrf("/admin/usuarios")
        FAKE_LIST[:] = []
        b.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "sync"})
        n = app.db().execute("SELECT COUNT(*) FROM users WHERE status='activo' AND dsm_user IS NOT NULL").fetchone()[0]
        self.assertGreaterEqual(n, 1)  # nadie fue bloqueado por una lista vacía
        FAKE_LIST[:] = [{"name": "boss", "email": "", "description": "Jefe", "expired": "normal"}]
        b.req("POST", "/admin/usuarios", {"csrf": csrf, "act": "sync"})  # solo boss en la lista: boss es admin y se salva
        self.assertEqual(app.db().execute("SELECT status FROM users WHERE dsm_user='boss'").fetchone()[0], "activo")

    def test_5_sync_sin_permiso(self):
        FAKE_USERS["dana"] = "pw-dana"
        c, _ = self.login("dana", "pw-dana")
        # dana no es admin del portal: no llega a la pantalla
        self.assertEqual(c.req("GET", "/admin/usuarios")[0], 403)

    def test_6_sin_setup_ni_registro(self):
        c = Client(self.port)
        self.assertEqual(c.req("GET", "/setup")[0], 303)
        self.assertEqual(c.req("GET", "/registro")[0], 303)  # sin sesión -> /entrar


if __name__ == "__main__":
    unittest.main()
