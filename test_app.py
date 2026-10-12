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
