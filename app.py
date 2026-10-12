#!/usr/bin/env python3
"""Portal Magnolia: registro de usuarios y de equipos de la red de Magnolia.

Solo usa la biblioteca estándar de Python (sin pip). Los datos viven en DATA_DIR
(portal.db, secret.key, setup_code.txt); esa carpeta es la que se monta como volumen
en Docker. Dos modos de acceso (AUTH_MODE):
  local       usuarios y contraseñas propios (PBKDF2), registro con aprobación.
  dsm         las cuentas son las del Synology (DSM): el portal valida usuario y
              contraseña contra su API y sincroniza la lista de usuarios.
  cloudflare  la identidad llega en la cabecera de Cloudflare Access; el portal solo
              asigna rol y equipos. Es la migración prevista.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

DATA_DIR = os.environ.get("DATA_DIR", "/data")
PORT = int(os.environ.get("PORT", "8088"))
AUTH_MODE = os.environ.get("AUTH_MODE", "local")
SESSION_TTL = 8 * 3600
MAX_FAILS = 5
LOCK_SECONDS = 900
MIN_PASSWORD = 10
ROLES = ("admin", "usuario", "invitado")
STATUSES = ("pendiente", "activo", "bloqueado")
MAX_BODY = 20000
MAX_PHOTO = 2 * 1024 * 1024  # bytes
SYNC_EVERY = int(os.environ.get("SYNC_EVERY", "3600"))  # segundos; 0 = sin sincronización periódica
DSM_URL = os.environ.get("DSM_URL", "http://127.0.0.1:5000")
ADMIN_USERS = [u.strip().lower() for u in os.environ.get("ADMIN_USERS", "").split(",") if u.strip()]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'invitado',
  status TEXT NOT NULL DEFAULT 'pendiente', must_change INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, last_login INTEGER);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '', roles TEXT NOT NULL DEFAULT 'admin,usuario',
  enabled INTEGER NOT NULL DEFAULT 1, sort INTEGER NOT NULL DEFAULT 100);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '');
"""

SEED_DEVICES = (
    ("Riego (RainMachine)", "Control de riego de Magnolia", "https://riego.motica.mx/ui/", "admin,usuario", 1, 10),
    ("Synology (DSM)", "Almacenamiento y Docker de Magnolia", "https://synology.motica.mx", "admin", 1, 20),
    ("Administración de medidores", "Por configurar: falta la dirección del equipo", "", "admin", 0, 30),
)

_fails = {}
_sids = {}  # id de usuario -> (sid del DSM, vencimiento); solo en memoria


# ---------- utilidades ----------
def db():
    conn = sqlite3.connect(os.path.join(DATA_DIR, "portal.db"), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def init_data():
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        if "dsm_user" not in [r[1] for r in conn.execute("PRAGMA table_info(users)")]:
            conn.execute("ALTER TABLE users ADD COLUMN dsm_user TEXT")
        if "role_set" not in [r[1] for r in conn.execute("PRAGMA table_info(users)")]:
            conn.execute("ALTER TABLE users ADD COLUMN role_set INTEGER NOT NULL DEFAULT 0")
        if "url_local" not in [r[1] for r in conn.execute("PRAGMA table_info(devices)")]:
            conn.execute("ALTER TABLE devices ADD COLUMN url_local TEXT NOT NULL DEFAULT ''")
        if "photo" not in [r[1] for r in conn.execute("PRAGMA table_info(devices)")]:
            conn.execute("ALTER TABLE devices ADD COLUMN photo BLOB")
            conn.execute("ALTER TABLE devices ADD COLUMN photo_type TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_dsm ON users(dsm_user)")
        if conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO devices(name,description,url,roles,enabled,sort) VALUES(?,?,?,?,?,?)",
                SEED_DEVICES)
    key = os.path.join(DATA_DIR, "secret.key")
    if not os.path.exists(key):
        fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    code = os.path.join(DATA_DIR, "setup_code.txt")
    if AUTH_MODE == "local" and no_users() and not os.path.exists(code):
        fd = os.open(code, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(4))


def secret():
    with open(os.path.join(DATA_DIR, "secret.key")) as f:
        return f.read().strip().encode()


def no_users():
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


PBKDF2_ITER = 600000
DUMMY_HASH = "pbkdf2$600000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def hash_pw(password):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER, dklen=32)
    return "pbkdf2$%d$%s$%s" % (PBKDF2_ITER, base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def check_pw(password, stored):
    try:
        kind, iters, salt, h = stored.split("$")
        if kind != "pbkdf2":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iters), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def sign(text):
    return hmac.new(secret(), text.encode(), hashlib.sha256).hexdigest()


def audit(actor, action, detail="", ip=""):
    with db() as conn:
        conn.execute("INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)",
                     (int(time.time()), actor, action, detail[:300], ip))


def locked(key):
    n, until = _fails.get(key, (0, 0))
    return until > time.time()


def register_fail(key):
    n, until = _fails.get(key, (0, 0))
    n += 1
    _fails[key] = (n, time.time() + LOCK_SECONDS if n >= MAX_FAILS else 0)


def clear_fails(key):
    _fails.pop(key, None)


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"


def valid_email(s):
    return 3 <= len(s) <= 120 and "@" in s and " " not in s and s.count("@") == 1


def safe_url(u):
    return u == "" or u.startswith("http://") or u.startswith("https://")


# ---------- DSM ----------
USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
DSM_CTX = ssl.create_default_context()
DSM_CTX.check_hostname = False  # el DSM usa un certificado propio y se le habla en local
DSM_CTX.verify_mode = ssl.CERT_NONE


def dsm_call(path, params):
    req = urllib.request.Request(DSM_URL.rstrip("/") + path, data=urlencode(params).encode())
    with urllib.request.urlopen(req, timeout=10, context=DSM_CTX) as r:
        return json.loads(r.read().decode())


def dsm_login(username, password, otp=""):
    """Devuelve (sid, "") si entra, o (None, código de error del DSM)."""
    params = {"api": "SYNO.API.Auth", "version": "3", "method": "login", "account": username,
              "passwd": password, "session": "PortalMagnolia", "format": "sid"}
    if otp:
        params["otp_code"] = otp
    try:
        r = dsm_call("/webapi/auth.cgi", params)
    except Exception as exc:
        sys.stderr.write("DSM no responde: %r\n" % (exc,))
        return None, "sin_respuesta"
    if r.get("success"):
        return r["data"]["sid"], ""
    return None, str(r.get("error", {}).get("code", ""))


def dsm_logout(sid):
    try:
        dsm_call("/webapi/auth.cgi", {"api": "SYNO.API.Auth", "version": "1", "method": "logout",
                                      "session": "PortalMagnolia", "_sid": sid})
    except Exception:
        pass


def dsm_list_users(sid):
    r = dsm_call("/webapi/entry.cgi", {"api": "SYNO.Core.User", "version": "1", "method": "list",
                                       "type": "local", "offset": "0", "limit": "-1",
                                       "additional": '["email","description","expired"]', "_sid": sid})
    if not r.get("success"):
        raise PermissionError(str(r.get("error", {}).get("code", "")))
    return r["data"].get("users", [])



def do_sync(sid, actor, ip):
    """Trae los usuarios del DSM con la sesión `sid`. Devuelve (nota, error).

    Regla por defecto: activo en el DSM -> rol `usuario`; deshabilitado -> `invitado` y bloqueado.
    Un rol cambiado a mano (role_set=1) no se vuelve a tocar."""
    try:
        users = dsm_list_users(sid)
    except PermissionError:
        return "", "Tu cuenta del DSM no tiene permiso para listar usuarios."
    except Exception as exc:
        sys.stderr.write("sync DSM: %r\n" % (exc,))
        return "", "No se pudo hablar con el DSM."
    now = int(time.time())
    seen, nuevos, bloqueados, roles, activos, deshab = set(), 0, 0, 0, 0, 0
    with db() as conn:
        for u in users:
            name = (u.get("name") or "").strip()
            if not USER_RE.match(name):
                continue
            seen.add(name)
            disabled = str(u.get("expired", "normal")).lower() == "now"
            activos, deshab = activos + (not disabled), deshab + disabled
            want = "invitado" if disabled else "usuario"
            label = ((u.get("description") or "").strip() or name)[:80]
            mail = (u.get("email") or "").strip().lower()
            row = conn.execute("SELECT * FROM users WHERE dsm_user=?", (name,)).fetchone()
            if row is None:
                role = "admin" if name.lower() in ADMIN_USERS else want
                state = "bloqueado" if disabled else "activo"
                try:
                    conn.execute("INSERT INTO users(email,name,pw,role,status,created_at,dsm_user) VALUES(?,?,?,?,?,?,?)",
                                 (mail if valid_email(mail) else name + "@dsm", label, "x", role, state, now, name))
                except sqlite3.IntegrityError:  # correo repetido: usar uno propio
                    conn.execute("INSERT INTO users(email,name,pw,role,status,created_at,dsm_user) VALUES(?,?,?,?,?,?,?)",
                                 (name + "@dsm", label, "x", role, state, now, name))
                nuevos += 1
                bloqueados += 1 if disabled else 0
            else:
                conn.execute("UPDATE users SET name=? WHERE id=?", (label, row["id"]))
                if disabled and row["status"] == "activo":
                    conn.execute("UPDATE users SET status='bloqueado' WHERE id=?", (row["id"],))
                    bloqueados += 1
                if not row["role_set"] and row["role"] not in ("admin", want):
                    conn.execute("UPDATE users SET role=? WHERE id=?", (want, row["id"]))
                    roles += 1
        # Salvaguardas: una lista vacía no bloquea a nadie y los administradores nunca se bloquean por ausentes.
        for row in (conn.execute("SELECT * FROM users WHERE dsm_user IS NOT NULL AND status='activo'").fetchall() if seen else []):
            if row["dsm_user"] not in seen and row["dsm_user"].lower() not in ADMIN_USERS:
                conn.execute("UPDATE users SET status='bloqueado' WHERE id=?", (row["id"],))
                bloqueados += 1
    audit(actor, "sync_dsm", "%d usuarios, %d nuevos, %d bloqueados, %d roles" % (len(seen), nuevos, bloqueados, roles), ip)
    return ("Sincronizado: %d usuarios en el DSM (%d activos, %d deshabilitados). Nuevos: %d. Bloqueados ahora: %d. "
            "Roles ajustados por defecto: %d. Los activos reciben el rol «usuario» y los deshabilitados «invitado»; "
            "un rol cambiado a mano no se toca." % (len(seen), activos, deshab, nuevos, bloqueados, roles)), ""


def periodic_sync():
    """Cada SYNC_EVERY segundos sincroniza con la sesión de un administrador que siga abierta."""
    while True:
        time.sleep(SYNC_EVERY)
        now = time.time()
        for uid, (sid, exp) in list(_sids.items()):
            if exp < now:
                continue
            with db() as conn:
                adm = conn.execute("SELECT * FROM users WHERE id=? AND role='admin' AND status='activo'", (uid,)).fetchone()
            if adm:
                do_sync(sid, "auto", "")
                break


# ---------- fotos ----------
def sniff_image(b):
    """Tipo de imagen por sus primeros bytes. No se aceptan SVG (pueden llevar código)."""
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if b[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "image/webp"
    return ""


def parse_multipart(body, ctype):
    m = re.search(r'boundary="?([^";]+)"?', ctype or "")
    if not m:
        return {}, None
    delim = b"--" + m.group(1).encode()
    fields, upload = {}, None
    for part in body.split(delim)[1:]:
        if part.startswith(b"--"):
            break
        head, _, data = part.lstrip(b"\r\n").partition(b"\r\n\r\n")
        data = data[:-2] if data.endswith(b"\r\n") else data
        hdr = head.decode("latin-1")
        name = re.search(r'name="([^"]*)"', hdr)
        if not name:
            continue
        if re.search(r'filename="([^"]*)"', hdr):
            upload = (name.group(1), data)
        else:
            fields[name.group(1)] = data.decode("utf-8", "replace").strip()
    return fields, upload


# ---------- HTML ----------
e = html.escape

CSS = """
:root{--bg:#f6f7f4;--ink:#17201c;--mut:#5d6b64;--card:#fff;--line:#d9dfda;--acc:#1f7a4d;--bad:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#101b17;--ink:#eaf1ec;--mut:#9fb1a7;--card:#17251f;--line:#2a3b33;--acc:#5fd29a;--bad:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}
header{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
nav a{margin-right:14px;color:var(--ink)}main{max-width:960px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:0 0 12px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(240px,1fr))}
.foto{width:100%;height:150px;object-fit:cover;border-radius:8px;margin-bottom:8px;display:block}.foto.mini{width:160px;height:100px}
a.btn.alt{background:transparent;color:var(--ink);border:1px solid var(--line)}
a.btn,button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block}
button.alt{background:transparent;color:var(--ink);border:1px solid var(--line)}
input,select{font:inherit;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);max-width:100%}
label{display:block;margin:8px 0 2px;color:var(--mut);font-size:.9rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}
.tablewrap{overflow-x:auto}.msg{padding:10px;border-radius:8px;border:1px solid var(--acc);margin-bottom:12px}
.err{border-color:var(--bad);color:var(--bad)}.mut{color:var(--mut)}form.inline{display:inline}
"""


def page(title, body, user=None, csrf=""):
    nav = ""
    if user:
        links = '<a href="/">Equipos</a>'
        if user["role"] == "admin":
            links += '<a href="/admin/usuarios">Usuarios</a><a href="/admin/equipos">Gestionar equipos</a><a href="/admin/registro">Registro</a>'
        links += '<a href="/cuenta">Mi cuenta</a>'
        out = ""
        if AUTH_MODE in ("local", "dsm"):
            out = '<form class="inline" method="post" action="/salir"><input type="hidden" name="csrf" value="%s"><button class="alt">Salir</button></form>' % e(csrf)
        nav = "<nav>%s</nav><span class='mut'>%s (%s) %s</span>" % (links, e(user["name"]), e(user["role"]), out)
    return ("<!doctype html><html lang='es'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>%s · Portal Magnolia</title><style>%s</style></head><body>"
            "<header><strong>Portal Magnolia</strong>%s</header><main>%s</main></body></html>"
            % (e(title), CSS, nav, body)).encode()


def msg_html(text, error=False):
    return '<div class="msg%s">%s</div>' % (" err" if error else "", text) if text else ""


def form_login(error=""):
    reg = '<p class="mut">¿No tienes cuenta? <a href="/registro">Solicita acceso</a></p>'
    return page("Entrar", msg_html(e(error), True) + """
<div class="card"><h2>Entrar</h2><form method="post" action="/entrar">
<label>Correo</label><input name="email" type="email" required autocomplete="username">
<label>Contraseña</label><input name="password" type="password" required autocomplete="current-password">
<p><button>Entrar</button></p></form>%s</div>""" % reg)


def form_login_dsm(error="", otp=False, username=""):
    extra = ('<label>Código de verificación en dos pasos</label>'
             '<input name="otp" inputmode="numeric" autocomplete="one-time-code" autofocus>') if otp else ""
    return page("Entrar", msg_html(e(error), True) + """
<div class="card"><h2>Entrar</h2><p class="mut">Usa tu usuario y contraseña del Synology.</p>
<form method="post" action="/entrar">
<label>Usuario</label><input name="username" value="%s" required autocomplete="username">
<label>Contraseña</label><input name="password" type="password" required autocomplete="current-password">%s
<p><button>Entrar</button></p></form></div>""" % (e(username, quote=True), extra))


# ---------- servidor ----------
class Handler(BaseHTTPRequestHandler):
    server_version = "PortalMagnolia"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # -- infraestructura --
    def ip(self):
        return (self.headers.get("CF-Connecting-IP") or
                (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or
                self.client_address[0])

    def secure(self):
        return self.headers.get("X-Forwarded-Proto", "") == "https" or os.environ.get("COOKIE_SECURE") == "1"

    def send(self, status, body, ctype="text/html; charset=utf-8", cookie=None, location=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        if cookie is not None:
            flags = "; Path=/; HttpOnly; SameSite=Lax" + ("; Secure" if self.secure() else "")
            self.send_header("Set-Cookie", "pm_session=%s%s%s" % (cookie, flags, "; Max-Age=0" if cookie == "" else "; Max-Age=%d" % SESSION_TTL))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, where, cookie=None):
        self.send(303, b"", location=where, cookie=cookie)

    def cookie_value(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pm_session":
                return v
        return ""

    def session_token(self, uid):
        payload = "%d:%d" % (uid, int(time.time()) + SESSION_TTL)
        return base64.urlsafe_b64encode(payload.encode()).decode() + "." + sign(payload)

    def identity(self):
        """Devuelve (usuario, csrf). El usuario solo se acepta si está activo."""
        if AUTH_MODE == "cloudflare":
            mail = (self.headers.get("Cf-Access-Authenticated-User-Email") or "").strip().lower()
            if not valid_email(mail):
                return None, ""
            with db() as conn:
                u = conn.execute("SELECT * FROM users WHERE email=?", (mail,)).fetchone()
                if u is None:
                    conn.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES(?,?,?,?,?,?)",
                                 (mail, mail.split("@")[0], "x", "invitado", "pendiente", int(time.time())))
                    u = conn.execute("SELECT * FROM users WHERE email=?", (mail,)).fetchone()
            return (u if u["status"] == "activo" else None), sign("csrf:" + mail)
        raw = self.cookie_value()
        try:
            b64, sig = raw.split(".")
            payload = base64.urlsafe_b64decode(b64.encode()).decode()
            if not hmac.compare_digest(sig, sign(payload)):
                return None, ""
            uid, exp = payload.split(":")
            if int(exp) < time.time():
                return None, ""
            with db() as conn:
                u = conn.execute("SELECT * FROM users WHERE id=?", (int(uid),)).fetchone()
            if u is None or u["status"] != "activo":
                return None, ""
            return u, sign("csrf:" + payload)
        except Exception:
            return None, ""

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return None
        data = parse_qs(self.rfile.read(n).decode(errors="replace"), keep_blank_values=True)
        return {k: v[0].strip() for k, v in data.items()}

    def multipart(self):
        """Devuelve (campos, archivo) o (None, None) si el cuerpo excede el límite."""
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_PHOTO + 8192:
            return None, None
        return parse_multipart(self.rfile.read(n), self.headers.get("Content-Type", ""))

    def origin_ok(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return urlparse(origin).netloc == self.headers.get("Host", "")

    # -- despacho --
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        path = urlparse(self.path).path
        try:
            if path == "/salud":
                return self.send(200, b"ok", "text/plain")
            if method == "POST" and not self.origin_ok():
                return self.send(403, page("Prohibido", msg_html("Origen no permitido.", True)))
            if path == "/setup":
                return self.page_setup(method)
            if no_users() and AUTH_MODE == "local":
                return self.redirect("/setup")
            if path == "/entrar" and AUTH_MODE in ("local", "dsm"):
                return self.login(method)
            if path == "/registro" and AUTH_MODE == "local":
                return self.signup(method)
            user, csrf = self.identity()
            if user is None:
                if AUTH_MODE == "cloudflare":
                    return self.send(403, page("Acceso pendiente", msg_html(
                        "Tu correo ya está registrado, pero un administrador debe activarlo.")))
                return self.redirect("/entrar")
            if method == "POST":
                if path == "/admin/foto":
                    data, upload = self.multipart()
                    if data is not None:
                        data["_file"] = upload
                else:
                    data = self.form()
                if data is None or not hmac.compare_digest(data.get("csrf", ""), csrf):
                    return self.send(403, page("Prohibido", msg_html("Formulario no válido, recarga la página.", True), user, csrf))
            else:
                data = {}
            if user["must_change"] and path not in ("/cuenta", "/salir"):
                return self.redirect("/cuenta")
            if path.startswith("/foto/"):
                return self.serve_photo(path, user, csrf)
            routes = {"/admin/foto": self.admin_photo, "/": self.home, "/salir": self.logout, "/cuenta": self.account,
                      "/admin/usuarios": self.admin_users, "/admin/equipos": self.admin_devices,
                      "/admin/registro": self.admin_audit}
            fn = routes.get(path)
            if fn is None:
                return self.send(404, page("No encontrado", msg_html("No existe esa página.", True), user, csrf))
            if path.startswith("/admin") and user["role"] != "admin":
                return self.send(403, page("Prohibido", msg_html("Solo administradores.", True), user, csrf))
            return fn(method, user, csrf, data)
        except Exception as exc:  # no mostrar detalles al usuario
            sys.stderr.write("ERROR %r\n" % (exc,))
            self.send(500, page("Error", msg_html("Error interno.", True)))

    # -- páginas --
    def page_setup(self, method):
        if AUTH_MODE != "local" or not no_users():
            return self.redirect("/")
        with open(os.path.join(DATA_DIR, "setup_code.txt")) as f:
            code = f.read().strip()
        err = ""
        if method == "POST":
            d = self.form() or {}
            key = "setup:" + self.ip()
            if locked(key):
                err = "Demasiados intentos, espera unos minutos."
            elif not hmac.compare_digest(d.get("code", ""), code):
                register_fail(key)
                err = "Código de instalación incorrecto."
            elif not valid_email(d.get("email", "").lower()) or len(d.get("password", "")) < MIN_PASSWORD or not d.get("name"):
                err = "Revisa los datos (contraseña de al menos %d caracteres)." % MIN_PASSWORD
            else:
                with db() as conn:
                    conn.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES(?,?,?,?,?,?)",
                                 (d["email"].lower(), d["name"][:80], hash_pw(d["password"]), "admin", "activo", int(time.time())))
                audit(d["email"].lower(), "instalacion", "primer administrador", self.ip())
                os.remove(os.path.join(DATA_DIR, "setup_code.txt"))
                return self.redirect("/entrar")
        return self.send(200, page("Instalación", msg_html(e(err), True) + """
<div class="card"><h2>Primera instalación</h2>
<p class="mut">El código de instalación está en el registro (log) del contenedor.</p>
<form method="post" action="/setup">
<label>Código de instalación</label><input name="code" required autocomplete="off">
<label>Nombre</label><input name="name" required>
<label>Correo</label><input name="email" type="email" required>
<label>Contraseña (mínimo %d)</label><input name="password" type="password" required minlength="%d" autocomplete="new-password">
<p><button>Crear administrador</button></p></form></div>""" % (MIN_PASSWORD, MIN_PASSWORD)))

    def login(self, method):
        if AUTH_MODE == "dsm":
            return self.login_dsm(method)
        if method == "GET":
            return self.send(200, form_login())
        d = self.form() or {}
        mail = d.get("email", "").lower()
        key = "login:%s:%s" % (self.ip(), mail)
        if locked(key):
            return self.send(429, form_login("Demasiados intentos. Espera 15 minutos."))
        with db() as conn:
            u = conn.execute("SELECT * FROM users WHERE email=?", (mail,)).fetchone()
        ok = u is not None and check_pw(d.get("password", ""), u["pw"])
        if not ok:
            if u is None:
                check_pw(d.get("password", ""), DUMMY_HASH)
            register_fail(key)
            audit(mail or "?", "login_fallido", "", self.ip())
            return self.send(401, form_login("Correo o contraseña incorrectos."))
        if u["status"] != "activo":
            audit(mail, "login_sin_activar", u["status"], self.ip())
            txt = "Tu cuenta está pendiente de aprobación." if u["status"] == "pendiente" else "Tu cuenta está bloqueada."
            return self.send(403, form_login(txt))
        clear_fails(key)
        with db() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (int(time.time()), u["id"]))
        audit(mail, "login", "", self.ip())
        return self.redirect("/", cookie=self.session_token(u["id"]))

    def login_dsm(self, method):
        if method == "GET":
            return self.send(200, form_login_dsm())
        d = self.form() or {}
        name = d.get("username", "")
        key = "login:%s:%s" % (self.ip(), name.lower())
        if locked(key):
            return self.send(429, form_login_dsm("Demasiados intentos. Espera 15 minutos.", username=name))
        if not USER_RE.match(name) or not d.get("password"):
            register_fail(key)
            return self.send(401, form_login_dsm("Usuario o contraseña incorrectos.", username=name))
        sid, code = dsm_login(name, d["password"], d.get("otp", ""))
        if sid is None:
            if code in ("403", "404", "406") and not d.get("otp"):
                return self.send(200, form_login_dsm("Escribe el código de verificación en dos pasos.", True, name))
            if code == "sin_respuesta":
                return self.send(503, form_login_dsm("No se pudo hablar con el Synology. Intenta de nuevo.", username=name))
            register_fail(key)
            audit(name, "login_fallido", "dsm:%s" % code, self.ip())
            msg = {"401": "Tu cuenta del Synology está deshabilitada.", "404": "Código de verificación incorrecto."}.get(
                code, "Usuario o contraseña incorrectos.")
            return self.send(401, form_login_dsm(msg, code == "404", name))
        with db() as conn:
            u = conn.execute("SELECT * FROM users WHERE dsm_user=?", (name,)).fetchone()
            if u is None:
                role = "admin" if name.lower() in ADMIN_USERS else "invitado"
                conn.execute("INSERT INTO users(email,name,pw,role,status,created_at,dsm_user) VALUES(?,?,?,?,?,?,?)",
                             (name + "@dsm", name, "x", role, "activo", int(time.time()), name))
                u = conn.execute("SELECT * FROM users WHERE dsm_user=?", (name,)).fetchone()
            elif name.lower() in ADMIN_USERS and u["role"] != "admin":
                conn.execute("UPDATE users SET role='admin' WHERE id=?", (u["id"],))
                u = conn.execute("SELECT * FROM users WHERE dsm_user=?", (name,)).fetchone()
        if u["status"] != "activo":
            dsm_logout(sid)
            audit(name, "login_bloqueado", u["status"], self.ip())
            return self.send(403, form_login_dsm("Tu acceso al portal está bloqueado. Habla con un administrador.", username=name))
        clear_fails(key)
        _sids[u["id"]] = (sid, time.time() + SESSION_TTL)
        with db() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (int(time.time()), u["id"]))
        audit(name, "login", "dsm", self.ip())
        if u["role"] == "admin":  # sincroniza solo, sin esperar al botón
            threading.Thread(target=do_sync, args=(sid, name, self.ip()), daemon=True).start()
        return self.redirect("/", cookie=self.session_token(u["id"]))

    def sync_dsm(self, admin):
        entry = _sids.get(admin["id"])
        if not entry or entry[1] < time.time():
            return "", "Vuelve a iniciar sesión para sincronizar: se necesita tu sesión del DSM."
        return do_sync(entry[0], admin["dsm_user"] or admin["email"], self.ip())

    def signup(self, method):
        err = ok = ""
        if method == "POST":
            d = self.form() or {}
            mail = d.get("email", "").lower()
            key = "signup:" + self.ip()
            if locked(key):
                err = "Demasiadas solicitudes, intenta más tarde."
            elif not valid_email(mail) or not d.get("name") or len(d.get("password", "")) < MIN_PASSWORD:
                err = "Revisa los datos (contraseña de al menos %d caracteres)." % MIN_PASSWORD
            else:
                register_fail(key)
                try:
                    with db() as conn:
                        conn.execute("INSERT INTO users(email,name,pw,role,status,created_at) VALUES(?,?,?,?,?,?)",
                                     (mail, d["name"][:80], hash_pw(d["password"]), "invitado", "pendiente", int(time.time())))
                    audit(mail, "registro", "solicitud nueva", self.ip())
                except sqlite3.IntegrityError:
                    pass  # no revelar si el correo ya existe
                ok = "Solicitud enviada. Un administrador debe aprobarla antes de que puedas entrar."
        return self.send(200, page("Solicitar acceso", msg_html(e(err), True) + msg_html(e(ok)) + """
<div class="card"><h2>Solicitar acceso</h2><form method="post" action="/registro">
<label>Nombre</label><input name="name" required>
<label>Correo</label><input name="email" type="email" required>
<label>Contraseña (mínimo %d)</label><input name="password" type="password" required minlength="%d" autocomplete="new-password">
<p><button>Solicitar</button> <a href="/entrar">Volver</a></p></form></div>""" % (MIN_PASSWORD, MIN_PASSWORD)))

    def logout(self, method, user, csrf, data):
        audit(user["email"], "salida", "", self.ip())
        if AUTH_MODE == "dsm":
            entry = _sids.pop(user["id"], None)
            if entry:
                dsm_logout(entry[0])
        return self.redirect("/entrar", cookie="")

    def home(self, method, user, csrf, data):
        with db() as conn:
            rows = conn.execute("SELECT * FROM devices WHERE enabled=1 ORDER BY sort,name").fetchall()
        cards = ""
        for r in rows:
            if user["role"] not in r["roles"].split(",") or not (r["url"] or r["url_local"]):
                continue
            links = ""
            if r["url_local"]:
                links += ('<a class="btn" href="%s" target="_blank" rel="noopener noreferrer">Abrir local</a> '
                          % e(r["url_local"], quote=True))
            if r["url"]:
                links += ('<a class="btn%s" href="%s" target="_blank" rel="noopener noreferrer">Abrir remoto</a>'
                          % (" alt" if r["url_local"] else "", e(r["url"], quote=True)))
            hint = ('<p class="mut">Local: solo en la red de Magnolia. Remoto: desde internet.</p>'
                    if r["url_local"] and r["url"] else "")
            img = '<img class="foto" src="/foto/%d" alt="" loading="lazy">' % r["id"] if r["photo"] else ""
            cards += ('<div class="card">%s<h3>%s</h3><p class="mut">%s</p>%s<p>%s</p></div>'
                      % (img, e(r["name"]), e(r["description"]), hint, links))
        body = '<h2>Equipos de Magnolia</h2>' + ('<div class="grid">%s</div>' % cards if cards else
                                                 '<p class="mut">No tienes equipos asignados todavía.</p>')
        return self.send(200, page("Equipos", body, user, csrf))

    def account(self, method, user, csrf, data):
        note = err = ""
        if method == "POST":
            if AUTH_MODE != "local":
                err = "En este modo la contraseña se maneja en Cloudflare."
            elif not check_pw(data.get("old", ""), user["pw"]):
                err = "La contraseña actual no coincide."
            elif len(data.get("new", "")) < MIN_PASSWORD or data.get("new") == data.get("old"):
                err = "La nueva contraseña debe tener al menos %d caracteres y ser distinta." % MIN_PASSWORD
            else:
                with db() as conn:
                    conn.execute("UPDATE users SET pw=?, must_change=0 WHERE id=?", (hash_pw(data["new"]), user["id"]))
                audit(user["email"], "cambio_password", "", self.ip())
                return self.redirect("/")
        forced = '<p class="mut">Debes cambiar tu contraseña para continuar.</p>' if user["must_change"] else ""
        body = msg_html(e(err), True) + forced + """<div class="card"><h2>Mi cuenta</h2>
<p>%s · %s</p><form method="post" action="/cuenta"><input type="hidden" name="csrf" value="%s">
<label>Contraseña actual</label><input name="old" type="password" required autocomplete="current-password">
<label>Nueva contraseña (mínimo %d)</label><input name="new" type="password" required minlength="%d" autocomplete="new-password">
<p><button>Cambiar contraseña</button></p></form></div>""" % (e(user["email"]), e(user["role"]), e(csrf), MIN_PASSWORD, MIN_PASSWORD)
        return self.send(200, page("Mi cuenta", body, user, csrf))

    def admin_users(self, method, user, csrf, data):
        note = err = ""
        if method == "POST":
            act, uid = data.get("act", ""), data.get("id", "")
            with db() as conn:
                target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid.isdigit() else None
                if act == "crear":
                    mail = data.get("email", "").lower()
                    role = data.get("role", "")
                    if not valid_email(mail) or not data.get("name") or role not in ROLES:
                        err = "Datos de usuario no válidos."
                    else:
                        temp = secrets.token_urlsafe(9)
                        try:
                            conn.execute("INSERT INTO users(email,name,pw,role,status,must_change,created_at) VALUES(?,?,?,?,?,?,?)",
                                         (mail, data["name"][:80], hash_pw(temp), role, "activo", 1, int(time.time())))
                            note = "Usuario creado. Contraseña temporal (se muestra una sola vez): <code>%s</code>" % e(temp)
                            audit(user["email"], "usuario_creado", "%s (%s)" % (mail, role), self.ip())
                        except sqlite3.IntegrityError:
                            err = "Ese correo ya existe."
                elif act == "sync" and AUTH_MODE == "dsm":
                    note, err = self.sync_dsm(user)
                elif target is None:
                    err = "Usuario no encontrado."
                elif target["id"] == user["id"] and act in ("bloquear", "rol"):
                    err = "No puedes bloquearte ni cambiarte el rol a ti mismo."
                elif act in ("aprobar", "activar"):
                    conn.execute("UPDATE users SET status='activo' WHERE id=?", (target["id"],))
                    audit(user["email"], "usuario_activado", target["email"], self.ip())
                elif act == "bloquear":
                    conn.execute("UPDATE users SET status='bloqueado' WHERE id=?", (target["id"],))
                    audit(user["email"], "usuario_bloqueado", target["email"], self.ip())
                elif act == "rol" and data.get("role") in ROLES:
                    conn.execute("UPDATE users SET role=?, role_set=1 WHERE id=?", (data["role"], target["id"]))
                    audit(user["email"], "rol_cambiado", "%s -> %s" % (target["email"], data["role"]), self.ip())
                elif act == "reset":
                    temp = secrets.token_urlsafe(9)
                    conn.execute("UPDATE users SET pw=?, must_change=1 WHERE id=?", (hash_pw(temp), target["id"]))
                    note = "Contraseña temporal de %s (se muestra una sola vez): <code>%s</code>" % (e(target["email"]), e(temp))
                    audit(user["email"], "password_reiniciada", target["email"], self.ip())
        with db() as conn:
            users = conn.execute("SELECT * FROM users ORDER BY CASE status WHEN 'pendiente' THEN 0 ELSE 1 END, email").fetchall()
        rows = ""
        for u in users:
            def btn(act, label, extra=""):
                return ('<form class="inline" method="post" action="/admin/usuarios"><input type="hidden" name="csrf" value="%s">'
                        '<input type="hidden" name="id" value="%d"><input type="hidden" name="act" value="%s">%s<button class="alt">%s</button></form> '
                        % (e(csrf), u["id"], act, extra, label))
            sel = "".join('<option%s>%s</option>' % (" selected" if r == u["role"] else "", r) for r in ROLES)
            acts = btn("rol", "Guardar rol", '<select name="role">%s</select>' % sel)
            acts += btn("aprobar", "Aprobar") if u["status"] == "pendiente" else ""
            acts += btn("activar", "Activar") if u["status"] == "bloqueado" else ""
            acts += btn("bloquear", "Bloquear") if u["status"] == "activo" else ""
            acts += btn("reset", "Reiniciar contraseña") if AUTH_MODE == "local" else ""
            rows += "<tr><td>%s<br><span class='mut'>%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                e(u["email"]), e(u["name"]), e(u["role"]), e(u["status"]), fmt_ts(u["last_login"]), acts)
        opts = "".join("<option>%s</option>" % r for r in ROLES)
        body = (msg_html(note) + msg_html(e(err), True) + '<h2>Usuarios</h2><div class="card tablewrap"><table>'
                '<tr><th>Usuario</th><th>Rol</th><th>Estado</th><th>Último acceso</th><th>Acciones</th></tr>%s</table></div>'
                '<div class="card"><h3>Crear usuario</h3><form method="post" action="/admin/usuarios">'
                '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="act" value="crear">'
                '<label>Nombre</label><input name="name" required><label>Correo</label><input name="email" type="email" required>'
                '<label>Rol</label><select name="role">%s</select><p><button>Crear</button></p></form></div>' % (rows, e(csrf), opts))
        if AUTH_MODE == "dsm":
            body = body.split('<div class="card"><h3>Crear usuario')[0] + (
                '<div class="card"><form method="post" action="/admin/usuarios"><input type="hidden" name="csrf" value="%s">'
                '<input type="hidden" name="act" value="sync"><button>Sincronizar con el DSM</button> '
                '<span class="mut">Trae usuarios nuevos y bloquea a los deshabilitados o ausentes.</span></form></div>' % e(csrf))
        return self.send(200, page("Usuarios", body, user, csrf))

    def admin_devices(self, method, user, csrf, data, err=""):
        if method == "POST":
            act = data.get("act", "")
            roles = ",".join(r for r in ROLES if data.get("r_" + r))
            with db() as conn:
                if act in ("crear", "guardar"):
                    if not data.get("name") or not safe_url(data.get("url", "")) or not safe_url(data.get("url_local", "")):
                        err = "Nombre obligatorio y las direcciones deben empezar con http:// o https://."
                    elif act == "crear":
                        conn.execute("INSERT INTO devices(name,description,url,url_local,roles,enabled,sort) VALUES(?,?,?,?,?,?,?)",
                                     (data["name"][:80], data.get("description", "")[:200], data.get("url", ""),
                                      data.get("url_local", ""), roles, 1 if data.get("enabled") else 0,
                                      int(data.get("sort", "100") or 100)))
                        audit(user["email"], "equipo_creado", data["name"], self.ip())
                    elif data.get("id", "").isdigit():
                        conn.execute("UPDATE devices SET name=?,description=?,url=?,url_local=?,roles=?,enabled=?,sort=? WHERE id=?",
                                     (data["name"][:80], data.get("description", "")[:200], data.get("url", ""),
                                      data.get("url_local", ""), roles, 1 if data.get("enabled") else 0,
                                      int(data.get("sort", "100") or 100), int(data["id"])))
                        audit(user["email"], "equipo_editado", data["name"], self.ip())
                elif act == "borrar" and data.get("id", "").isdigit():
                    conn.execute("DELETE FROM devices WHERE id=?", (int(data["id"]),))
                    audit(user["email"], "equipo_borrado", data["id"], self.ip())
        with db() as conn:
            devs = conn.execute("SELECT * FROM devices ORDER BY sort,name").fetchall()

        def fields(d):
            have = (d["roles"] if d else "admin,usuario").split(",")
            checks = "".join('<label><input type="checkbox" name="r_%s" value="1"%s> %s</label>' % (
                r, " checked" if r in have else "", r) for r in ROLES)
            g = (lambda k: e(str(d[k]), quote=True)) if d else (lambda k: "")
            return ('<label>Nombre</label><input name="name" value="%s" required>'
                    '<label>Descripción</label><input name="description" value="%s">'
                    '<label>Dirección local (IP de la red de Magnolia, http/https)</label><input name="url_local" value="%s">'
                    '<label>Dirección remota (desde internet, http/https)</label><input name="url" value="%s">'
                    '<label>Orden</label><input name="sort" value="%s" size="4">%s'
                    '<label><input type="checkbox" name="enabled" value="1"%s> Visible</label>'
                    % (g("name"), g("description"), g("url_local"), g("url"), g("sort") if d else "100", checks,
                       " checked" if (d is None or d["enabled"]) else ""))
        cards = ""
        for d in devs:
            cards += ('<div class="card"><form method="post" action="/admin/equipos"><input type="hidden" name="csrf" value="%s">'
                      '<input type="hidden" name="id" value="%d">%s<p><button name="act" value="guardar">Guardar</button> '
                      '<button class="alt" name="act" value="borrar" onclick="return confirm(\'¿Borrar?\')">Borrar</button></p></form>'
                      '<hr style="border:0;border-top:1px solid var(--line)">%s'
                      '<form method="post" action="/admin/foto" enctype="multipart/form-data">'
                      '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%d">'
                      '<label>Foto del equipo (PNG, JPG, GIF o WebP, máx. 2 MB)</label>'
                      '<input type="file" name="photo" accept="image/png,image/jpeg,image/gif,image/webp"> '
                      '<button name="act" value="subir">Subir foto</button> '
                      '<button class="alt" name="act" value="quitar">Quitar foto</button></form></div>'
                      % (e(csrf), d["id"], fields(d),
                         '<img class="foto mini" src="/foto/%d" alt="">' % d["id"] if d["photo"] else "",
                         e(csrf), d["id"]))
        body = (msg_html(e(err), True) + "<h2>Equipos</h2>" + cards +
                '<div class="card"><h3>Agregar equipo</h3><form method="post" action="/admin/equipos">'
                '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="act" value="crear">%s'
                '<p><button>Agregar</button></p></form></div>' % (e(csrf), fields(None)))
        return self.send(200, page("Equipos", body, user, csrf))

    def serve_photo(self, path, user, csrf):
        did = path[len("/foto/"):]
        r = None
        if did.isdigit():
            with db() as conn:
                r = conn.execute("SELECT roles, photo, photo_type FROM devices WHERE id=?", (int(did),)).fetchone()
        if r is None or not r["photo"] or (user["role"] != "admin" and user["role"] not in r["roles"].split(",")):
            return self.send(404, b"no encontrada", "text/plain")
        return self.send(200, bytes(r["photo"]), r["photo_type"] or "application/octet-stream")

    def admin_photo(self, method, user, csrf, data):
        if method != "POST":
            return self.redirect("/admin/equipos")
        did, err = data.get("id", ""), ""
        if not did.isdigit():
            err = "Equipo no válido."
        elif data.get("act") == "quitar":
            with db() as conn:
                conn.execute("UPDATE devices SET photo=NULL, photo_type='' WHERE id=?", (int(did),))
            audit(user["email"], "foto_quitada", did, self.ip())
        else:
            up = data.get("_file")
            if not up or not up[1]:
                err = "Elige una imagen."
            elif len(up[1]) > MAX_PHOTO:
                err = "La imagen pesa más de 2 MB."
            else:
                kind = sniff_image(up[1])
                if not kind:
                    err = "Solo se aceptan imágenes PNG, JPG, GIF o WebP."
                else:
                    with db() as conn:
                        conn.execute("UPDATE devices SET photo=?, photo_type=? WHERE id=?", (up[1], kind, int(did)))
                    audit(user["email"], "foto_subida", "equipo %s, %d bytes" % (did, len(up[1])), self.ip())
        if err:
            return self.admin_devices("GET", user, csrf, {}, err)
        return self.redirect("/admin/equipos")

    def admin_audit(self, method, user, csrf, data):
        with db() as conn:
            rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        trs = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            fmt_ts(r["ts"]), e(r["actor"]), e(r["action"]), e(r["detail"]), e(r["ip"])) for r in rows)
        body = ('<h2>Registro</h2><div class="card tablewrap"><table><tr><th>Fecha</th><th>Quién</th><th>Acción</th>'
                '<th>Detalle</th><th>IP</th></tr>%s</table></div>' % trs)
        return self.send(200, page("Registro", body, user, csrf))


def main():
    init_data()
    if AUTH_MODE == "dsm" and not ADMIN_USERS:
        print("AVISO: define ADMIN_USERS (usuarios del DSM que administran el portal)", flush=True)
    if no_users() and AUTH_MODE == "local":
        with open(os.path.join(DATA_DIR, "setup_code.txt")) as f:
            print("CODIGO DE INSTALACION: %s (abre /setup)" % f.read().strip(), flush=True)
    if AUTH_MODE == "dsm" and SYNC_EVERY > 0:
        threading.Thread(target=periodic_sync, daemon=True).start()
    print("Portal Magnolia en el puerto %d (modo %s)" % (PORT, AUTH_MODE), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
