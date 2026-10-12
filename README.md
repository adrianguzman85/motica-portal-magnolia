# Portal Magnolia

Portal web para la red de Magnolia: registro de equipos (riego, Synology, medidores…), alta y aprobación de usuarios, roles y bitácora. Un solo archivo (`app.py`), solo biblioteca estándar de Python, datos en SQLite dentro de una carpeta que se monta como volumen en Docker.

## Qué incluye
- **Equipos:** cada uno con nombre, descripción, dirección y los roles que lo ven. Se administran desde el portal (Gestionar equipos).
- **Usuarios:** solicitud de acceso (`/registro`) con aprobación de un administrador, o alta directa con contraseña temporal. Roles: `admin`, `usuario`, `invitado`.
- **Bitácora:** entradas, intentos fallidos, altas, cambios de rol y de equipos.
- **Seguridad:** contraseñas con PBKDF2-SHA256 (600 000 iteraciones), bloqueo de 15 min tras 5 intentos, cookie de sesión firmada (HttpOnly, SameSite, Secure tras HTTPS), token CSRF y revisión de `Origin` en cada formulario, cabeceras de seguridad, texto escapado.
- **Instalación inicial:** al primer arranque se genera un código de un solo uso que se imprime en el log del contenedor; con él se crea el primer administrador en `/setup`.

## Modo DSM (recomendado en Magnolia)
Con `AUTH_MODE=dsm` las cuentas son las del Synology:
- **Entrada:** el portal envía usuario, contraseña y, si hace falta, el código de dos pasos a la API de autenticación del DSM (`SYNO.API.Auth`). El portal **no guarda contraseñas**. Una cuenta deshabilitada en el DSM no entra.
- **Primer acceso:** se crea la ficha del usuario con rol `invitado`, sin acceso a ningún equipo hasta que un administrador del portal le asigne rol. Quien esté en `ADMIN_USERS` es administrador.
- **Sincronización:** el botón «Sincronizar con el DSM» (solo administradores) lista los usuarios del DSM con la sesión del administrador (`SYNO.Core.User`), da de alta a los nuevos y **bloquea** a los deshabilitados o que ya no existen. No reactiva solo a nadie que un administrador haya bloqueado.
- **Roles por defecto al sincronizar:** activo en el DSM → `usuario`; deshabilitado → `invitado` y bloqueado. Un rol cambiado a mano por un administrador **no se vuelve a tocar**.
- **Sincronización automática:** se ejecuta sola cuando entra un administrador y cada `SYNC_EVERY` segundos (3600 por defecto) mientras haya una sesión de administrador abierta. No guarda contraseñas: usa esa sesión. Salvaguardas: una lista vacía del DSM no bloquea a nadie y los `ADMIN_USERS` nunca se bloquean por «ausentes».
- **Dos enlaces por equipo:** cada equipo puede tener dirección **local** (IP de la red de Magnolia) y **remota** (nombre público); el portal muestra un botón por cada una.
- **Variables:** `ADMIN_USERS` (usuarios del DSM separados por comas) y `DSM_URL` (por defecto `http://127.0.0.1:5000`; con la red del host de Docker funciona tal cual).

## Migración prevista a Cloudflare Access
Con `AUTH_MODE=cloudflare` el portal deja de pedir contraseña y toma el correo de la cabecera `Cf-Access-Authenticated-User-Email`. Los correos nuevos quedan «pendientes» hasta que un administrador los activa y les da rol. **Antes de usarlo** el puerto del portal solo debe alcanzarse a través del túnel con Access delante (si no, la cabecera se podría falsificar) y conviene validar el JWT `Cf-Access-Jwt-Assertion`.

## Variables
| Variable | Valor por defecto | Para qué |
|---|---|---|
| `DATA_DIR` | `/data` | Carpeta con `portal.db`, `secret.key` y `setup_code.txt` (hacer respaldo) |
| `PORT` | `8088` | Puerto interno |
| `AUTH_MODE` | `local` | `local`, `dsm` o `cloudflare` |
| `ADMIN_USERS` | vacío | Modo `dsm`: administradores del portal (usuarios del DSM) |
| `SYNC_EVERY` | `3600` | Modo `dsm`: segundos entre sincronizaciones automáticas (0 = desactivar) |
| `DSM_URL` | `http://127.0.0.1:5000` | Modo `dsm`: dirección del DSM visto desde el contenedor |

## Probar en local
```bash
cd portal-magnolia
python3 -W ignore -m unittest -v test_app
DATA_DIR=/tmp/portal-datos python3 app.py   # abre http://localhost:8088/setup
```

## Docker en el Synology (DSM 6)
Imagen: `python:3.12-alpine` (bajada con «Agregar desde URL» usando `https://mirror.gcr.io/library/python`, etiqueta `3.12-alpine`). Red del host, reinicio automático, volumen `/docker/portal-magnolia` → `/data`, comando que descarga `app.py` y lo ejecuta. Ruta del túnel: `magnolia.motica.mx` → `http://localhost:8088`.
