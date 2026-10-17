# C6 — Sitio web y administración de SP-DECODE Cloud

Rama `feat/cloud-c6-public-site-admin`, PR apilado sobre C5 → C4 → C3.5 → C2 → C1 → C0.

## Sitio público (Next.js App Router)

Rutas `/`, `/features`, `/docs`, `/privacy`, `/status`. Diseño responsive de enfoque móvil, contenido en español, SEO y OpenGraph informativo, aviso de prepublicación. No incluye formulario de descifrado web ni enlaces de descarga de APK que aún no exista.

La página de estado usa `/api/site/status`: solo comunica `not_ready`, `testing` o `maintenance` y no revela redes privadas, tokens, claves, contadores de abuso o datos de archivos. Indicador `testing` NO significa que el servicio ya esté aprobado para público.

La política de privacidad es provisional y explica transporte de archivos, datos de contraseña/HWID, proveedores externos, metadatos hash para límites de abuso, historial local y requisitos legales pendientes. No afirma certificaciones ni políticas legales terminadas.

## Panel administrativo

Rutas `/admin/login` y `/admin` con operaciones exclusivamente desde `/api/admin/login`, `/api/admin/session`, `/api/admin/maintenance` y `/api/admin/logout`.

Admin exige `CLOUD_ADMIN_ENABLED=true`, `CLOUD_TRUST_PROXY=true`, Redis privado, `CLOUD_ADMIN_SESSION_KEY` aleatoria >=32 caracteres, `CLOUD_ADMIN_PASSWORD_SCRYPT` (scrypt con sal aleatoria) y `CLOUD_ADMIN_PUBLIC_ORIGIN` como origen HTTPS exacto. En ausencia de cualquiera de estos factores **el panel permanece desactivado** (503).

El login usa hash scrypt, máximo cinco intentos por IP/15 min, límite global, cookie HMAC HttpOnly/Secure/SameSite Strict con caducidad 30 minutos y presencia de sesión en Redis. La IP hash debe coincidir para cada petición y la revocación de la cookie cierra la sesión. Las mutaciones exigen Origin HTTPS fijo, cabecera `X-SPDecode-Admin-Action: 1`, JSON estricto y Fetch Metadata same-origin.

El panel visualiza **solo** estado de Redis, readiness del worker, configuración booleana de la API/proveedores, mantenimiento y contadores agregados diarios UTC. No visualiza nombres, contenido, contraseñas, HWID, bearer, tokens ni archivos procesados; no puede modificar claves ni el inventario de motores.

El interruptor guarda en Redis la clave `spc6:maintenance`. Las rutas de desafío y sesión Play Integrity, descifrado de archivos/texto e importadores C3.5 rechazan nuevas operaciones si la clave está activa. El estado de mantenimiento es volátil por diseño en este entorno de desarrollo Redis sin persistencia. En producción se requiere un mecanismo persistente/externo y un plan de continuidad antes de habilitarlo para operación pública. Las operaciones ya iniciadas pueden terminar.

Las métricas guardan exclusivamente contadores por día UTC y resultado correcto/fallido; TTL de ocho días. No se graban payloads, valores descifrados, direcciones IP o credenciales. No se contabilizan solicitudes bloqueadas antes de ejecutar un worker.

## Provisión segura, solo VPS

Se puede generar un hash administrador por stdin con `node cloud/web/scripts/hash-admin-password.mjs` (por ejemplo, introducir la contraseña por una entrada de terminal no registrada). Nunca pasar la contraseña en argv, publicar el hash, ni guardar la clave del panel en el APK. Elegir claves distintas de `CLOUD_WORKER_TOKEN` y `CLOUD_SESSION_SIGNING_KEY`.

Todas las rutas administrativas se sirven exclusivamente tras un proxy HTTPS que **sobrescribe X-Real-IP** y configura HSTS. Añadir allowlist IP, VPN, MFA o SSO del operador es recomendado antes de exposición pública. El dashboard no incorpora MFA y **no debe presentarse como configuración definitiva de producción**.

Para correr CI: `cd cloud/web && npm install && npm test && npm run build`; y `docker compose -f cloud/compose.yaml config --quiet` desde la raíz. La suite C6 prueba acceso, cookies, CSRF, expiración/revocación, rate limit, mantenimiento y métricas, sin credenciales reales.

## Pendientes

- Configuración real de dominio DNS/HTTPS, cuentas Play Integrity, credenciales, seguridad operativa y privacidad legal.
- C7: integración Android-Cloud y paridad de descifrado con archivos autorizados, pruebas de carga y auditoría del panel.
- C8: endurecimiento de despliegue, monitorización, rollback y aprobación para producción.
- No fusionar a main ni publicar APK hasta superar los checks y estas validaciones.

**El bot Python, los motores y los nueve archivos visuales Android de C0 permanecen intactos.**