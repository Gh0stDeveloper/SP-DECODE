# C3 — API protegida, sesiones, límites y procesamiento seguro

**Alcance:** únicamente SP-DECODE Android Cloud; sin cambiar UI/UX, bot ni algoritmos. La comunicación C++ en `libspdecode.so` sigue siendo parte de C4 y **no contendrá ninguna credencial permanente**.

## C3.1: API de archivos, textos y catálogos

`POST /api/v1/decode/file`, `/decode/text` y `/decode/import/catalog` conectan Next.js con los respectivos motores privados de C2 **solo** tras validar una sesión temporal de aplicación. Los archivos entran como JSON Base64 con formato explícito; `.hc` admite `credentials.password` y/o `credentials.hwid` de manera transitoria (solo en RAM y entrada estándar del worker). No se guardan originales en la API web ni se registran cuerpos de solicitud o resultados. Las salidas conservan `rawText`, `structuredJson`, `isPartial`, warnings y metadatos, sin afirmar certificación de versiones de exportador.

C3 introduce como límite de subida pública **8 MiB**, textos **250.000 caracteres**, cuerpo JSON **11 MiB**, worker privado C2 **16 MiB** máximo y salida **4 MiB**. El cuerpo HTTP se consume con límites; no se leen cantidades ilimitadas. Todos los resultados usan `Cache-Control: no-store` y códigos de error explícitos. El borrado de temporales ocurre dentro del `TemporaryDirectory` de C2 después del proceso.

## C3.2: sesiones y Google Play Integrity

1. Android solicita `POST /api/v1/session/challenge`: recibe `challengeId` y `nonce` aleatorios, conservados **120 segundos** en Redis.
2. La futura biblioteca nativa `libspdecode.so` integra con Kotlin/Play Integrity el desafío. Solicita un **token de integridad clásico** con ese `nonce`; la API no confía en valores enviados por Android sobre versión, modelo, paquete ni resultado.
3. Android envía `POST /api/v1/session` con `challengeId` e `integrityToken`. El servidor consume el desafío atómicamente con Redis `GETDEL` (no permite reuso) y llama al servidor de **Google Play Integrity API** para descodificar el token utilizando una cuenta de servicio exclusivamente del servidor.
4. Se comprueba `requestPackageName`, `nonce`, `timestampMillis` reciente, `appIntegrity.appRecognitionVerdict=PLAY_RECOGNIZED`, `deviceIntegrity` con `MEETS_DEVICE_INTEGRITY` y `LICENSED` por defecto. El requisito Strong Integrity es configurable.
5. Tras validación se emite un bearer HMAC-SHA256 con `jti` aleatorio y alcance `decode`, **TTL 300 segundos**, asociado a presencia activa de `jti` en Redis. Cada petición comprueba firma en tiempo constante, expiración y existencia de sesión.

**Limitaciones:** la validación real solo puede verificarse con credenciales de Google y una versión reconocida por Play Console; las pruebas CI inyectan una respuesta de Google simulada, nunca acreditan verificación real con dispositivos. Play Integrity no sustituye la protección de datos personales, autorización por usuario ni defensas contra robo de tokens; la app debe usar HTTPS y nunca registrar bearer o credenciales. Si se necesita acceso por cuenta de usuario habrá que añadir autenticación de identidad adicional.

## C3.3: límites, concesiones y red

- Desafíos: máximo **15 por ventana de 15 minutos** por IP normalizada (solo cabecera `X-Real-IP` establecida por proxy confiable; el Nginx debe **sobrescribirla** y limpiar encabezados de cliente).
- Admisiones Play Integrity: máximo **20 por IP / 15 minutos**.
- Solicitudes de descifrado: máximo **10 por token / minuto** y **20 por IP / minuto**.
- Procesos simultáneos por token: **2**. Un semáforo Redis evita excederlos incluso con múltiples instancias.
- Redis se utiliza para desafío de un solo uso, sesión y control de concurrencia; las cargas descifradas **no se almacenan** en Redis.
- API → worker está restringida a `http://decoder-worker:8787` (red privada Docker). Worker exige `X-SP-Worker-Token` distinto del token de sesión.
- API pública deshabilitada a menos que `CLOUD_API_ENABLED=true`, existan credenciales de Google, claves aleatorias del backend, URL Redis y proxy confiable. Sin configuración las rutas siguen respondiendo `503 CLOUD_NOT_READY`.
- `/api/v1/ready` solo responde READY cuando se encuentra configurado el acceso, Redis responde y el worker privado está listo; `/health` es únicamente liveness.

## C3.4: errores y resultado

Las rutas no exponen stderr, excepciones, contraseñas, rutas de sistemas de archivos ni tokens. Errores frecuentes: `INVALID_REQUEST`, `UNAUTHORIZED`, `RATE_LIMITED`, `INVALID_BASE64`, `INPUT_TOO_LARGE`, `UNSUPPORTED_FORMAT`, `PASSWORD_REQUIRED`, `HWID_REQUIRED`, `HWID_PASSWORD_REQUIRED`, `AUTH_FAILED`, `ENGINE_TIMEOUT`, `DECODE_FAILED` y `SERVICE_UNAVAILABLE`.

## C3.5: integraciones externas pendientes de activar

**HTTP Injector Cloud / `POST /api/v1/decode/import/cloud` permanece intencionalmente deshabilitado.** Aceptar una URL arbitraria y hacer `fetch` desde el servidor generaría riesgo de SSRF, credenciales filtradas y accesos a la red interna. Antes de habilitarlo es obligatorio un broker de descarga con allowlist de hosts del proveedor real, resolución DNS vinculada a IP pública, denegación de IP privadas/reservadas, prohibición de redirecciones y limitaciones de contenido/tiempo.

Los catálogos NUR ya descargados se pueden procesar como bytes protegidos, pero el servidor aún no descarga sus enlaces. La subida de muestras reales, la certificación de todas las versiones Android y las pruebas con Play Console siguen pendientes. **C3 no modifica ni adelanta la publicación del APK**.

## C3.6: despliegue y validación

`cloud/compose.yaml` añade Redis en la red interna, sin puerto público, sin persistencia de desafíos; no se entregan valores de secretos en Git. La API se publica solo en **127.0.0.1:3000** para pruebas locales, nunca se abre sin HTTPS y proxy restrictivo. La instancia Redis no está protegida con ACL/password porque es solo el prototipo de red Docker privada; usar autenticación y segmentación adicional para producción y configurar copias/HA según la política de retención.

```bash
cd cloud/web && npm install --no-audit --no-fund && npm test && npm run build
cd ../..
docker compose -f cloud/compose.yaml config --quiet
```

Las pruebas de `.github/workflows/cloud-c3.yml` verifican configuración fail-closed, expiración/replay, firma HMAC, nonce y respuestas Play Integrity simuladas, Redis simulado, límites y gateway en memoria. **Estas pruebas no sustituyen pruebas en un VPS real con Redis, Google Play Integrity, reverse proxy y datos sintéticos por cada formato.**

### Condiciones pendientes antes de habilitar usuarios

- [ ] Provisión de Google Cloud API, cuenta de servicio y aplicación Play Console reconocida.
- [ ] Configuración de servidor HTTPS, proxy confiable, protecciones anti-abuso y Redis autenticado.
- [ ] Auditoría de ataques SSRF e importadores remotos HTTP Injector Cloud/NUR.
- [ ] Pruebas reales Android → Play Integrity → API → workers por variante y formato, manteniendo UI/UX.
- [ ] Política de privacidad que explique transferencia de archivos, almacenamiento transitorio y no-retención.
- [ ] Pruebas de carga, memoria, tareas canceladas y continuidad del servicio.
- [ ] Retirar motores/secreto del APK (C4/C5) **solo** después de paridad.

**Rama:** `feat/cloud-c3-api-security`, PR apilado sobre C2 → C1 → C0. **No fusionar con `main` ni activar producción antes de validar los requisitos pendientes.**
