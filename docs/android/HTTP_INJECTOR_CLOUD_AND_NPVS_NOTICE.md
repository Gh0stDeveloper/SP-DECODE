# SP-DECODE Android — HTTP Injector Cloud y aviso NPVS

## Alcance

- Nueva sección independiente **Nube (Online)** en Inicio, con icono de nube.
  No sustituye el apartado **Textos**, los archivos locales ni los motores existentes.
- Soporta **HTTP Injector Cloud 6.5.0 / build 244** mediante:
  1. `https://ehi.link/CLAVE`, `ehi://ehi.link/CLAVE` o clave ASCII válida.
  2. Secuencias de emojis `💉…🚀` exportadas por HTTP Injector. El codec
     utiliza puntos Unicode, desplazamiento **128467** y Base64 estándar.
- Al tocar **Importar configuración cloud** se realiza un único POST HTTPS
  firmado hacia `https://www.ehi.tools/httpinjector/import_config`.
  Se verifican los HMAC y límites de tamaño; la respuesta se abre con AES-CBC,
  descompresión zlib y el motor EHI local existente usando una cabecera
  sintética temporal. El resultado se presenta en la tarjeta habitual.
- Los demás 239 formatos de archivo y protocolos de texto siguen operando
  **sin red**. La aplicación en su conjunto **ya no es 100 % sin permisos de
  red**: necesita `INTERNET` por esta función opt-in. No se añade backend,
  cuentas, telemetría ni sincronización.
- La referencia cloud y los identificadores sintéticos de petición llegan al
  servicio tercero. No se realiza la petición sin pulsación expresa. Un
  enlace cloud puede caducar o revocarse y requiere que el proveedor funcione.
- Las constantes del protocolo provienen de la investigación de HTTP Injector
  6.5.0 y son recuperables de cualquier APK cliente; **no son secretos privados
  de usuario**. El protocolo puede cambiar sin aviso. La clave de MAC del
  contenedor únicamente autentica el ciphertext, **no el IV**, por diseño
  del protocolo existente. `achilles` no se verifica y no se finge hacerlo.

## Mensaje NPVS localizado

Si falla la importación de un `.npvs`, se muestra un diálogo que informa
formalmente sobre la posible protección mediante clave privada. La evidencia
actual solo valida **NPVS v5 app-key**; no permite afirmar que cualquier fallo
sea forzosamente un bloqueo private-key (podría ser un archivo roto, otro modo
de exportación u otra versión). Por ello se usa «**es posible**».

Traducciones incluidas: inglés, español, portugués de Brasil y árabe.
Los lotes siguen procesando los demás archivos tras un error, y presentan el
aviso más el resumen final. El texto no expone el archivo ni contraseñas.

## Preservación de seguridad

- Red limitada a `HttpInjectorCloudPort`, invocado expresamente desde
  `MainActivity.decodeCloud()`, con HTTPS, redirects desactivadas,
  límite de 8 MiB, timeout de conexión 10s y lectura 20s.
- Datos EHI del servidor se vuelven a verificar criptográficamente con el
  motor Android existente; no hay fallback a texto cifrado ambiguo.
- No se guarda una entrada fallida, ni se guardan referencias como
  configuración descifrada. El historial mantiene su almacenamiento cifrado.
- `android_s3_security_audit.py` y `android_h_production_audit.py` ahora
  aceptan únicamente `INTERNET` por esta modalidad específica, siguen
  rechazando permisos amplios, logs sensibles y claves privadas.
- No publicar automáticamente una nueva APK: compilar y verificar en CI primero,
  y realizar QA manual de red/errores en un dispositivo.

## Pruebas

`HttpInjectorCloudInstrumentedTest` verifica sin contactar servidores:
- codificación emoji positiva `TEST1234` y referencias válidas;
- enlaces maliciosos y secuencias inválidas rechazados;
- firma HMAC-SHA1 frente a un vector independiente de Python;
- HMAC de respuesta manipulado y respuesta API inválida;
- EHI sintético no autenticado rechazado aunque el contenedor API sea válido.

Las pruebas de red en vivo no se realizan en GitHub Actions ni se publican
enlaces o respuestas de usuarios.
