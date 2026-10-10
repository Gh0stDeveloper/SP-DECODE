# SP-DECODE — Triaje de discrepancias reales Python/Node/PHP ↔ Android

**Fecha:** 2026-10-09 · **Rama:** `fix/android-text-decoder-parity-credits`.

## Objetivo

Corregir las configuraciones que el decodificador de referencia de SP-DECODE sí lee
(`decoders/Python`, `decoders/JavaScript`, `decoders/PHP`) pero la aplicación Android
rechaza. **No asumir que una comprobación sintética de la extensión verifica todas
las versiones exportadoras**. La app nativa usa motores Kotlin y primitivas JCA,
no ejecuta Python, Node ni PHP dentro del teléfono.

El registro `decoders.json` contiene **60 sufijos**; el test
`tests/test_android_route_source_contract.py` comprueba que cada uno tiene
una ruta Android única y que el script de referencia correspondiente existe.
**Ese test audita el cableado, NO demuestra que las 60 implementaciones cifren o
descifren igual**.

## Casos de divergencia identificados al revisar el código

| Caso | Referencia del bot | Diferencia detectada | Corrección / prueba |
|---|---|---|---|
| `nm-ssh://` y resto de `nm-*://` | `spdecode/handlers/text_protocols.py`, NetMod | El bot acepta texto descifrado no JSON; Android rechazaba la cadena si no era JSON. El motor **de textos** utiliza una clave fija y no debe confundirse con el motor **de archivos .nm**, que prueba tres claves históricas. | `TextProtocolDecoder.netmod` conserva el texto; `TextProtocolDecoderInstrumentedTest` incluye JSON y no JSON cifrados. |
| `ar-ssh://` | Manejador ARMod de texto | `parse_qs` de Python omite pares inválidos/vacíos y descifra dos veces escapes URL del campo `payload`. También puede reconocer credenciales SSH presentes en el texto. | Ruta Kotlin separada y prueba con enlace cifrado sintético. |
| `.dark`, `dark://`, `dtunnel://`, `dt://` | **Mismo** `DARKTUNNEL.py` para archivos y textos | El port Kotlin era más estricto que la referencia en Base64 de transporte, UTF-8 exterior, claves escalares MessagePack y valores binarios no imprimibles. | `DarkPort` + `StrictMessagePack` ajustados; 2 variantes sintéticas adicionales con resultado esperado generado por `DARKTUNNEL.run`; reimportaciones y texto/file en AndroidTest. |
| Copia ordenada | `ResultPresentation.kt` | El encabezado mostraba «Créditos» en vez de un enlace directo al perfil del desarrollador. | Eliminar etiqueta y mostrar `https://t.me/Gh0stDeveloper`; conservar grupo y canal en el pie. |

Para Dark Tunnel, tanto los archivos como los textos completos comparten el
**mismo port** `DarkPort.decode`. Un error de datos en un archivo no debería
resolverlo el decoder de un protocolo sin relación. La app procesa enlaces
completos pegados; el bot admite sesiones multipart en Telegram. No se debe
inventar una sesión multipart de Telegram en la aplicación Android.

## Protocolo reproducible para próximas muestras reales

1. Recibir **archivo real autorizado**, extensión y aplicación exportadora,
   `versionName/versionCode`; comprobar SHA-256 y longitud. Nunca registrar
   credenciales, endpoints privados ni archivos reales en el repositorio público.
2. Ejecutar el **script original** del registro con el archivo: Python, Node o PHP,
   conservando código de salida y un resultado esperado en un entorno de QA
   privado; constatar que descifra realmente, no solo que devuelve texto.
3. Ejecutar el **motor Kotlin** identificado por `AndroidOfflineDecoderRouter`
   contra los **mismos bytes**. Comparar etapa por etapa (contenedor/Base64,
   clave, IV/nonce, modo/segmento, KDF, descompresión, parser y campos de salida),
   sin cambiar claves o intentar fallbacks criptográficos ajenos.
4. Para textos (`nm-ssh://`, `ar-ssh://`, Dark Tunnel, etc.) comparar **con el
   manejador `spdecode/handlers/text_protocols.py`**, no automáticamente con
   el decodificador de archivos de la misma marca.
5. Agregar una prueba de regresión **con input sintético con estructura
   representativa**, generada y verificada por el script original; si la muestra
   real no puede publicarse, guardar QA/fixture únicamente en privado y publicar
   solo sus hashes, metadatos y un reporte sin secretos.
6. Ejecutar pruebas Python/Linux, Android API35 (incluido fallo/entrada corrupta)
   y, si el comportamiento depende de ABI, ARM64 y páginas de 16KiB.
7. Informar por sufijo y por **versión real**: confirmado, fallido, bloqueado
   por ejemplo faltante o solo sintético. No marcar «todo verificado» hasta
   poseer evidencia por cada variante solicitada.

### Registro de evidencias

Al momento de esta revisión, el corpus de CI contiene referencias sintéticas
de las 60 extensiones; LinkLayer VER6 cuenta además con prueba real de usuario
y captura Android. **No se han recibido las muestras fallidas** de Dark Tunnel
ni de los otros sufijos que el usuario reporta. Por tanto no puede asegurarse
todavía que esas variantes funcionen después de la corrección. Los tests nuevos
amplían la cobertura y reducen falsos rechazos, pero el cierre de la
compatibilidad real exige esos ejemplos y sus resultados de referencia.

## Comportamiento de la distribución

La publicación estable **v1.0.4** permanece intacta. Esta investigación
está en un PR; el siguiente release debe utilizar un `versionCode` superior,
la misma keystore permanente, CI verde y una decisión de publicación explícita.
No sobrescribir el tag estable existente ni presentar resultados sintéticos
como verificación real de todos los exportadores.
