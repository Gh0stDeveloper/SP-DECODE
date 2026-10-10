# Historial de cambios

> Referencia de entregas públicas Android. Las entradas antiguas del bot se conservan al final. Una APK firmada en prerelease no equivale a superar el gate para versión estable.

## Android v1.0.5-rc.1 — 2026-10-09 (vista previa firmada)

- Corregida la paridad de los archivos Dark Tunnel `.dark`, sus variantes de texto y la reimportación repetida respecto del motor Python de referencia.
- Ajustado el descifrado de texto `nm-ssh://` para usar su lógica específica y permitir resultados válidos que no sean JSON.
- Mejorado el procesamiento de `ar-ssh://`, incluida la interpretación de campos y la normalización del payload.
- Sustituida la etiqueta «Créditos» por el enlace directo del perfil de Ghost Developer en la exportación ordenada, conservando el resto de las atribuciones.
- La revisión del PR #40 documentó **130 pruebas instrumentadas API 35 aprobadas**.
- **Estado:** APK de producción firmada con la keystore permanente V1/V2/V3, publicada en [v1.0.5-rc.1](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.5-rc.1). **NO-GO estable**: faltan muestras reales de variantes reportadas como fallidas. Ver [triaje de compatibilidad](docs/android/REAL_DECODER_PARITY_TRIAGE.md).

## Android v1.0.4 — 2026-10-09 (estable publicada)

- Corregida la presentación de atribución en resultados/exportaciones ordenadas: SP-DECODE, Ghost Developer, grupo y canal oficiales; se conserva el JSON sin campos de publicidad.
- Se conserva el conjunto de motores anterior, incluida compatibilidad desarrollada para LinkLayer `.lnk` VER6 y otros formatos.
- Publicada la [APK estable v1.0.4](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.4) tras aceptación explícita del propietario y firma de producción. Esa aceptación no certifica de manera independiente todas las versiones exportadoras.

## Android v1.0.0-rc.1 a v1.0.3-rc.1 — historial de candidatos

- Primeras compilaciones Android nativas y offline con Kotlin/Compose, importación de archivos, resultados y localización.
- Incrementos de compatibilidad de decodificadores y motor de texto, incluidos formatos HTTP Custom, SocksIP y LinkLayer.
- Publicación de APK firmadas, pruebas de paridad de referencia, checks de firma V1/V2/V3 y automatización de CI.
- Consultar [GitHub Releases](https://github.com/Gh0stDeveloper/SP-DECODE/releases) y [release runbook](docs/android/RELEASE_RUNBOOK.md) para la evidencia y las limitaciones de cada versión.

---

## Historial anterior del bot de Telegram

## SocksIP 15.14.4 y separación de HTTP Injector Lite 2026-07-23

- Verificado el ZIP completo y analizado SocksIP 15.14.4, incluidos sus tres DEX y la biblioteca nativa.
- Confirmado que esta compilación usa Base64, AES-128-ECB/PKCS#7 y serialización Java, sin una ruta `VER7`.
- Mejorado el diagnóstico de las muestras `VER7` para indicar que pertenecen a otra variante en vez de solicitar de nuevo el mismo APK.
- Creado `HTTPINJECTORLITE.py` como decodificador Python independiente para `.ehil`.
- Eliminada toda la lógica Lite de `HTTPINJECTOR.py`, que queda reservado para HTTP Injector normal `.ehi`.
- Añadida una validación de registro que impide que `.ehi` y `.ehil` vuelvan a compartir script.
- Añadidas pruebas de aislamiento entre formatos y de detección explícita de SocksIP `VER7`.

## Campos internos y HTTP Injector Lite 2026-07-23

- Añadido el descifrado recursivo de valores NoobCrypt AES-256-GCM dentro del JSON de Maya y XUI.
- Verificada la etiqueta GCM antes de reemplazar cada valor; las cadenas Base64 comunes permanecen intactas.
- Sustituido el registro antiguo `.ehil` por el decodificador Python actual para HTTP Injector Lite 5.4.0.
- Añadidas las dos capas AES-CBC de Lite y la decodificación de campos internos con su alfabeto Base64 propio.
- Probadas las muestras reales de Maya, XUI y HTTP Injector Lite.
- Ampliado el conjunto a catorce pruebas automatizadas.
- Confirmado que las dos muestras SocksIP usan `VER7`; la implementación queda pendiente de recibir completo el APK 15.14.4.

## Integración de tres aplicaciones 2026-07-23

- Actualizado Maya Tunnel `.maya` al método NoobCrypt AES-256-CBC de la muestra suministrada.
- Añadido XUI Tunnel `.xui` con su clave actual y extracción del JSON prefijado.
- Añadido SocksIP Tunnel `.sip` para el formato AES-ECB con serialización Java generado por el APK suministrado.
- Añadida detección explícita del contenedor SocksIP `VER7`, que requiere el APK exacto de esa variante.
- Registradas 54 extensiones en total.
- Añadidas tres pruebas funcionales generadas para Maya, XUI y SocksIP.

## Entrega acumulativa 2026-07-23

- Fusionados TLS Tunnel y e-V2Ray en una sola base.
- Registradas 52 extensiones sin rutas faltantes.
- Aplicada una autorización central a archivos, protocolos de texto y fallback.
- Eliminados `config.json`, credenciales incrustadas y archivos de permisos heredados de la distribución.
- Añadido soporte opcional para `SPDECODE_BOT_TOKEN`.
- Eliminado `node_modules` del paquete; la instalación reproducible usa `npm ci`.
- Fijadas versiones de dependencias Python y Node.js.
- Añadida ruta criptográfica alternativa para TLS mediante `cryptography`.
- Incorporadas pruebas unitarias de acceso y fixtures funcionales de TLS/e-V2Ray.
- Extendida la validación estática para comprobar permisos, secretos y dependencias.
