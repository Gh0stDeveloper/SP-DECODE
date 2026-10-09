# SP-DECODE Android 1.0.3 — firma permanente automática

**Actualizado:** 2026-10-09

La actualización `v1.0.3-rc.1` incorpora **LinkLayer VPN (.lnk) VER6**, los 60 campos Go gob, decodificación Kotlin completamente local y un aviso de novedades visible una vez por versión. Conserva todos los motores anteriores, incluidos HC HCCFG y SIP VER8 de `v1.0.2-rc.1`. Esta candidata usa `versionName = "1.0.3"`, `versionCode = 14` y la misma keystore definitiva.

**Evidencia:** el script Python fue verificado por Codex con un archivo real aportado por el propietario. El port Android debe demostrar primero paridad con fixtures sintéticos y después con archivos reales de forma privada; no se declara certificación de todos los exportadores. Estable sigue en **NO-GO**, distribución pública como **pre-release**.

## Compilación y firma de producción

La APK de producción es un `assembleRelease` con `versionName = "1.0.3"`
y `versionCode = 14`. **No se usa una clave provisional, APK debug ni
certificado generado en CI.** GitHub Actions toma la misma keystore PKCS#12
definitiva que el propietario configuró mediante los cuatro Secrets:

- `SPDECODE_SIGNING_KEYSTORE_BASE64`
- `SPDECODE_SIGNING_STORE_PASSWORD`
- `SPDECODE_SIGNING_KEY_ALIAS`
- `SPDECODE_SIGNING_KEY_PASSWORD`

Conservar la keystore original y sus contraseñas fuera del repositorio y en
copias privadas redundantes. Perder la clave imposibilita firmar futuras
actualizaciones compatibles con la misma identidad Android.

### Automatización

1. Un push o merge a `main` inicia `Validate SP-DECODE` (Linux y Android).
2. Al completar ese workflow con **SUCCESS**, se activa automáticamente
   `Android Production Signed APK` mediante `workflow_run`.
3. El workflow de producción **rechaza eventos originados en PR/forks**.
   Debe coincidir el SHA del CI exitoso con la punta actual de `main`; un
   CI viejo nunca puede firmar código distinto ni una rama externa.
4. La compilación genera el mismo activo local auditado NPV que el CI de
   Android y ejecuta `gradle :app:assembleRelease` usando exclusivamente
   los Secrets de producción.
5. Verifica `apksigner` (V1/V2/V3), `zipalign -P 16` (16 KiB), nombre
   del paquete y versión con `aapt`. Si cualquiera falla, se marca
   **FAILURE** y no se publica una APK.
6. El artefacto de GitHub Actions se llama
   `SP-DECODE-v1.0.3-PRODUCTION-SIGNED`. Contiene:
   - `SP-DECODE-v1.0.3-production-signed.apk`
   - `SHA256SUMS.txt`
   - `SIGNATURE_VERIFICATION.txt` (SHA-256 público del certificado,
     verificación de esquemas y SHA del commit)
7. Existe `workflow_dispatch` para repetir manualmente el mismo flujo
   de producción sin cambiar firma, y también exige CI verde del SHA
   exacto en `main`.

**Importante:** no se proporciona keystore ni contraseñas dentro del artefacto.
La única copia en el runner se destruye al acabar el job.

## APK firmada frente a publicación pública

El artefacto automático es **APK release de producción firmada con la
clave definitiva**, apta para pruebas de instalación y actualización. No
se debe confundir con la publicación pública en GitHub Releases.

La publicación estable se realiza automáticamente **solo cuando** la
verificación `scripts/android_release_gate.py --mode stable --version 1.0.3`
aprueba todas las evidencias existentes en
`release/android-readiness.json`, cuya decisión actual es `NO-GO`.
El propietario ha aprobado pasar a 1.0.3 y ha declarado pasar pruebas
ARM64/16 KiB, archivos reales, lotes y auditoría personal; no hay que
inventar informes externos para cambiar los checks a `verified`.
La firma y prueba de actualización con la clave definitiva todavía requieren
evidencia tras ejecutar el primer APK release. La validación específica
en dispositivo de los protocolos nuevos de texto también debe incorporarse.

Cuando los controles estén completos y el propietario confirme la
compatibilidad de instalación/actualización, registrar los informes y
cambiar `decision` a `GO`. El siguiente CI verde de `main` publicará
v1.0.3 una sola vez, sin sobrescribir tags o binarios ya publicados.

### GitHub Releases: distribución pública del APK firmado

Desde la aprobación explícita del propietario el 2026-10-09 se permite
publicar **automáticamente una versión preliminar pública** mientras se
mantiene el control estricto de estabilidad `NO-GO`. Esta autorización
es distinta de una auditoría independiente completa.

- Tag publicado automáticamente: `v1.0.3-rc.1` (GitHub **Pre-release**).
- APK: `SP-DECODE-v1.0.3-production-signed.apk`, compilado mediante
  `assembleRelease` con la **keystore definitiva** de GitHub Secrets.
- Evidencias adjuntas: `SHA256SUMS.txt` y `SIGNATURE_VERIFICATION.txt`.
- Condiciones: CI exitoso en el **SHA exacto** de `main`, firmación y
  verificación V1/V2/V3 exitosas, `ownerApproval=true`,
  `publicPreviewApproval=true`, `decision=NO-GO` y versión coincidente.
- No se publica un APK debug ni se vuelven a publicar/modificar tags o
  binarios existentes: cada `vX.Y.Z-rc.1` se crea una sola vez.
- El texto público avisa que la certificación independiente de todas las
  variantes y pruebas de instalación/actualización sigue pendiente.

El mismo workflow publicará **`v1.0.3` estable** (sin sufijo) únicamente
cuando `scripts/android_release_gate.py --mode stable` verifique todas
las evidencias y la decisión cambie a `GO`. La distribución preliminar
**no altera** ni sustituye las evidencias pendientes de `release/android-readiness.json`.

Página pública: https://github.com/Gh0stDeveloper/SP-DECODE/releases

## Instalación y actualizaciones

La APK de depuración anterior fue firmada con una clave diferente y **no
puede actualizarse en el mismo dispositivo** sobre ella. Desinstalar una
aplicación puede eliminar de forma definitiva el historial protegido con
Android Keystore: antes de cambiar de certificado, exportar los resultados
que el propietario desee conservar. Las siguientes compilaciones firmadas
con **la misma** clave definitiva sí podrán actualizarse sin reinstalar
si se incrementa `versionCode`.

## Privacidad

El histórico contiene registros cifrados AES-GCM en
`SecureDecodeHistory` respaldados por Android Keystore; Room es un
índice reconstruible de identificadores y fechas. DataStore guarda solo
preferencias, pestaña y UUID. Los protocolos textuales y sus partes
incompletas se procesan localmente, sin Telegram ni subida de archivos.

Consultar `docs/android/USER_MANUAL_VALIDATION_2026-10-09.md` y
`docs/android/TEXT_PROTOCOLS.md` para el alcance de pruebas comunicado.
