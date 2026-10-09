# SP-DECODE Android 1.0.4 — firma permanente automática

**Actualizado:** 2026-10-09

La actualización `v1.0.4-rc.1` modifica **solo los créditos**: en la pantalla se muestra «Decodificado por SP-DECODE» y la copia/exportación **ordenada** añade «Desarrollado por Ghost Developer», grupo y canal oficiales. El JSON continúa siendo JSON válido sin campos publicitarios y el resultado original no se reescribe. Los motores (.lnk VER6, .hc HCCFG, .sip VER8 y anteriores) no se modifican. `versionName = "1.0.4"`, `versionCode = 15`, con la misma keystore definitiva que `v1.0.3-rc.1`.

**Evidencia:** CI `main` de v1.0.3 pasó Linux y **125 pruebas API35**, incluidos casos de paridad Python/Kotlin con fixtures sintéticos. El propietario también confirmó pruebas reales de `.lnk`, `.hc`, otros archivos, lotes y funcionamiento en Android (capturas privadas), y aprobó la distribución pública. No equivale a un informe reproducible de todos los exportadores ni a una auditoría independiente. La firma V1/V2/V3 del release anterior está documentada en GitHub Actions. El gate estable sigue separado de la **APK de producción firmada** distribuible bajo un tag pre-release.

## Compilación y firma de producción

La APK de producción es un `assembleRelease` con `versionName = "1.0.4"`
y `versionCode = 15`. **No se usa una clave provisional, APK debug ni
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
   `SP-DECODE-v1.0.4-PRODUCTION-SIGNED`. Contiene:
   - `SP-DECODE-v1.0.4-production-signed.apk`
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

La versión **1.0.4** es la primera distribución estable aprobada por
el propietario mediante decisión `OWNER-GO`, tras sus pruebas manuales de
archivos reales en Android y el consentimiento documentado en
`docs/android/USER_MANUAL_VALIDATION_2026-10-09.md`. Este canal no se
presenta como certificación independiente de todas las aplicaciones emisoras.
Los informes aún no reproducibles permanecen expresamente pendientes en
`release/android-readiness.json`.

El workflow exige como mínimo CI Linux y Android API35 satisfactorio para
el SHA exacto de `main`, compilación `assembleRelease`, verificación
criptográfica de firma permanente V1/V2/V3, alineación de 16 KiB, checksum
SHA-256 de los artefactos y coincidencia de commit. El propietario decide
distribuir de forma estable aceptando que quedan evidencias adicionales de
accesibilidad, rendimiento y actualización de firma por documentar.

El gate `scripts/android_release_gate.py --mode stable --version 1.0.4`
solo acepta una aprobación **explícita, documentada y específica de la
versión** `1.0.4`. Las versiones futuras necesitan consentimiento renovado.
No se cambian los estados de QA incompleta a `verified`.

### GitHub Releases: distribución pública del APK firmado

La rama de publicación preliminar (`-rc.1`) sigue disponible en el
workflow para futuras versiones que permanezcan en `NO-GO`.
Para **1.0.4**, el propietario ha aprobado la publicación **estable**
`v1.0.4` (sin sufijo), condicionada a CI y firma de producción
satisfactorios. Nunca se reutilizan ni sobrescriben tags existentes.

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
