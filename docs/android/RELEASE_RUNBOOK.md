# SP-DECODE Android — firma, release y decisión GO/NO-GO

**Fecha de preparación:** 2026-10-09

La implementación de un pipeline de publicación NO equivale a permiso para
publicar una versión estable. Mientras A.2.4.3, A.2.4.4 y H.2–H.5 no estén
cerradas con evidencia reproducible, el archivo
[`release/android-readiness.json`](../../release/android-readiness.json)
permanece en **NO-GO**. La APK alpha nunca debe anunciar compatibilidad de
59 formatos reales sin verificación por versión.

## Responsabilidades

- **Usuario/tester:** ARM64 físico, páginas de 16 KB, exportaciones auténticas,
  variantes de cifrado y compatibilidad por versión; pruebas SAF/lotes de 30.
- **Desarrollo:** compilar, ejecutar CI, probar restauración cifrada/Room,
  comprobar permisos, auditoría y documentación del estado, correcciones de código.
- **Responsable de release:** revisar informes sin secretos, aprobar GO,
  custodiar la clave de firma y autorizar manualmente la publicación.

## Formato de evidencias

Cada bloque `evidence` debe indicar `status: "verified"` y `report`
con URL HTTPS o ruta real dentro de `docs/android/` o `release/evidence/`.
Los informes deben precisar app original y versión, Android/API/ABI,
fabricante/dispositivo, 4/16 KB, hash de fixture (sin credenciales),
resultado esperado/obtenido, intentos y hallazgos. No incorporar
configuraciones originales con credenciales o enlaces a datos privados.

No basta con tests sintéticos Linux/x86_64 para cerrar ARM64, 16 KB o
exportadores externos. Firmar la APK tampoco certifica la compatibilidad.

## Flujo de candidato firmado (no publica)

1. Configurar las variables secretas del repositorio o entornos protegidos:
   `SPDECODE_SIGNING_KEYSTORE_BASE64` (almacén codificado en Base64),
   `SPDECODE_SIGNING_STORE_PASSWORD`, `SPDECODE_SIGNING_KEY_ALIAS`,
   `SPDECODE_SIGNING_KEY_PASSWORD`. No insertar valores en Gradle,
   commits, capturas ni informes.
2. Proteger el entorno `spdecode-production` con revisores obligatorios
   y limitarlo a la rama `main`; opcionalmente `spdecode-candidate`.
3. GitHub → Actions → **Android Signed Release (Manual Gates)** →
   Run workflow, elegir `candidate`, versión `0.3.5-alpha`,
   `publish=false`.
4. La acción exige código de `main`, CI verde del **mismo SHA**,
   compila `assembleRelease` y verifica con `apksigner` v1/v2/v3,
   `zipalign` con páginas de 16 KiB y genera `SHA256SUMS.txt`.
5. Descargar el artefacto firmado y validar instalación/actualización
   contra **la misma clave**. Una APK debug firmada con otra clave
   **no puede actualizarse encima** de la versión firmada de producción;
   desinstalar para cambiar de firma borra el historial privado. No
   recomendar desinstalar sin exportar resultados deseados previamente.

## Publicación estable manual

Tras completar cada evidencia y obtener aprobación:

1. Cambiar `versionName` en Gradle a una versión estable real, incrementar
   `versionCode` y ajustar `stableVersion`, `decision: "GO"`,
   `ownerApproval: true` en el estado de release.
2. Ejecutar `python scripts/android_release_gate.py --mode stable --version 1.0.0`
   como comprobación previa. Revisar de nuevo tests, seguridad y CI de `main`.
3. Ejecutar manualmente el workflow con `kind=stable`, `version=1.0.0`,
   `publish=true` y `confirmation=PUBLISH_STABLE`. El entorno protegido
   exige revisión. Nunca crear release estable por un simple push o merge.
4. Confirmar APK, SHA-256, firma, instalación, changelog, políticas de datos
   y descarga pública. Guardar resultados en `release/evidence/`.

## Privacidad de la arquitectura B.5

El único almacenamiento que contiene perfiles descifrados es
`SecureDecodeHistory`: registros AES-GCM protegidos por Android Keystore,
guardados mediante `AtomicFile` bajo `noBackupFilesDir`. El índice Room
nuevo contiene únicamente UUID y timestamp; puede reconstruirse de esos
registros sin migrarlos, copiarlos ni descifrarlos en SQLite. DataStore
contiene retención, pestaña y último UUID, nunca la salida original.
El contenedor `SpDecodeApplication` centraliza estas dependencias.

El proceso Android recrea el ViewModel y vuelve a cargar los registros desde
disco; una restauración fallida del índice NO debe borrar archivos cifrados.
La navegación por pestañas sigue con Compose ligero; no declarar integración
Navigation Compose/Hilt realizada si no existe.
