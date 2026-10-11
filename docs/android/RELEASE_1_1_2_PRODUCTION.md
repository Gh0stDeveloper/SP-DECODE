# SP-DECODE Android v1.1.2 — Release de producción

- **Versión:** 1.1.2
- **versionCode:** 23
- **Rama de publicación:** main
- **Cambios de código:** PR #81 (integrado por el propietario antes de preparar esta versión)
- **Canal:** GitHub Release estable, APK de producción firmada con la misma keystore permanente de GitHub Secrets de versiones anteriores.

## Contenido

Se incluyen todos los cambios ya fusionados en main, especialmente el descifrado Android de HTTP Custom HCCFG 7.11.19 con detección y entrada de contraseña, HWID y doble bloqueo, sin sustituir el descifrador .hc anterior. También están presentes las funcionalidades de vista JSON, importación voluntaria HTTP Injector Cloud y aviso NPVS de la versión de código actual.

## Aprobación de distribución y límites

El 11 de octubre de 2026 el propietario autorizó expresamente subir versionName/versionCode y publicar inmediatamente una nueva **versión estable de producción**, sin solicitar validaciones adicionales. El propietario informó que Codex dejó el PR #81 con 229 pruebas Android satisfactorias, 289 pruebas Python con nueve omisiones previstas, compilación debug y R8 correctas. Estas cifras proceden del informe del propietario y no se presentan como certificación independiente.

La publicación utiliza exclusivamente los controles obligatorios del workflow existente: CI del commit exacto de main, generación del APK release con GitHub Secrets, firmas V1/V2/V3, coincidencia del certificado con versiones anteriores, alineación 16 KiB y SHA-256. No se introducen validaciones adicionales ni se deshabilitan los controles existentes.

Quedan pendientes informes independientes de instalación y actualización firmada en dispositivos físicos, una matriz completa de exportadores reales y una exportación comercial de doble bloqueo. No se afirma que esas verificaciones hayan ocurrido. La función Cloud requiere Internet tras una acción explícita; los descifradores de archivos y textos locales no lo requieren.

El workflow debe publicar **v1.1.2** con el archivo `SP-DECODE-v1.1.2-production-signed.apk` y sus comprobantes `SHA256SUMS.txt` y `SIGNATURE_VERIFICATION.txt`.
