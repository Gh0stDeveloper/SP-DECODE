# SP-DECODE Android v1.1.3 — Lanzamiento de producción

- **Versión:** 1.1.3
- **versionCode:** 24
- **Rama de publicación:** `main`
- **Preparación:** PR #83, rama `feat/android-multilingual-guide-cloud-hc`
- **Canal previsto:** GitHub Release estable, APK firmada con la keystore permanente de GitHub Secrets.

## Cambios de esta versión

- NUR Tunnel VPN: descifrado Android de perfiles `.solid` y pantalla Server VPN con catálogo HTTPS descargado solo mediante acción explícita del usuario.
- Icono dedicado de NUR Tunnel en la tarjeta Server VPN.
- Idiomas persa, francés, indonesio y ruso, además de los idiomas que ya estaban disponibles.
- Guía ampliada de HTTP Injector Cloud y de importación protegida de HTTP Custom, incluyendo contraseña y HWID.
- Aviso de novedades localizado que identifica la versión y las funciones incorporadas.

Se conservan las rutas de decodificación existentes, la vista JSON, el historial cifrado y el uso offline de los decodificadores locales. La pantalla de catálogo usa HTTPS y no descarga servidores hasta que el usuario lo solicita.

## Publicación y seguridad

El workflow de producción está preparado para ejecutarse después de que la validación completa del commit exacto de `main` termine satisfactoriamente. La publicación continúa exigiendo la keystore permanente de GitHub Secrets, verificación de firmas V1/V2/V3, coincidencia con el certificado publicado previamente, alineación de 16 KiB, hashes SHA-256 y el control de publicación por versión.

La aprobación del propietario para distribuir `1.1.3 (24)` se limita a esta versión. No representa certificación independiente de todos los exportadores VPN. Siguen pendientes evidencias reproducibles de instalación y actualización en dispositivos físicos, matriz completa de exportadores reales y validaciones independientes de accesibilidad y rendimiento. Esas limitaciones no se marcan como verificadas.

El lanzamiento debe publicar `v1.1.3` con `SP-DECODE-v1.1.3-production-signed.apk`, `SHA256SUMS.txt` y `SIGNATURE_VERIFICATION.txt`. No se debe sobrescribir `v1.1.2`.
