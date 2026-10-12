# SP-DECODE Android v1.1.4 — Privacidad de NUR Tunnel y legibilidad HTTP Custom

- **Versión:** 1.1.4
- **versionCode:** 25
- **Actualización desde:** v1.1.3 (24)
- **Rama de trabajo:** `fix/nur-url-private-hc-text-v1.1.4`

## Cambios incluidos

- La tarjeta NUR Tunnel ya no muestra el campo con la URL del catálogo. Al abrirla, el usuario solo ve la explicación y el botón **Descifrar servidores**.
- El endpoint del catálogo se almacena en un recurso de la aplicación protegido por el vault AES-GCM existente. La descarga se mantiene bajo demanda y el catálogo sigue pasando por la autenticación y validación existentes antes de mostrarse.
- El diálogo de importación protegida de HTTP Custom fuerza el texto introducido en los campos contraseña y HWID a un color blanco legible.
- Se actualizan el aviso de novedades, el versionCode y los controles de CI/auditoría para que el APK pueda instalarse como actualización de v1.1.3 sin cambiar la identidad de firma.

## Límites de seguridad

La URL no se muestra en la interfaz ni queda como recurso de texto plano dentro del APK empaquetado. El recurso cifrado utiliza el vault AES-GCM ya establecido por el proyecto. Esto dificulta la extracción casual, pero no es un límite de secreto absoluto: una persona que analice suficientemente el APK puede recuperar los datos necesarios para descifrar recursos locales. Si se necesita que el endpoint permanezca secreto incluso frente a ingeniería inversa, el diseño requiere un servicio intermediario propio; una aplicación Android no puede utilizar una URL sin que un atacante dedicado pueda llegar a reconstruirla.

## Publicación

La publicación estable solo procede tras validar el commit exacto de `main`, compilar y probar la app, firmar con la keystore permanente de GitHub Secrets y comprobar V1/V2/V3, la coincidencia del certificado previo, la alineación de 16 KiB y los hashes SHA-256. Las pruebas sintéticas de CI no sustituyen la validación independiente en dispositivos físicos ni la matriz completa de exportadores reales, que siguen pendientes.
