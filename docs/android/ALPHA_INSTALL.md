# Instalación de la primera APK funcional — 0.3.0-alpha

## Descargar APK debug de GitHub Actions

Abrir `.github/workflows/validate.yml` en Actions de SP-DECODE y
elegir el último run del PR `feat/android-b1-functional-compose-app`
con jobs `validate` y `Android UI alpha + 60 synthetic vectors (API 35)`
en `success`. En **Artifacts**, descargar
`SP-DECODE-Android-v0.3.0-alpha-debug-APK`. Extraer
`app-debug.apk` del ZIP del artefacto y enviarlo al teléfono.

**Importante:** este archivo no se obtiene desde el bot Telegram ni
desde un backend. Debe proceder de un run exitoso y quedar claramente
identificado como APK debug experimental (NO firmada para release 1.0).
Android puede requerir autorizar instalaciones de esa fuente.

## Uso real disponible

1. Abre la app. En Inicio toca **Seleccionar archivo**.
2. Android abrirá su selector de archivos (SAF). Elige un perfil local
   cuyo sufijo figure en Formatos.
3. SP-DECODE detecta el sufijo y ejecuta el port Kotlin completamente
   sin conexión. El tamaño máximo por archivo es 1 MiB en esta versión.
4. Si el decoder de esa variante puede producir salida, se mostrará en
   Resultado. Los datos sensibles se ocultan de forma conservadora
   hasta que se revelen.
5. Copiar y Exportar ofrecen por separado versiones censuradas y
   originales, con un mensaje previo sobre la posible exposición de
   contraseñas. Se puede abrir con Android «Abrir con/Compartir».
6. Historial **solo de sesión**, sin escritura a disco. Se borra al
   cerrar el proceso.

## Limitaciones

Los 59 sufijos tienen ports experimentales probados con **60 muestras
sintéticas**, no con cada versión actual del exportador de terceros.
Por ello un archivo real puede ser incompatible. Algunas variantes
como EHI estándar Argon2id/ChaCha20-Poly1305 y SocksIP VER7 siguen
pendientes. No se pretende certificar los 59 originales con esta APK.

No hay base de datos persistente cifrada, botón de idioma manual,
cancelación fuerte de cómputo interno, colas persistentes, firma release,
prueba física ARM64/16KB, ni certificación de calidad de producción.
Android utiliza el idioma del sistema entre es/en/pt-BR/ar, con RTL
para árabe; el resultado del decoder se conserva literalmente.

Diseño: `docs/android/USER_SCREENSHOT_REFERENCE.md`.

## Cambios de la alfa 0.3

- Resultados completos: ya no hay límites de diez campos ni tres líneas.
- `.xui`: propiedades JSON con sus tipos y orden original.
- `.hc`: Config y Protections se desglosan en campos anidados.
- Copiar/Exportar: JSON válido, vista estructurada completa o texto original.
- Ajustes: selector de idioma (sistema/es/en/pt-BR/ar) y preferencias de visibilidad.
- Créditos del desarrollador y enlaces GitHub/Telegram para colaborar.
- La preferencia de idioma y ocultación se guarda; los textos descifrados
  siguen exclusivamente en memoria. El historial no es persistente.

Detalles técnicos: `docs/android/FULL_RESULT_DISPLAY.md`.
