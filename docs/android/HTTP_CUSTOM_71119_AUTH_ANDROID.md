# SP-DECODE Android — HTTP Custom 7.11.19: contraseña, HWID y doble bloqueo

Este desarrollo se añade **solo a Android**, sin modificar el bot, los scripts
históricos ni los 238 métodos de archivos ajenos a `.hc`.

## Qué detecta

Al importar **un solo archivo `.hc`**, la aplicación inspecciona el contenedor
HCCFG sin derivar claves por fuerza bruta ni intentar Argon2 innecesariamente.
Se interpretan el calendario `e` y el indicador `h`:

- `h=1`: requiere **contraseña de exportación** exacta, con espacios y
  mayúsculas intactos. Se convierte a UTF-8; Argon2id v19 deriva la clave.
- `e=n2` o `e=n8`: requiere el **HWID de 32 caracteres** asociado al
  archivo; se normaliza a mayúsculas tras eliminar espacios externos.
- `h=1` junto a `n2/n8`: **solicita ambos datos en un único diálogo**.
- Ausencia de ambos: **conserva la ruta anterior** `HcPort` y
  `HcHccfgPort` sin modificar la interfaz.

El diálogo es seguro (`FLAG_SECURE`) y no obtiene automáticamente ningún
identificador del teléfono. Si solo se requiere contraseña y hay contraseñas
privadas S.4 registradas, el usuario puede seleccionarla desde Android Keystore
o introducirla manualmente. Para HWID/doble bloqueo se solicitan los datos
manualmente. Sin credenciales correctas no se ofrecen resultados parciales.

### Entrada, transformación y resultado

`HcHccfgPort` mantiene la apertura exterior estándar (etiqueta AEAD) y el
sobre stream-v3 **no autenticado** usado por las muestras de HTTP Custom
7.11.19. La inspección de stream-v3 solo orienta la interfaz: el resultado
requiere etiquetas XChaCha20-Poly1305 correctas de la sección principal,
perfiles, envolturas HPR1 y sidecars. El método protegido prohíbe el antiguo
fallback HPR1 no autenticado.

La derivación replica el calendario `n7/n8`, concatenación Argon2id cuando
existe contraseña y `HKDF-SHA256`; los slots `o` de HWID se autentican
por separado. No se prueban claves alternativas ni se sustituye el HWID.

Para archivos protegidos, la salida incluye:
`app_version`, `requirements`, `config` (perfiles con
`options`, `flags`, `updated_at_ms`, `label`, `payload`),
`protections`, `main_config` y `other_sections` cuando existan.

La contraseña **de exportación** no se incorpora al documento descifrado:
`config[*].password` sigue representando la contraseña del perfil del
servidor, no la credencial que abre el archivo.

## Compatibilidad y límites

- Se conserva la ruta `HcPort.decode(context,input)` y el decoder
  HCCFG histórico para importaciones sin bloqueos. No se altera el bot.
- Entrada local limitada por las cotas ya existentes del Android router (1 MiB
  en `.hc`). No se amplía arbitrariamente a 16 MiB del script Python sin
  análisis de memoria de dispositivos pequeños.
- Se conservan las cotas Argon2 de Android y la validación de las secciones.
- En importación múltiple no se desbloquean silenciosamente archivos
  protegidos; la solicitud interactiva está disponible para **importación
  individual**. El lote continúa y reporta el fallo.
- Los tres archivos comerciales (sin bloqueo, contraseña, HWID) fueron
  verificados en **Python**, según el documento proporcionado por el usuario.
  **No se adjuntaron aquí los archivos comerciales para probar el motor
  Android.** Las pruebas de CI usan exclusivamente datos sintéticos.
- El **doble bloqueo** se ha demostrado con una fixture generada, no con
  una exportación comercial 7.11.19 real. Falta esa confirmación externa.

## Seguridad

El diálogo usa política de pantalla segura y campo de contraseña oculto.
La contraseña introducida se transforma a bytes de vida corta, y se limpia
tras la importación o cancelación del trabajo. El buffer cifrado de vista
previa también se limpia en cierre/cancelación. No se almacena contraseña
de exportación en historial ni se transmite por red.

La detección `inspectRequirements` puede ver una cabecera stream-v3
**sin autenticar**. Se valida contenido por etiquetas AEAD antes de mostrar
configuraciones; una cabecera maliciosa nunca certifica por sí misma un
descifrado válido.

## Pruebas

`HcSipVersionedInstrumentedTest` (Android API 35) cubre:
- Archivo `.hc` legado y HCCFG no protegido.
- Contraseña S.4 y comparación con contraseña errónea.
- HWID de 32 caracteres, normalización y rechazo incorrecto.
- Doble bloqueo: ambos datos, cada uno omitido o incorrecto.
- Salida de campos completos (incluida `main_config`).
- No aplicar credenciales `.hc` a `.ehi`, `.sip` ni otros motores.

Las muestras HWID y doble bloqueo se generan de forma sintética por
`tests/golden/hc_sip_new_variants.py`; **ninguna contraseña o HWID
comercial se publica**.

Cuatro idiomas: inglés, español, portugués de Brasil y árabe.
No se modifica la publicación de la APK estable automáticamente.
