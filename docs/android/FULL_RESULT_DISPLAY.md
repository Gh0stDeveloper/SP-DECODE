# Android 0.3 — resultados completos y ajustes

Referencia directa: tres capturas compartidas por el usuario tras probar
la APK `0.2.0-alpha` en un teléfono Android real. No se sustituyen
esas capturas por diseños de otros chats.

## Problemas observados

1. La vista de `.xui` solo enseñaba las primeras diez entradas de JSON
   y recortaba cada valor a tres líneas.
2. Un `.hc` presentaba el objeto `Config` entero en una única fila,
   incluso cuando contiene campos anidados.
3. El detector heurístico consideraba sensibles nombres amplios como
   `Payload`, `PublicKey`, `Config` y otros que no son contraseñas;
   el usuario pidió visualizar íntegra la información.
4. Ajustes no tenía selector manual funcional, créditos ni enlaces de
   contacto del proyecto.

## Contrato del nuevo renderizador

`ResultPresentation.kt` recibe la salida textual exacta de Kotlin y
genera tres proyecciones **sin modificar el original**:

- **JSON**: si el texto contiene un objeto JSON completo independiente,
  extrae el JSON con un rastreador de llaves que respeta cadenas y escapes.
  Conserva `null`, booleanos, números, listas, objetos y el orden fuente
  de los miembros. No añade metadatos decorativos al JSON. Para otros
  scripts, toma los campos `│[۞] clave: valor` y convierte los valores
  JSON anidados cuando son válidos. Si el script no ofrece estructura
  interpretable, genera JSON válido con `format` y `raw`, **sin afirmar
  que el perfil se interpretó por completo**.
- **Estructurado**: lista todos los campos/subcampos con caminos
  `Config › advanced › port`, salida multilínea legible, sin
  `.take(10)`, sin `maxLines=3`, conservando el orden original.
- **Original**: copia de texto exacta e inmutable de la salida del
  decoder, disponible sin reescritura ni recodificación.

La pantalla por defecto muestra toda la información ya procesada.
«Ocultar contraseñas» es opcional y **desactivado inicialmente**.
No se considera secreto un campo `payload`, `proxy`, `publicKey`
ni `Config`. Los nombres explícitos de credenciales sí pueden
ocultarse opcionalmente **solo en la vista**. Copiar o exportar incluye
una confirmación de que se va a transferir texto fuera de la aplicación.

Cada acción Copiar o Exportar deja elegir JSON, Estructurado u Original;
la exportación JSON usa `application/json` y extensión `.json`;
las otras opciones usan TXT. Todos los archivos se crean mediante SAF.

## Ajustes y contacto

La opción Idioma permite sistema, Español, English, Português Brasil
y العربية. Se conserva en `SharedPreferences` junto a la opción de
ocultar contraseñas; **no** se persiste texto descifrado.
`DecodeSessionViewModel` preserva la sesión en memoria ante recreación
de Activity para cambiar idioma o rotar la pantalla. Se mantiene
`supportsRtl=true` y `Configuration.setLayoutDirection`.

Enlaces verificados con el README principal: 
- GitHub: https://github.com/Gh0stDeveloper/SP-DECODE
- Desarrollador: https://t.me/Gh0stDeveloper
- Grupo: https://t.me/CodeBreakersHub
- Canal: https://t.me/GhostDeve
- Issues y colaboración: https://github.com/Gh0stDeveloper/SP-DECODE/issues

Solo una lista blanca de HTTPS puede abrir aplicaciones externas.
La app sigue sin permisos `INTERNET`.

## Cobertura y límites

Las pruebas `FullResultsInstrumentedTest` cubren más de 46 claves,
JSON tipado, saltos de línea, estructuras anidadas y falsas detecciones
de datos sensibles. Las pruebas anteriores y la paridad sintética de
los 59 adaptadores no se modifican.

Los 59 decodificadores siguen siendo **experimentales**: falta
certificación frente a archivos reales y versiones recientes,
variantes EHI estándar/SIP VER7, ARM64/16KiB y revisión final antes
de publicar `release`. La alfa se firma y empaqueta como `debug`.

### Decisión final del usuario: una sola vista (0.3.5-alpha)

La presentación con el formato del bot, encabezados, delimitadores, claves y
valores completos, y JSON interno organizado es **la única vista principal**.
Se eliminan los controles desplegables de «Texto original» y «Campos
detallados». El texto original sin alteraciones se conserva en memoria
cifrada y en las acciones explícitas de copiar/exportar; no hay pérdida
de información ni cambios en motores criptográficos. La máscara de
credenciales continúa siendo opcional y desactivada por defecto.


### Nueva decisión 0.3.6-alpha: presentación exclusivamente JSON

Se reemplaza el bloque de salida estilo bot por **un único objeto/array JSON
indentado**. Los separadores originales no aparecen en pantalla. Metadatos
del resultado en líneas de comentario externas al JSON:
aplicación identificada por catálogo, fecha local de decodificación y
`Powered by Ghost Developer`. El objeto JSON es sintácticamente válido
cuando se copia exclusivamente su contenido; los comentarios NO se incluyen
dentro del objeto.

JSON nativo mantiene tipos, listas y objetos anidados. Salidas legacy `key:
value` se convierten en claves JSON manteniendo duplicados; casos no
estructurados se presentan como `content` JSON sin decoración. El texto
original continúa disponible a través de las acciones tradicionales de
copiar/exportar, sin modificación del resultado cifrado.
