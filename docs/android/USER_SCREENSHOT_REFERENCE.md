# SP-DECODE Android — referencia visual aprobada por el usuario

**Prioridad visual:** captura compartida en la conversación del proyecto el
2026-10-08. Su diseño **prevalece sobre los SVG anteriores** de
`docs/android/design/` si existen discrepancias de composición o color.
Los SVG históricos se conservan para trazabilidad, sin eliminarlos.

## Rasgos que deben conservarse

- Fondo AMOLED negro real `#000000`, contenido blanco, acentos neutros.
- Cabecera compacta con escudo blanco en contenedor gris redondeado,
  «SP-DECODE» destacado y subtítulo «Decodificador de configuraciones».
  Icono discreto de opciones a la derecha.
- Panel superior de importación gris carbón (`#242424`), forma grande
  redondeada, icono vectorial de archivo/subida centrado, título
  «Importar configuración», descripción de dos líneas y botón píldora
  «Seleccionar archivo» gris oscuro.
- Debajo: fila «Resultado» y nota «Ejemplo ilustrativo» antes de importar.
- Tarjeta de resultado **negra**, con borde fino oscuro y radio redondeado,
  cabecera archivo (p. ej. perfil.tls), indicador de estado, separador,
  filas Formato / Servidor / Puerto / Contraseña, ojo para secreto, y
  botones oscuros gemelos «Copiar» y «Exportar».
- Barra inferior negra de cuatro iconos blancos/grises sin emojis:
  Inicio, Historial, Formatos, Ajustes. Una pestaña activa con énfasis claro.
- Interfaz iOS-like minimalista implementada con **Android nativo Compose**,
  sin imágenes de relleno, sin degradados fuertes, sin cartas azules.

## Diferencia deliberada por veracidad

Una captura conceptual puede mostrar «Decodificado» en verde para una
muestra ficticia. En la aplicación, ningún motor sin pruebas reales de
exportador debe etiquetarse como **certificado**. Se muestra
«Experimental» en amarillo tenue incluso tras producir un texto válido.
El ejemplo inicial se marca como **Ejemplo ilustrativo**, con Copiar y
Exportar deshabilitados.

## Implementación

- `android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt`.
- `MainActivity.kt` integra Android Storage Access Framework y puertos
  Kotlin por sufijo; conserva la prohibición de permisos de Internet.
- Localización es/en/pt-BR/ar en Android string resources.
- No se permite almacenar en disco el texto decodificado sin cifrado.
  La alpha almacena los resultados solamente en memoria de sesión.

La captura de referencia es un **adjunto de la conversación del usuario**,
no una captura generada por un emulador ni un recurso compilado en la APK.
No se debe confundir con evidencia de pruebas visuales físicas.

## Criterios para cerrar B.1–B.3 funcional alpha

- UI Compose arranca en Android 35; importar usando selector SAF;
- detección por extensión precisa (incluidos `.sksrv.png` y `.fɴ`);
- resultado original de decoder sin traducción y revelación opcional;
- copiar censurado por defecto, copiar original con confirmación;
- exportar TXT censurado/original con confirmación y ACTION_CREATE_DOCUMENT;
- pestañas y 59 formatos experimentales; historial solo de sesión;
- pruebas instrumentadas CI sin regresión en 72 tests anteriores;
- APK debug en artefacto GitHub Actions, **NO** release firmada estable.
