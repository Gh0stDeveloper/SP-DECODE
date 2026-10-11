# Fase U — Únicamente visor JSON interactivo

Alcance confirmado: **U.1 árboles expandibles/contraíbles; U.2 rendimiento
para JSON grandes; U.3 resaltado de sintaxis en el resultado JSON**.

No se implementan búsqueda, botones nuevos de copia por campo, estadísticas,
historial adicional, cambios de tema, estilos globales o nuevos colores de
navegación. El diseño aprobado de SP-DECODE permanece intacto.

## Implementación

- `CompleteResultCard` conserva su superficie negra, bordes, cabecera de
  archivo, atribución, acciones Copiar/Exportar y control de ocultación.
- Solo el bloque que mostraba JSON con un `Text(...)` ahora monta
  `JsonTreeViewer` dentro de la misma tarjeta.
- Los colores están definidos exclusivamente dentro de
  `JsonTreeViewer.kt`: **claves azul**, **cadenas verde**, **números
  ámbar**, **booleanos violeta**, **null rosado** y **signos blancos**.
  No afectan a `MaterialTheme`, menús, botones o `strings.xml` aparte
  de las etiquetas accesibles de las acciones JSON.
- La presentación usa `AnnotatedString` con resaltado de sintaxis estilo
  Markdown con bloque `json`, **sin inyectar Markdown en el documento** y
  sin contaminar lo que el usuario copia/exporta.
- Objetos y listas se abren completos por defecto. Los controles de
  contracción manual y los colores existentes se conservan.
- Todas las entradas y cadenas se muestran completas, sin paginación,
  recortes de 512 caracteres ni límite de 5000 filas.
- La tarjeta usa un `Column` sin altura fija ni scroll propio: solo se
  desplaza la pantalla exterior de `HomeScreen`.
- La proyección recorre el árbol de forma iterativa, conservando rutas únicas
  y todas las ramas anidadas sin un corte artificial de profundidad.
- El análisis inicial del JSON se ejecuta en `Dispatchers.Default`,
  evitando bloquear el hilo de composición.
- Se reutiliza la lógica `ResultJsonDisplay` para respetar la redacción de
  credenciales y la extracción de JSON desde texto de decodificadores legacy.

## Invariantes

1. No se modifica el contenido `DecodeView.rawText`, el historial
   cifrado, los decodificadores ni ninguna clave.
2. `ResultJsonDisplay.render` sigue generando JSON **puro**, sin
   Markdown, anotaciones, comentarios de UI ni truncamiento.
3. La copia destinada a Telegram sigue empleando el bloque Markdown
   ```json` y los créditos exteriores; la vista de Android no altera
   esa salida.
4. Al ocultar credenciales, la proyección solo recibe el árbol enmascarado.
   Nunca se pinta el valor original en esa vista.
5. No se publica ninguna APK de producción únicamente por integrar U.

## Pruebas

`JsonTreeViewerInstrumentedTest` comprueba la expansión/contracción,
el enmascaramiento, rutas únicas para campos especiales, las 12 500 entradas
completas, valores largos y un único scroll exterior en `CompleteResultCard` sin perder
Copiar/Exportar. Se mantiene la suite de paridad existente.

CI: `validate`, Android API35 instrumentado, `assembleDebug`,
R8 `assembleRelease` (solo unsigned smoke) y auditorías S.1–S.4.
