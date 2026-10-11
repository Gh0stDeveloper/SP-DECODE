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
- Objetos y listas se pueden expandir/contraer. Los objetos pequeños de
  primer nivel se abren por defecto para conservar campos importantes.
- Proyección de filas con carga progresiva: hasta 80 hijos inicialmente por
  colección, 80 adicionales por toque; las ramas cerradas no se recorren.
- `LazyColumn` compone las filas visibles dentro de un área con altura
  máxima de 480 dp; no intenta crear miles de `Text` a la vez.
- Cadenas largas muestran inicialmente 512 caracteres y permiten revelar
  1024 adicionales por toque. No se corta el texto original ni la exportación.
- Se limita el máximo de filas proyectadas y la profundidad de expansión
  para evitar ciclos descontrolados al explorar JSON patológicos.
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
el enmascaramiento, rutas únicas para campos especiales, paginación de
12 500 entradas y visualización en `CompleteResultCard` sin perder
Copiar/Exportar. Se mantiene la suite de paridad existente.

CI: `validate`, Android API35 instrumentado, `assembleDebug`,
R8 `assembleRelease` (solo unsigned smoke) y auditorías S.1–S.4.
