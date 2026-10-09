# SP-DECODE — Handoff para Codex: análisis de VER6 en una extensión nueva

**Fecha de preparación:** 2026-10-09  
**Estado:** documentación inicial; **pendiente de recibir la aplicación original y el archivo de configuración**.  
**Repositorio:** https://github.com/Gh0stDeveloper/SP-DECODE  
**Destinatario:** nueva sesión de Codex con acceso al repositorio y capacidad de ejecutar pruebas.

**Alcance prioritario confirmado por el propietario:** entregar **solo un script Python funcional de descifrado para el bot Telegram SP-DECODE**. El port Kotlin/Android, cambios de interfaz, APK, firma y Releases quedan **pospuestos a otra sesión**. El propietario ya obtuvo scripts con Codex y Sol, y desea **economizar tokens de Sol**: concentrarse en analizar la aplicación y el archivo, implementar el script y probarlo; evitar informes repetitivos, exploraciones innecesarias y tareas Android adelantadas, sin sacrificar pruebas ni exactitud.

> **ACLARACIÓN CRÍTICA:** El `VER6` de este encargo **NO pertenece a SocksIP ni a la extensión `.sip`**. El propietario enviará una aplicación distinta y un archivo de otro formato en el próximo chat. No asumir que `VER6` es una cabecera, versión o algoritmo compartido. No reutilizar claves, offsets, cifrados ni transformaciones de SocksIP, HC o cualquier otro decodificador sin evidencia directa del **nuevo** par aplicación–archivo.

## 1. Objetivo de la nueva sesión

Analizar, con evidencia reproducible, cómo la aplicación original **importa y procesa** el nuevo archivo de configuración; determinar su formato y las etapas relevantes; desarrollar un **decodificador Python compatible con el bot de SP-DECODE** (único entregable funcional exigido ahora); y conservar intactos los decodificadores de versiones y formatos existentes.

**No fabricar compatibilidad:** reconocer extensiones, cabeceras o cadenas como `VER6` no prueba la decodificación. Si no se reproduce la importación original de manera verificable, documentar el punto alcanzado y continuar el análisis, sin marcar el soporte como confirmado.

## 2. Datos que todavía NO se conocen

Antes de recibir los adjuntos, todo lo siguiente es **desconocido**:

- Nombre de la aplicación de origen, identificador de paquete, versión y build.
- Extensión del archivo, estructura y función precisa de `VER6`.
- Si existe una versión anterior del mismo formato y si ya tiene motor en SP-DECODE.
- Capas de codificación, compresión, serialización, cifrado, autenticación, derivación de clave y metadatos.
- Si la aplicación obtiene datos de red o contiene claves locales para importar.
- Si el archivo dispone de bloqueo de uso, contraseña de exportación, validación de dispositivo o firma; **no inferir** que una contraseña es necesariamente parte de la decodificación.
- Resultado esperado y conjunto de campos, hasta obtener una exportación controlada o evidencia equivalente.

**Los adjuntos todavía no se han suministrado en esta conversación.** No referenciar rutas de APK ni archivos que no existan realmente en la próxima sesión.

## 3. Materiales a recibir en el nuevo chat

**Obligatorios:** (a) APK de la aplicación original y (b) archivo de configuración asociado.  
**Deseables:** versión exacta de la app, extensión confirmada, imagen del resultado de importar el archivo en la app original y una descripción de los campos de una configuración de prueba conocida, sin secretos reales. Si existen varias exportaciones del mismo formato, solicitar dos o más archivos con cambios controlados de un único campo para comparar la estructura.

Trabajar sobre una copia del APK y de los archivos; obtener y registrar SHA-256, tamaños, tipo detectado, marcadores, versión/fecha y procedencia. No publicar APKs de terceros, configuraciones privadas, credenciales o endpoints reales en commits, issues o logs públicos.

## 4. Arquitectura existente que debe respetarse

### 4.1 Bot Telegram / Python

- Registro canónico: `decoders.json` (actualmente **59 extensiones**; comprobar la cifra de nuevo al iniciar).
- Lectura, extensión incluida extensión compuesta y validación: `spdecode/registry.py`.
- Ejecución de decodificadores Python, Node o PHP con `subprocess` y tiempo máximo: `spdecode/executor.py`.
- Recepción y respuesta de documentos: `spdecode/handlers/documents.py`.
- Decodificadores existentes: `decoders/Python/`, `decoders/JavaScript/`, `decoders/PHP/`.

El nuevo decodificador del bot debe ser **no interactivo**, aceptar una ruta de entrada en el CLI, usar errores explícitos, producir resultados deterministas y respetar límites de tamaño/tiempo. No registrar claves privadas ni entradas completas en logs. El bot divide sus respuestas largas por límites de Telegram; **esta numeración no forma parte de la salida en Android**.

Si la extensión ya existe, añadir una ruta de versión **dentro de su decodificador** conservando el algoritmo viejo. Si es nueva, determinar el nombre, la ruta y el runtime del futuro registro, pero **no modificar todavía `decoders.json` en `main`** sin adaptar el catálogo Android. El propietario integrará ese paso posteriormente.

### 4.2 Aplicación Android / Kotlin — referencia para otro chat; fuera del alcance actual

**No implementar ni compilar Android en esta sesión.** Estos archivos se enumeran solo para que, posteriormente, el propietario pueda integrar o portar el decoder Python al motor Kotlin offline. Esa adaptación no es automática.

- App offline con Kotlin + Jetpack Compose; importación mediante Storage Access Framework, resultados completos y almacenamiento local cifrado del historial.
- Despacho: `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/AndroidOfflineDecoderRouter.kt`.
- Puertos específicos y utilidades: `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/`.
- Inventario Android: `AndroidDecoderCatalog.kt` y `android/app/src/main/assets/decoder_catalog.json`.
- Generador de catálogo: `scripts/android_a24_catalog.py`, enlazado con `decoders.json`.
- Pruebas del catálogo: `tests/test_android_a24_catalog.py`.
- UI de resultados: `CompleteResultCard.kt`, `ResultPresentation.kt`, `SpDecodeApp.kt` según requiera el formato.

**Nota para integración futura:** hay contadores y aserciones literales de `59` en el catálogo y las pruebas Android. Registrar una extensión nueva en `decoders.json` exigirá adaptar ese catálogo en la fase posterior. **No registrar una extensión nueva en `main` ni fusionar PR experimental ahora** si rompe el catálogo; mantener el script Python probado en una rama separada. No incrementar contadores de formatos verificados sin evidencia.

Android no debe requerir Python, Node, PHP, red, credenciales externas o acceso root para descifrar. No cambiar el diseño de inicio ni deshacer los resultados completos, el historial y el comportamiento offline ya incorporados.

### 4.3 Release y CI (línea base)

- Referencia al preparar este handoff: Android **v1.0.2**, `versionCode=13`, con `v1.0.2-rc.1` pública firmada.
- Workflow de validación: `.github/workflows/validate.yml`, Linux y pruebas instrumentadas Android API 35.
- Firma de producción con keystore **definitiva en GitHub Secrets**, verificación V1/V2/V3 y archivos SHA-256. **Jamás usar keystore temporal, subir una keystore ni copiar secretos al repositorio.**
- Puerta estable `GO/NO-GO`: `release/android-readiness.json` y `scripts/android_release_gate.py`.
- La fusión en `main` puede disparar firma y publicación automática de APK. **En este encargo NO fusionar a `main`, NO incrementar `versionCode` ni `versionName`, NO firmar ni publicar APKs**. Entregar solo el motor Python validado en una rama/PR separada.

## 5. Fases de investigación e implementación

### Fase 0 — Registro y validación de insumos

1. Verificar que los dos adjuntos pertenecen al mismo producto y edición; registrar APK `packageName`, `versionName`, `versionCode`, ABI/SDK, SHA-256 de ambos y extensión real. Mostrar únicamente metadatos seguros.
2. Comprobar si el archivo puede importarse de verdad en la aplicación suministrada. Un bloqueo de **uso** posterior a la importación puede ser distinto de la capa de **decodificación**; registrarlos por separado.
3. Revisar `main` actual, catálogo y decodificadores existentes para evitar trabajo duplicado. Crear una rama de investigación `analysis/<formato>-ver6`, sin modificar producción.
4. Redactar la matriz de evidencia: `observado en archivo`, `observado en app`, `confirmado por prueba`, `hipótesis`, `pendiente`.

**Salida obligatoria:** identificación fiable de los materiales y plan revisado según su formato real.

### Fase 1 — Reconstrucción del flujo de importación

1. Inspeccionar la estructura de la APK de forma local y autorizada: manifest, recursos, assets, librerías `.so`, DEX y referencias del selector/importador (herramientas como JADX, apktool y `aapt` cuando estén disponibles).
2. Localizar el punto de entrada al archivo, lectores de bytes/streams, validaciones, parsers, serialización y operaciones criptográficas. Seguir el trayecto del archivo por **todas** las rutas relevantes de importación, no solo buscar cadenas en el APK.
3. Trazar controles de versión del contenedor y comprobar dónde aparece `VER6`, **si aparece**. No atribuir a un marcador una semántica sin observar su uso.
4. Si el código está ofuscado o depende de librerías nativas, inspeccionar llamadas y límites Java↔JNI y realizar experimentos controlados en un emulador con la APK suministrada si el entorno lo permite.
5. Separar la comprobación de integridad/autenticidad, permisos de uso y lógica de presentación de la lectura y descifrado del archivo.

**Salida obligatoria:** diagrama **basado en evidencia**, referencias precisas a funciones/clases/librerías relevantes y lista de etapas confirmadas frente a desconocidas.

### Fase 2 — Caracterización del formato

1. Medir longitud, firmas/magic bytes, contenedores internos, cabeceras, offsets, endianness, campos, flags y segmentos variables. Comparar archivos con diferencias controladas si se disponen.
2. Identificar codificación, compresión, serialización y, **solo cuando exista evidencia**, cifrado, KDF, nonce/IV, autenticación, AAD y orden real de las capas.
3. Implementar un inspector **de solo lectura**, sin pérdida de bytes, con tamaños máximos y salida de metadatos/SHA-256. No buscar claves a ciegas ni interpretar contenido arbitrario como éxito.
4. No confundir el marcador `VER6` con la extensión `.sip`, con el cifrado de SocksIP `VER8` o con cualquier variante de otra aplicación.

**Salida obligatoria:** especificación de archivo y un inspector reproducible que no expose contenidos privados.

### Fase 3 — Decoder Python para el bot

1. Implementar motor pequeño, mantenible y modular con API pura `decode(bytes)` o equivalente y envoltorio CLI `python ... archivo.ext`.
2. Encauzar excepciones tipadas: formato no reconocido, versión no soportada, contenedor truncado, autenticación inválida, dependencias ausentes y error de procesamiento.
3. Dar salida completa y ordenada sin inventar campos ni suprimir errores; conservar valores originales y separar comentarios/encabezados del contenido de configuración.
4. Preservar todos los motores existentes y la salida anterior cuando se trate de una nueva variante de un sufijo existente.
5. Añadir `decoders.json` únicamente tras confirmar la extensión, y pruebas del registro/CLI/bot.

**Salida obligatoria:** resultado verificable con la muestra aportada y pruebas negativas que no producen falsos éxitos.

### Fase 4 — Preparación mínima para una futura integración Android (OPCIONAL)

**No portar a Kotlin, no cambiar la UI y no compilar APK en esta sesión.** Tras conseguir que Python funcione, dejar como máximo una nota breve con entrada, salida, algoritmos comprobados y dependencias para que el propietario realice la integración Android posteriormente.

**Salida opcional:** breve guía de portabilidad. **No exigirla para dar por terminado el trabajo Python.**

### Fase 5 — Auditoría de seguridad y QA

- Casos positivos autorizados, negativos, entradas vacías/corruptas, longitudes alteradas, versiones desconocidas, duplicados y lotes mixtos.
- Validar autenticación e integridad donde corresponda: ningún resultado presentado como éxito tras fallar un MAC/tag.
- Límites de tamaños, profundidad, tiempo, memoria y descompresión. No ejecutar deserialización de objetos con efectos secundarios ni código procedente del archivo.
- Comprobar que ninguna configuración privada ni clave privada se escriba en logs, fixtures públicos o informes del CI. Para dispositivos, conservar procesamiento local.
- Ejecutar **tests Python y CLI/bot**, incluidos casos positivos y negativos y CI Linux relevante. Android API35, ARM64 y páginas de 16 KiB quedan para el trabajo posterior; **no ejecutarlos como parte de esta solicitud**.
- No dar por verificado un formato real basándose exclusivamente en archivos sintéticos. Registrar al menos un caso real autorizado y su resultado esperado en un repositorio **privado** o registro de QA seguro, no en GitHub público.

**Salida obligatoria:** matriz de pruebas, alcance real de compatibilidad y reporte de limitaciones reproducibles.

### Fase 6 — Entrega focalizada del decodificador Python

1. Documentar brevemente formato, método identificado, dependencias y límites, citando evidencias sin exponer secretos privados.
2. Mantener el código probado en una rama independiente; abrir un PR de Python si resulta útil. Ejecutar tests pertinentes y corregir errores.
3. No fusionar a `main`, no alterar versión Android ni activar publicación de APK. El propietario decidirá después cómo portar e integrar.
4. Entregar ruta del script, comando de uso (`python ... archivo.ext`), dependencias y resultado de las pruebas con el archivo suministrado.

**Salida obligatoria:** script Python funcional y verificado, pruebas de errores y guía breve para ejecutarlo desde el bot. **No se requiere Kotlin, APK ni Release.**

## 6. Criterios estrictos de aceptación

**Para este encargo Python, la entrega se considera terminada cuando:**

- La extensión y la relación de `VER6` con la **nueva aplicación (no SocksIP)** están confirmadas con los adjuntos.
- El script **Python** se ejecuta sin preguntas interactivas y reproduce los campos que se pueden verificar en el archivo real.
- Las pruebas positivas, negativas y de entradas truncadas son reproducibles, sin errores silenciosos ni falsos éxitos.
- No se alteran ni rompen los decodificadores anteriores.
- Se proporciona archivo fuente, dependencias, comando de uso y resultado concreto de validación.
- Todo queda aislado en rama/PR, sin fusionar ni disparar una publicación de la aplicación.

**Quedan expresamente fuera de aceptación:** compilación Android, Kotlin, interfaces, pruebas instrumentadas, número de versión de APK y GitHub Releases.

Si una etapa no es posible, declarar **PARCIAL / BLOQUEADO / NO CONFIRMADO**, indicar la evidencia faltante y avanzar en pruebas o análisis que sí sean verificables. No marcar “terminado” sin pruebas.

## 7. Uso eficiente de tokens con Codex/Sol

El propietario ya ha desarrollado scripts de descifrado con Sol y desea aprovechar su capacidad de programación **sin gastar tokens en tareas que no pidió**. Priorizar el resultado funcional, usar herramientas dirigidas y evitar explorar secciones irrelevantes del repositorio o volver a explicar hallazgos ya verificados. No reducir comprobaciones esenciales por ahorrar tokens.

Cada respuesta de progreso debe ser compacta: **qué código avanzó, qué prueba pasó/falló y qué impide obtener la salida correcta**. Trabajar directamente en Python y usar evidencias de APK/archivo; no abrir trabajos Android, propuestas gráficas ni largos documentos si el script todavía no descifra.

En la entrega final bastan: ruta del script, comando para probarlo, dependencias, pruebas ejecutadas y limitaciones reales. No afirmar éxito por identificar una cabecera o extraer bytes no interpretados.

## 8. Indicaciones para abrir el siguiente chat con Codex

Entregar en el mismo mensaje **la APK y el archivo de configuración**. Solicitar lectura de este documento desde `main` e inicio inmediato del análisis. **Objetivo final: script Python funcional para el bot; NO Android ahora.** Codex deberá preguntar solo por información indispensable que no se pueda extraer de los adjuntos.

**No iniciar VER6 dentro de `.sip`. No reutilizar el trabajo experimental del `VER7` de SocksIP ni deducir que VER6 utiliza las mismas claves. Son investigaciones distintas.**
### Prompt corto recomendado para el nuevo chat con Sol

> Usa el conector de GitHub en `Gh0stDeveloper/SP-DECODE` y lee `docs/VER6_NEW_FORMAT_CODEX_HANDOFF.md`. Adjunto la APK original y un archivo de configuración que utiliza **otro formato: VER6 no corresponde a `.sip`**. Analiza el flujo de importación real y crea **únicamente el script Python de descifrado para el bot**, con CLI sin interacción, resultado completo y pruebas con el archivo proporcionado. Conserva los decodificadores anteriores y trabaja en una rama independiente. **No programes Android/Kotlin, no compiles APK y no publiques Releases**; la integración Android la haremos después. Para ahorrar tokens evita explicaciones repetitivas y cambios fuera del alcance, sin inventar métodos ni omitir pruebas.


Como material de ejemplo metodológico, la rama `main` contiene `analysis/SOCKSIP_VER8_VER7_VER6_STUDY.md`, pero ese documento trata de **SocksIP y no describe el nuevo archivo**. Solo consultarlo para observar cómo separar evidencias, no como fuente criptográfica del nuevo objetivo.
