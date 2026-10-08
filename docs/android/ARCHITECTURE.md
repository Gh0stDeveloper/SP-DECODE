# Arquitectura oficial — Android offline

## 1. Arquitectura hexagonal por capas

**Implementación propuesta:** Kotlin + Jetpack Compose + Navigation Compose + Coroutines/Flow, ViewModel, Room y DataStore. El motor es un conjunto de adaptadores embebidos y **no un servidor local**. Estandarizar interfaces entre Kotlin y Python evita vincular UI a scripts particulares.

~~~mermaid
flowchart TB
    A["System Picker / ACTION_VIEW / ACTION_SEND / Entrada de texto"] --> B["Android UI: Compose + ViewModel"]
    B --> C["ImportUseCase / DecodeUseCase / ExportUseCase"]
    C --> D["InputResolver: ContentResolver + límites"]
    D --> E["FormatDetector + DecoderRegistry"]
    E --> F{"Runtime local"}
    F --> G["Python Adapter (Chaquopy, pendiente validación ABI/wheels)"]
    F --> H["Kotlin/JS port Adapter"]
    F --> I["Kotlin/Python port de PHP"]
    G --> J["DecodeResult normalizado"]
    H --> J
    I --> J
    J --> K["Resultado Compose"]
    J --> L["HistoryRepository + Room (cifrado de payloads)"]
    K --> M["SAF Export / Sharesheet / Clipboard"]
    L --> K
~~~

**Prohibido:** HTTP fallback, conexión con el bot, ejecución shell que asuma Termux/Node/PHP, solicitudes de permisos de almacenamiento total, extracción de archivos de otra app mediante root y descarga dinámica de algoritmos.

## 2. Estructura del repositorio

Mantener sin alterar spdecode/ y decoders/ hasta que se formalice la compartición. Crear directorio nuevo **android/** dentro del repositorio existente:

~~~text
SP-DECODE/
├── main.py                         # Bot Telegram (sin cambios de conducta)
├── decoders.json                   # Registro canónico existente
├── decoders/{Python,JavaScript,PHP}
├── tests/
├── docs/android/                   # ESTA DOCUMENTACIÓN
└── android/                        # A CREAR EN FASE B
    ├── settings.gradle.kts
    ├── build.gradle.kts
    ├── gradle/libs.versions.toml
    ├── gradle/wrapper/
    ├── app/
    │   ├── build.gradle.kts
    │   └── src/main/
    │       ├── AndroidManifest.xml
    │       ├── java/com/ghostdeveloper/spdecode/
    │       │   ├── MainActivity.kt
    │       │   ├── core/{model,registry,decode,importer,security,export}
    │       │   ├── data/{room,preferences,repositories}
    │       │   ├── ui/{theme,components,navigation,screens}
    │       │   └── di/
    │       ├── python/             # Bridges Python empaquetados y dependencias compatibles
    │       └── res/{values,values-es,drawable,mipmap-*}
    ├── decoder-catalog/            # Registro generado + pruebas de consistencia
    ├── test-fixtures/              # Únicamente casos artificiales/sanitizados
    └── README.md
~~~

**Nota técnica:** para integrar Chaquopy la ubicación exacta del plugin se decidirá según la restricción de **un solo módulo por aplicación**. Puede instalarse en app o un library module, pero no en múltiples módulos simultáneamente. No fijar versiones AGP/Kotlin/Chaquopy incompatibles.

## 3. Contratos entre capas

**DecoderDescriptor**
- id, publicName, suffixes[], algorithmVersion, originRuntime (python/node/php), androidEngine (python/ported-kotlin/unsupported), status (registered, porting, experimental, verified, disabled), minExpectedSize, maxInputBytes, supportsTextScheme, supportedSchemes[], compatibilityNotes.
- Los sufijos (incluidos compuestos) son case-insensitive Unicode normalizados; **nunca confiar solo en extensión** para interpretar contenido como seguro.
- La lista se genera de decoders.json y se completa con un catálogo de overrides Android; validar que todo sufijo del registro esté inventariado.

**DecodeRequest**
- requestId aleatorio, sourceName saneado, extension resuelta, inputSource (Content URI o texto), bytes contenidos/canal de lectura, cancelation flag, deadline.
- Content URI se lee con ContentResolver.openInputStream; no convertir content:// a File usando «real path».
- Bytes en memoria con cota; streams/temporales solo dentro del sandbox; limpiar en finally.

**DecodeResult**
- status enum: success / partial / unsupported / invalid_input / dependency_error / timeout / cancelled / internal_error.
- decoderId + algorithmVersion + elapsedMs + source metadata.
- rawText, structuredFields[] (key,label,value,sensitivity,originalOrder), warnings[], safeErrorCode.
- **success** exige datos sustantivos y validación de salida. «El script imprimió texto» NO basta; algunos scripts imprimen errores por stdout.
- No transformar silenciosamente textos con JSON embebido: conservar rawText byte/character faithful tanto como sea viable y renderizar campos sin reordenar.
- Sensitivity = secret / sensitive / public para controlar copia, guardado y reveal.

**DecodingService.decode(DecodeRequest): DecodeResult** es la única API de dominio para UI; se ejecuta fuera del hilo principal, expone Flow de estados e interrumpe cooperativamente cuando es posible. Un decoder no cooperativo se aísla según límites disponibles; nunca prometer corte forzoso de un thread Python que no lo permite.

## 4. Diseño de motor y adaptadores

1. **RegistrySync:** leer decoders.json en build, generar catalog.json de Android; CI falla ante divergencia de sufijos o rutas.
2. **FormatDetector:** coincidir sufijos ordenados por longitud, distinguir «registrado» de «verificado», comprobar tamaño/MIME/signatura cuando exista.
3. **ExecutionRouter:** mapear ID → adaptador offline; no cargar archivos fuera del directorio empaquetado.
4. **PythonAdapter:** primer prototipo Chaquopy; hacer puente a funciones run(bytes) cuando existan. Los scripts CLI antiguos necesitan refactor a función pura con parámetros explícitos; evitar modificar su comportamiento del bot sin tests.
5. **NodeAdapter/PortedDecoder:** 6 scripts JS distintos mapeados a 8 sufijos; portar crypto (AES/TEA/XOR/Base64), fs, Buffer y argument parsing, con vectores cruzados bit a bit; no ejecutar un Node global ni instalar por Termux.
6. **PHPAdapter/PortedDecoder:** 3 scripts PHP; portar AES/OpenSSL, manejo de JSON y bytes a Kotlin/Python validando padding y orden de bytes.
7. **OutputNormalizer:** reconocer salida JSON cuando sea JSON válido; para formatos legado preservar vista «Texto original» y aplicar parsing conservador, sin inventar campos.
8. **TestHarness:** archivo fixture → salida esperada (golden) → salida Android, comparación normalizada y assertions de campos relevantes.

**Casos especiales:** decoders que acceden a archivos relativos como nodehat.json o cfg/keyFile.json deberán recibir dependencias read-only empaquetadas mediante AssetResolver; revisar licencia y secretos. El código legado puede contener claves de descifrado: un APK no ofrece confidencialidad de constantes embebidas. No enviar ninguna credencial privada de servicio a los assets.

### Elección de Python y ABI

Documentación oficial: https://chaquo.com/chaquopy/doc/current/android.html. Al documentar, Chaquopy 17.0 exige minSdk ≥ 24, se instala solo en un módulo, soporta Python 3.10–3.14 con combinaciones distintas de ABIs; Python 3.12+ solo 64 bits. **No adoptar ninguna versión como definitiva** hasta comprobar wheels para pycryptodome, argon2-cffi, msgpack y compatibilidad con páginas de memoria de 16 KB en dispositivos arm64 modernos.

Prototipo recomendado: Python 3.11 o 3.13 **según wheel/16 KB smoke test**, arm64-v8a de inicio y x86_64 para instrumentación. Si una librería no tiene wheel Android compatible, portar ese algoritmo o generar wheel reproducible; no degradar offline ni usar servicios.

## 5. Pipeline de importación

~~~mermaid
sequenceDiagram
    actor User as Usuario
    participant UI as Compose
    participant SAF as Android SAF
    participant IR as ImportRepository
    participant DR as DecodeUseCase
    participant DB as Room
    User->>UI: Toca "Importar"
    UI->>SAF: ACTION_OPEN_DOCUMENT
    SAF-->>UI: content:// URI temporal / acceso autorizado
    UI->>IR: abrir stream con ContentResolver
    IR->>IR: cotejar tamaño, límite, nombre y sufijo
    IR->>DR: bytes/canal seguro + metadata
    DR->>DR: resolver decoder local y ejecutar
    DR-->>UI: Result(status, fields, rawText)
    DR->>DB: guardar resultado solo si usuario lo permite
    UI-->>User: Tarjetas + texto crudo + acciones
~~~

- SAF ACTION_OPEN_DOCUMENT para importar; ACTION_CREATE_DOCUMENT para exportar. El método de compartir externo puede entregar URI con permiso transitorio: procesar dentro del tiempo del grant. Para reabrir el contenido original, solicitar persistencia de lectura solo cuando corresponda y manejar proveedores que no la ofrezcan.
- Manifest incluir intent filters para ACTION_VIEW, ACTION_SEND y ACTION_SEND_MULTIPLE según MIME y extensiones soportadas. Android no garantiza filtrado de todos los sufijos mediante MIME, por eso usar selector general y validar internamente.
- Debounce de intents y requestId impide que la misma importación se ejecute dos veces por cambio de Activity.
- Multiples: cola secuencial por defecto con botón cancelar, paralelismo limitado tras benchmarking; no saturar memoria.

## 6. Persistencia y retención

**Room**
- history_records(id UUID, createdAt, updatedAt, filenameRedacted?, suffix, decoderId, decoderVersion, status, favorite, durationMs, encryptedPayload, payloadNonce, payloadSchemaVersion, fileDigest).
- Un payload contiene rawText + structuredFields + warnings; cifrado por registro con AES-GCM usando clave administrada por Android Keystore y AAD que vincula id + schemaVersion.
- Filtrar con metadatos no secretos; evitar indexar texto descifrado/contraseñas en FTS claro. De ser necesaria búsqueda por contenido, realizarla sobre datos descifrados **en memoria** de forma acotada, nunca sobre una FTS sin cifrar.
- Términos exactos de búsqueda por nombre/extension y fechas; opción desactivar historial, borrar individual/todo y política de retención.
- Backups Android excluyen Room/history y secretos, o se desactivan completamente; no exportar claves de Keystore.

**DataStore:** themeMode, hideSensitive=true, saveHistory=true (valor inicial sujeto a consentimiento UX), retentionDays, reduceMotion, lastSelectedTab. El idioma se gestiona mediante la API oficial de idioma por aplicación/AndroidX AppCompat (**fuente única de verdad**, con persistencia compatible según SDK); no duplicarlo en un campo language de DataStore sin migración explícita. Jamás almacenar credenciales crudas en preferencias.

**Clipboard/export:** censura de campos secret por defecto, confirmación para datos crudos, limpiar portapapeles bajo políticas Android si técnicamente posible sin garantías; no garantizar que otra app no vea datos que el usuario decidió compartir.

## 7. Manifest y construcción

- Permisos solicitados: ninguno de red; NO INTERNET, ACCESS_NETWORK_STATE, READ/WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE ni QUERY_ALL_PACKAGES.
- Prohibir providers exportados que expongan DB o assets; FileProvider configurado solo si realmente se comparte archivo con URI temporal.
- android:allowBackup=false o reglas explícitas que excluyan datos descifrados; android:usesCleartextTraffic=false. Audit de **manifest combinado** en CI para detectar permisos añadidos por librerías.
- Package ID inicial sugerido: com.ghostdeveloper.spdecode (reservar y comprobar disponibilidad antes de publicar).
- Gradle reproducible mediante wrapper versionado y dependency locking/verification; debug vs release, ABI splits o AAB en Play, APK arm64 firmada para GitHub.
- Versionar sample fixture con datos sintéticos, jamás credenciales de producción.

## 8. Localización de UI sin mutar DecodeResult

- **Solo UI** en es/en/pt-BR/ar; recursos locales `values/strings.xml` (en por defecto), `values-es`, `values-pt-rBR`, `values-ar` y `plurals`/accesibilidad. No servicios de traducción.
- Selector Sistema/4 idiomas desde Ajustes y preferencias de idioma en Android 13+; en Android 7–12 compatibilidad AndroidX AppCompat según documentación oficial, sin duplicar preferencia con DataStore. Configuración RTL habilitada para árabe.
- El traductor de cadenas de Compose usa `stringResource` exclusivamente para textos de interfaz. **`DecodeResult.rawText`, `originalKey`, `originalLabel` y `rawValue` nunca pasan por traductor**; persistencia, clipboard y exportación original conservan contenido sin mutaciones (máscaras censuradas solo como opción separada).
- Pantalla técnica en árabe: `LayoutDirection.Ltr` / dirección del texto LTR en regiones de raw text, JSON, URLs/IP/dominios/código; aislamiento bidi visual sin insertar marcas Unicode en el dato. Resto de UI RTL con start/end en lugar de left/right.
- El cambio de locale puede recrear Activity: conservar sesión y resultados en ViewModel/estado. Pruebas de invariancia de resultado al alternar los cuatro idiomas.
- Fuente de verdad de alcance, cadenas y aceptación: [LOCALIZATION.md](LOCALIZATION.md).

## 9. Dependencias entre componentes / aislamiento

Compose depende de use cases y models; dominios no dependen de Android UI. Registry conoce solo manifest y assets. ImportRepository usa ContentResolver. DecodeUseCase no conoce Telegram ni Room. RoomRepository solo persiste tipos serializados. Compartir y exportar son adaptadores Android, no lógica de decoder.

## 10. Observabilidad sin conexión

Un panel local opt-in de diagnósticos puede mostrar duración, decoder, status y versión; **nunca contenido descifrado, bytes originales, token ni trazas que incluyan secretos**. Exportación manual de diagnóstico genera exclusivamente versión, dispositivo genérico y códigos sanitizados. Ninguna petición de soporte automática.

## 11. Riesgos de arquitectura

- Falla de wheels ARM/16 KB → probar temprano y portar primitivas.
- Scripts dependientes de cwd, subprocess o red → refactor a funciones puras.
- Resultados texto libre/error mezclados → comprobación semántica/golden fixtures.
- Claves estáticas embebidas → auditarlas: extracción del APK es siempre posible.
- Coste de almacenamiento historial → cuota/retención; cifrado; limpieza segura en medida que ofrezca Android.
- Registro del bot evoluciona → generación automática y fail CI ante drift.

## 12. Referencias

- Android Storage Access Framework: https://developer.android.com/guide/topics/providers/document-provider
- Android intents comunes: https://developer.android.com/guide/components/intents-common
- Arquitectura moderna Android: https://developer.android.com/topic/architecture
- Android Room: https://developer.android.com/training/data-storage/room
- Chaquopy: https://chaquo.com/chaquopy/doc/current/android.html

