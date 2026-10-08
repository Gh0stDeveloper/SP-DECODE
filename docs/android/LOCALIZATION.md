# Localización e idiomas oficiales — SP-DECODE Android

> **Decisión de producto, 2026-10-08.** Solo se traduce **la interfaz Android**; **jamás** se traduce, se modifica o se reescribe automáticamente el resultado que producen los decodificadores. La aplicación sigue siendo 100 % offline, sin cuenta, sin Telegram y sin conexión.

## 1. Alcance de lanzamiento (4 idiomas de interfaz)

| Código BCP 47 | Nombre visible en selector | Sentido de lectura UI | Estado de producto |
|---|---|---|---|
| \`es\` (español; redacción es-419) | Español | Izquierda a derecha (LTR) | Obligatorio |
| \`en\` | English | LTR | Obligatorio; fallback predeterminado |
| \`pt-BR\` | Português (Brasil) | LTR | Obligatorio; audiencia lusófona |
| \`ar\` | العربية | Derecha a izquierda (RTL) | Obligatorio |

El idioma de las pantallas se determina por **Preferencia del sistema** (por defecto) o por elección explícita del usuario en **Ajustes → Idioma**. El selector debe mostrar los cuatro nombres autóctonos y la opción **Usar idioma del dispositivo**. Si el idioma del sistema no está disponible, la interfaz utiliza inglés. Si el idioma del sistema es portugués de otra región, se puede resolver a pt-BR conforme a una política de coincidencia probada; español regional se resuelve a es. Nunca cambiar los campos descifrados por el idioma del sistema.

**Sin descargas de idiomas:** todos los textos y recursos necesarios están empaquetados en la APK; los cambios de idioma deben funcionar en modo avión desde la primera ejecución.

## 2. Frontera innegociable: app localizada ≠ resultado traducido

**Se localiza la interfaz**, incluyendo:
- títulos de pantallas, botones, barra inferior, filtros, mensajes vacíos, diálogos, confirmaciones, errores de la aplicación, progreso, ajustes, accesibilidad/TalkBack, fechas y unidades de la interfaz;
- mensajes **generados por la app**: «Archivo no soportado», «Copiado», «No se pudo leer», «Formato detectado», etc.;
- etiquetas **propias de la UI**, por ejemplo «Nombre del archivo», «Formato», «Historial», «Exportar», siempre que no sean claves del resultado original.

**No se localiza ni se reescribe el resultado del motor**, incluyendo:
- \`rawText\` del decodificador, texto heredado, banners, ASCII art, etiquetas como \`SSH Host\`, \`Payload\`, \`Server\`, \`Password\` y el JSON devuelto por los scripts;
- nombres y valores de campos producidos por el algoritmo, estructuras \`JSON\`, campos internos, URLs, payloads, nombres de host, tokens, credenciales y sus identificadores;
- TXT/JSON exportados a partir del resultado bruto, ni el contenido copiado explícitamente como resultado original.

**Ejemplo:** con la aplicación en árabe, el título de la pantalla debe verse como «النتيجة», el botón como «نسخ», pero dentro de la tarjeta del decoder se conserva literalmente \`SSH Host: example.com\`. Con la app en español, el motor continúa entregando \`SSH Host: example.com\` y no \`Servidor SSH: example.com\`. Si el script produce caracteres Unicode propios, tampoco se traducen.

**Salida original:** existe un campo inmutable \`rawText\` (protegido/cifrado en historial) que la UI solo interpreta para visualización. La copia/exportación bruta debe preservar su cadena, espacios, orden, saltos de línea, claves y valores; redactar secretos es **una acción de privacidad independiente** y explícita, etiquetada como versión censurada. No alterar el resultado guardado bajo la excusa de localizarlo.

**Campos estructurados:** conservar \`originalKey\` / \`originalLabel\` / \`rawValue\` del decoder. Las claves de datos nunca se buscan en \`strings.xml\`. Las etiquetas añadidas por la aplicación alrededor de estos campos pueden ser locales; distinguir la capa de presentación del payload. No modificar salida porque un parser haya identificado un \`password\`.

## 3. Arquitectura Android para la localización

- Usar Android **String Resources** para toda cadena visible: \`res/values/strings.xml\` (inglés por defecto), \`res/values-es/strings.xml\`, \`res/values-pt-rBR/strings.xml\`, \`res/values-ar/strings.xml\`. Es-419 puede añadirse con \`values-b+es+419\` si se decide diferenciarlo de es genérico; no crear variantes vacías.
- También traducir \`plurals\`, nombres de menú, etiquetas de acceso y \`contentDescription\`, confirmaciones y textos de error. Las cadenas \`@string\` deben ser el único origen de textos de UI; Compose usa \`stringResource\` y \`pluralStringResource\` cuando proceda.
- En Android 13+ habilitar idioma por aplicación en Ajustes del sistema mediante \`LocaleConfig\` generado por AGP cuando la configuración de build lo permita; limitar idiomas anunciados a los realmente completos.
- Selector en Ajustes: preferir API AndroidX \`AppCompatDelegate.setApplicationLocales(LocaleListCompat)\` con \`AppCompatActivity\` donde corresponda; soporta compatibilidad con Android 12 e inferiores (minSdk preliminar 24). Selección «Sistema» equivale a lista vacía.
- **Fuente única de preferencias:** usar el mecanismo oficial de AppCompat/Android para la selección del idioma; no mantener dos fuentes independientes en DataStore. En Android 12 o anterior decidir entre \`autoStoreLocales\` de AppCompat o un almacenamiento propio con restauración previa a \`onCreate\`, documentado y probado. DataStore puede guardar otros ajustes (tema, privacidad, historial).
- Cambiar idioma en la app actualizará toda la UI y los mensajes del sistema gestionados por la aplicación; tolerar recreación de Activity sin perder archivo importado, progreso ni resultado, usando ViewModel/estado persistente.
- Fechas y números **de la UI** respetan Locale; cifras/puertos/cadenas del decoder permanecen sin modificar.
- Los nombres de archivo importados se preservan con Unicode original. No traducir marcas, extensiones, nombres de programas ni valores del decoder.
- Impedir traducciones externas automáticas o llamadas a motores de traducción (incluido ML/cloud). La localización es un conjunto de recursos estáticos revisados.

Referencias Android oficiales: https://developer.android.com/guide/topics/resources/app-languages y https://developer.android.com/develop/ui/compose/text/fonts. Verificar compatibilidad real del paquete de AndroidX antes de fijar versiones Gradle.

## 4. Soporte árabe RTL sin dañar la salida

- Habilitar \`android:supportsRtl="true"\` en el manifest cuando se implemente B.1; usar \`start/end\`, \`Alignment.Start/End\`, \`Arrangement.Start/End\` y layouts semánticos (no \`left/right\` salvo contenido bruto).
- En árabe, espejar donde corresponda la estructura de cabecera, contenedores, botones de navegación, back arrows y menú inferior; mantener exactamente las cuatro pestañas del diseño aprobado. No espejar indiscriminadamente iconos sin direccionalidad (copiar, archivo, candado, escudo).
- El **panel que contiene el resultado decodificado no debe reordenar el texto técnico**. Renderizar \`rawText\`, consola, JSON y strings técnicas en un contenedor o \`TextStyle\` de dirección LTR explícita; mantener secuencia lógica original. Para contenido mezclado aplicar aislamiento bidi en visualización sin insertar marcas Unicode en el dato almacenado/exportado.
- Direcciones IP, dominios, correos, URIs, puertos, hashes, rutas de archivos, payloads y código se visualizan como fragmentos LTR **incluso si la UI está en árabe**. Cadenas largas deben hacer wrap/scroll horizontal según componente, evitando corte de datos.
- Las maquetas SVG en docs/android/design/home-dark.svg y result-dark.svg **son el baseline visual LTR**, no deben sobrescribirse. Crear capturas golden de Compose en árabe (RTL) con el mismo estilo AMOLED; conservar la composición relativa de paneles, contraste, bordes, dimensiones y categorías de acciones.
- Usar una fuente del sistema con glifos árabes completos; **no forzar una fuente decorativa incompatible**. Ajustar altura de línea, ligaduras, diacríticos, alineación y truncamiento; verificar árabe largo y TalkBack árabe.
- Textos de la interfaz se muestran en árabe auténtico; no mezclar inglés en encabezados por falta de recursos (salvo marcas/nombres propios), y no se permite un estado «traducido» en UI si quedan cadenas clave en inglés.
- Valorar variantes de numerales en la UI según Locale, **jamás** modificar valores de resultado.

## 5. Glosario UI (ejemplos normativos, no resultado)

| Clave de UI | Español | English | Português (Brasil) | العربية |
|---|---|---|---|---|
| nav_home | Inicio | Home | Início | الرئيسية |
| nav_history | Historial | History | Histórico | السجل |
| nav_formats | Formatos | Formats | Formatos | الصيغ |
| nav_settings | Ajustes | Settings | Configurações | الإعدادات |
| import_title | Importar configuración | Import configuration | Importar configuração | استيراد إعدادات |
| select_file | Seleccionar archivo | Select file | Selecionar arquivo | اختيار ملف |
| result_title | Resultado | Result | Resultado | النتيجة |
| copy | Copiar | Copy | Copiar | نسخ |
| export | Exportar | Export | Exportar | تصدير |
| share | Compartir | Share | Compartilhar | مشاركة |
| favorites | Favoritos | Favorites | Favoritos | المفضلة |
| language | Idioma | Language | Idioma | اللغة |
| use_device_language | Usar idioma del dispositivo | Use device language | Usar idioma do dispositivo | استخدام لغة الجهاز |
| processing | Procesando… | Processing… | Processando… | جارٍ المعالجة… |
| unsupported_file | Formato no compatible | Unsupported format | Formato não compatível | صيغة غير مدعومة |
| hidden_secret | Oculto | Hidden | Oculto | مخفي |
| raw_result | Texto original | Original text | Texto original | النص الأصلي |

Este glosario define intención y términos; la traducción definitiva deberá revisarse en contexto por hablantes competentes, especialmente árabe y portugués. No copiar estas claves como \`rawText\` del decoder.

## 6. UX e independencia del diseño

- Encabezado con escudo, hero de importación, tarjetas de resultado y barra inferior de cuatro destinos **no se cambian**; solo se ajusta alineación/dirección al idioma.
- Si un texto en portugués o árabe ocupa más espacio, usar límites flexibles, auto-height, wrap, tipografía dinámica y \`maxLines\` justificadas; nunca cortar CTA principal.
- Estatus/avisos, filtro de búsqueda, Snackbar, errores SAF, confirmación de borrado, descripciones de TalkBack y mensajes de exportación deben tener cobertura en las cuatro lenguas.
- Cambiar idioma no puede borrar historial, alterar archivos o reiniciar un proceso de descifrado de modo destructivo.
- La pantalla Resultado, con independencia del locale, conserva exactamente la cadena generada por el script; cualquier transformación de visualización se limita a la presentación.
- No se requieren paquetes de idioma descargados ni privilegios adicionales para RTL.

## 7. Pruebas de aceptación y puerta de release

1. Las cuatro lenguas tienen recursos completos para todas las claves de UI (incluyendo pluralización/placeholders), sin textos críticos hardcodeados en Compose.
2. Selector «Sistema / Español / English / Português (Brasil) / العربية» funciona en modo avión; persiste tras relanzar, reiniciar Activity, cambio de sistema y process death.
3. En Android 13+, idioma de la app aparece en Ajustes del sistema; en Android 7–12 cambio desde el selector integrado funciona sin red.
4. Revisar cinco pantallas principales y todos los estados modales en las cuatro lenguas; probar anchuras 320/360/393dp, 200 % font, TalkBack y paisaje.
5. Capturas golden LTR para español/inglés/portugués y **RTL árabe**; verificar hero, resultado, CTA, bottom bar y visual fidelity con SVG baseline.
6. Prueba de paridad del motor: mismo fixture, resultado de \`rawText\` idéntico al alternar entre es/en/pt-BR/ar; mismos bytes al exportar salida original según codificación UTF-8 definida por el proyecto.
7. Test bidi: cadenas \`SSH Host: example.com:443\`, \`vmess://...\`, JSON anidado, \`example@host\`, IPv6 y nombres Unicode se ven en orden correcto en contexto RTL, sin mutar \`rawText\`.
8. Las traducciones se cargan únicamente de assets locales; sin INTERNET/SDK de traducción, sin peticiones remotas.
9. No declarar F.5 ni H.2 cerradas sin evidencias de QA locales y revisión lingüística.

## 8. Registro de alcance y futuras lenguas

Cuatro idiomas obligatorios en v1.0: es, en, pt-BR y ar. Nuevos idiomas requieren traducción completa de la interfaz y QA. **Nunca se extiende la localización a resultados de decodificadores sin una decisión explícita nueva del propietario del producto** y, aun así, siempre se preservaría la salida original sin modificar.

