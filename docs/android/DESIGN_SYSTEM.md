# Sistema visual oficial — SP-DECODE Android

> **REQUISITO BLOQUEADO DE PRODUCTO:** conservar el aspecto de la maqueta conceptual aceptada en el chat de proyecto: marca y escudo pequeño, tipografía minimalista, gran panel de importación, tarjetas de resultado, controles Copiar/Exportar y barra inferior de cuatro iconos. El objetivo no es un clon exacto de píxeles de ChatGPT, sino **la misma composición y sensación visual** en Android. Cambios estructurales requieren ADR y aceptación explícita.

## 1. Referencias visuales editables (no son capturas de app real)

- [Pantalla Inicio AMOLED — SVG](design/home-dark.svg)
- [Pantalla Resultado AMOLED — SVG](design/result-dark.svg)
- Su fuente SVG es parte del repositorio y debe preservarse aunque se rediseñe el código de Compose.
- Se prohíben emojis como iconos; utilizar vectores monocromos de Material Symbols o Lucide bajo licencias verificadas.
- En cuanto exista UI ejecutable, producir capturas de emulador con golden screenshot tests y compararlas manualmente con los SVG.

## 2. Identidad y composición

Nombre en barra superior: **SP-DECODE**. Bajada «Decodificador de configuraciones». Símbolo pequeño: escudo con check o marca de código, encajado en contenedor redondeado de 40–44 dp. Fondo pleno casi negro, sin fondos ilustrados ni gradientes saturados. Una sola acción principal en Inicio, visualmente inequívoca. Títulos compactos y campos formateados sin ruido. Estilo cercano a iOS por ritmo y bordes, pero interacción **Android nativa**.

### Tokens de tema oscuro AMOLED (basales)

| Token | Hex | Rol |
|---|---|---|
| background | #080C12 | Fondo app |
| surface | #111821 | Tarjetas, barras |
| surfaceRaised | #18222F | Panel destacado |
| surfaceMuted | #1C2735 | Botón suave |
| outline | #2C394A | Divisores y bordes |
| textPrimary | #F4F7FB | Texto principal |
| textSecondary | #9BA9BC | Etiquetas secundarias |
| textMuted | #728298 | Metadata |
| accent | #8DBBFF | Iconos y CTA selectivos |
| accentSoft | #18314D | Fondo seleccionado |
| success | #70D5A3 | Decodificación verificada |
| warning | #EEC37A | Decoder experimental |
| danger | #F09297 | Fallos y borrado |
| scrim | #000000 | Overlays 55–75% |

**Regla:** la primera referencia conceptual usaba una jerarquía mayoritariamente neutra; usar azules solo como acento muy moderado, no superficies enteras azules. Los fondos siguen el token dark; jamás reemplazar este estilo por pantalla blanca genérica.

### Tema claro

background #F7F9FC, surface #FFFFFF, raised #EEF3F9, outline #DCE4ED, textPrimary #172230, textSecondary #526274, accent #285AA5; confirmar WCAG real y ajustar colores de estado al validar contraste. Respetar modo del sistema; predeterminado oscuro si no hay preferencia, sin forzar AMOLED si el usuario elige claro.

### Tipografía, espaciado, bordes

- Fuente: tipografía nativa sans sin licencias privadas. Comportamiento visual SF-like: trazo limpio, semibold en títulos, line-height amplio, kerning sin estilizaciones excéntricas.
- Display/brand: 22sp / 28sp, semibold. Screen title: 20sp / 26sp. Card title: 16sp / 22sp semibold. Body: 14sp / 20sp. Caption: 12sp / 16sp. Metadata técnica: 12sp monoespaciada solo para payload/JSON.
- Rejilla base **4dp**. Márgenes horizontales **16dp**, separación entre bloques 16–20dp, interior tarjetas 16dp, icon-label 8dp. Separaciones compactas de 8dp en filas.
- Radio de panel principal 24dp; tarjetas 16dp; botones 12–14dp; chips 999dp.
- Punteros/touch: mínimo 48dp. Barra inferior: alto aproximado 68–80dp + safe area system nav, fondo surface, borde superior outline, 4 iconos/etiquetas de igual ancho.
- Animación: press feedback ligero, transiciones 180–260ms, progreso determinista, shimmer solo cuando necesario; desactivar si system reduce motion.
- No aplicar blur costoso bajo cada tarjeta; blur opcional únicamente overlays de modal si supera test de rendimiento.

## 3. Pantalla Inicio: jerarquía congelada

**Orden vertical:** status bar segura → cabecera marca y botón Ajustes → padding 16 → panel Importar (elemento central) → «Recientes» si hay historial → información ligera al pie → navegación inferior fija.

### Cabecera

Icono escudo-check en caja 44×44, a la izquierda. «SP-DECODE» 20–22sp semibold, debajo subtítulo 12sp. A la derecha icono Settings con target 48dp. No usar un hero gigante ni barra de búsqueda dominante.

### Panel principal «Importar configuración»

Panel surfaceRaised radio 24, padding 24dp, centrado, alto variable aprox 190–220dp en 390×844; icono file-up lineal grande (32dp) dentro de círculo/bloque discreto. Título 17sp semibold, descripción en dos líneas centrada 13sp. Botón «Seleccionar archivo» ancho 100% o centrado según anchura, contraste sólido/superficie suave, target ≥48dp. Bajo el panel: atajo «Pegar texto o enlace» discreto y explicación «Procesamiento local · sin conexión» sin prometer capacidad aún no portada.

### Recientes

Máximo 2–3 elementos a primera vista. Cada tarjeta muestra icono archivo, nombre truncado en una línea, formato, fecha, estado. No mostrar claves ni previsualizaciones de contenido. Si no hay historial, bloque vacío compacto.

## 4. Pantalla Resultado: jerarquía congelada

**Orden:** toolbar flecha atrás + «Resultado» + acciones → identificación de archivo (ej. perfil.tls, etiqueta Decodificado) → filas «Formato», «Servidor», «Puerto», «Contraseña» (si corresponde) → secciones dinámicas del decoder → panel «Texto original» colapsable → barra de acciones «Copiar» y «Exportar», con «Compartir» adicional. Los campos en las maquetas son **ejemplos sintéticos**, no el resultado real de un archivo.

- Card con borde outline suave, fondo surface, radio 16, padding 16.
- Etiquetas a izquierda en gris, valores a derecha en blanco y monoespaciado opcional si técnico; permitir wrap para cadenas largas.
- Credenciales/secretos como bullets (••••••••) inicialmente, icono ojo accesible; el ojo revela temporalmente, al perder foco/reabrir se oculta.
- Estado superior con chip green success **solo cuando el decoder fue verificado y resultado válido**. Los experimentales usan advertencia y texto informativo, no falso éxito.
- Dos acciones de tamaño homogéneo: Copiar · Exportar. Compatibles con scroll y teclado; no tapar contenido.
- Error: sustituir chip éxito por advertencia/danger, mostrar descripción y detalle técnico opcional sanitizado; no renderizar datos falsos.

## 5. Pantalla Historial

Título «Historial», icono búsqueda compacto expandible, filtro chips «Todos / Favoritos / Recientes», entradas por día con formato y estado. Selección múltiple mediante pulsación larga. CTA borrar requiere confirmación; estado vacío coherente con Inicio. Almacenamiento cifrado sin revelar contraseñas en lista.

## 6. Pantalla Formatos

Búsqueda compacta, lista agrupada por aplicación o alfabética, chip de estado (Verificado / Experimental / No verificado / No disponible), sufijos en monoespaciado. Mostrar **59 registradas** como conteo, pero «verificadas» es un contador separado que nunca se autoincrementa con el registro.

## 7. Pantalla Ajustes

Secciones compactas: Apariencia (tema claro/oscuro/sistema), Privacidad (ocultar secretos por defecto, guardar historial), Almacenamiento (limpiar, retención), Idioma, Acerca de, versión. Ningún ajuste de bot, token, servidor, grupo ni login.

## 8. Componentes Compose sugeridos

- SpDecodeScaffold, BrandTopBar, BottomNav, ImportHeroCard, RecentFileRow, ResultHeader, ResultFieldRow, SecureValue, ActionPill, DecoderStatusChip, EmptyState, ProgressSheet, ErrorDetailSheet, ConfirmationDialog, FormatListItem.
- Tokens consolidados en SpDecodeTheme + ColorTokens + ShapeTokens + TypeTokens + Spacing; evitar colores hardcodeados en screens.
- Íconos: ShieldCheck, Settings2, FileUp, FileCheck2, Copy, Download, House, History, FileCode2, ArrowLeft, Eye/EyeOff, Search, Star, Share2, Trash2. Preferencia de diseño: **solo iconos, sin emojis**.
- Los botones y chips usan semántica de Compose para TalkBack; no usar únicamente color para estados.
- El diseño nunca debe requerir conexión de red o imagen remota: iconos y recursos se empaquetan.

## 9. Breakpoints y accesibilidad

- Diseño optimizado para teléfonos **320–430dp**; también debe escalar a >= 600dp sin desbordarse. No bloquear tablet artificialmente; priorizar columna centrada de maxWidth 560dp.
- Respetar WindowInsets: barra de estado, notch, navegación gestual, teclado. Resultado scrollable.
- Texto escalado a 200% debe conservar controles y contenido legibles; si no caben cuatro labels en bottom bar, compactar espacios sin ocultar destinos.
- Contraste: texto normal 4.5:1 objetivo WCAG AA, iconos y controles 3:1, foco y targets de 48dp.
- Modo landscape se prueba al menos para apertura externa/resultado, aun si la estética principal es portrait.

## 10. Internacionalización visual obligatoria

La app admite **español, inglés, portugués brasileño y árabe**. El diseño aprobado no se sustituye: la maqueta SVG está en español LTR y actúa como referencia visual canónica. En árabe se invierte el flujo de la **interfaz** RTL (cabecera, navegación, botones direccionales, orden y alineaciones) con los mismos tokens AMOLED, radios, tarjeta hero y barra inferior de cuatro destinos; el **resultado original del decoder no se traduce ni se reordena** y sus bloques técnicos se presentan LTR/aislados. Los textos largos árabes y portugueses usan disposición flexible sin cortar botones. La pantalla en árabe requiere capturas golden propias. Ver [LOCALIZATION.md](LOCALIZATION.md).

## 10. Animación y microinteracciones

Importación: el botón responde de inmediato; modal/sheet inferior de progreso con nombre truncado + etapa («Leyendo», «Detectando formato», «Decodificando», «Preparando resultado»). Éxito con transición corta a Resultado; fallo muestra causa. Copiar: snackbar «Copiado» solo después de acción completa; exportación: snackbar «Archivo guardado» únicamente tras confirmación positiva del proveedor.

## 11. Golden visual DoD

Para declarar UI fiel:
1. Capturas reales de Inicio, Resultado, Historial, Formatos y Ajustes en 360×800dp y 393×852dp, modo oscuro.
2. Contrastar cabecera, hero, tarjeta de resultados, botones Copiar/Exportar y barra inferior con SVG de referencia; registrar discrepancias.
3. Probar claro, AMOLED, fuentes grandes, pantalla compacta, TalkBack y teclado.
4. No entregar pantalla vacía de plantilla Compose ni placeholders como si fuesen datos reales.
5. Los cambios visuales se revisan por PR con capturas y nota de diseño. Esta especificación gobierna incluso al reanudar en otro chat.

