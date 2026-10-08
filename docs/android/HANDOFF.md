# Continuidad del proyecto entre chats — NO PERDER LA UI

Este archivo es el punto de entrada para reanudar SP-DECODE Android en otro chat o tras perder contexto. **GitHub es la fuente durable**, no la memoria del chat.

## Identidad y decisiones que nunca se deben perder

- Repositorio: https://github.com/Gh0stDeveloper/SP-DECODE
- Producto: SP-DECODE Android; APK nativa Kotlin + Compose, totalmente offline, no login, no cuenta, no Telegram, no tokens, no VPS y sin permiso INTERNET.
- El bot existente se preserva sin cambios funcionales.
- **Diseño visual aceptado:** cabecera con escudo y nombre SP-DECODE, panel grande central «Importar configuración», sección Resultado con campos legibles y secretos ocultos, acciones Copiar/Exportar, navegación inferior **Inicio · Historial · Formatos · Ajustes**, modo AMOLED, tarjetas suaves, tipografía limpia y SOLO ICONOS sin emojis.
- Fuente visual: docs/android/DESIGN_SYSTEM.md, docs/android/design/home-dark.svg, docs/android/design/result-dark.svg. Las maquetas son referencias editables, NO screenshots de APK.
- Los 59 sufijos del registro son solo inventario, no prueba de funcionamiento actual.
- **Multidioma obligatorio en la interfaz**: español, inglés, portugués brasileño y árabe, con RTL para árabe. **Los resultados, campos, claves y texto original de los decodificadores NO se traducen**, aunque la UI se muestre en cualquier idioma. Véase docs/android/LOCALIZATION.md. Nunca perder este requisito en otro chat.

## Orden de recuperación (obligatorio)

1. Usar conector GitHub, revisar main y PRs/ramas Android abiertos.
2. Leer docs/android/README.md, PRODUCT_REQUIREMENTS.md, DESIGN_SYSTEM.md, ARCHITECTURE.md, DECODER_MATRIX.md, SECURITY_AND_QA.md, ROADMAP.md, ADR.md, status.json y este HANDOFF.md.
3. Mirar commits/runs de CI. Distinguir documentado / implementado / probado / publicado.
4. Identificar primera subfase realmente pendiente en ROADMAP. No reabrir fases cerradas salvo defectos.
5. Trabajar en rama y PR; no reescribir main ni lógica del bot innecesariamente.
6. Al cerrar cada subfase, actualizar status.json, HANDOFF.md y matriz de formatos. Adjuntar SHA, links, checks, pruebas, estado y siguiente tarea.
7. Comparar pantallas Compose reales con los SVG y los tokens. Si diseño o condición offline van a cambiar, obtener aprobación explícita y dejar ADR.

## Estado inicial verificable (2026-10-08)

- Proyecto Android: **NO implementado**.
- APK: **NO generada**.
- A.1, A.3, A.4, A.5 y A.6: especificaciones redactadas.
- A.2: conteo y matriz generados; **pendiente auditoría funcional real y fixtures de los 48 scripts**.
- B, C, D, E, F, G, H: sin iniciar.
- Formatos: 59 sufijos (48 Python, 8 Node, 3 PHP); scripts distintos 39 Python + 6 JS + 3 PHP.
- Todos los 59 formatos Android: «no verificado». No se han probado wheels nativos, ABI o compilación.
- CI de la rama main existente: validate.yml del bot. No workflow Android.
- Rama fundacional de documentación: docs/android-offline-architecture. Cuando se fusione, main pasa a ser referencia para cualquier nuevo chat.

## Formato obligatorio de actualización

~~~text
Fecha:
Subfase:
Rama / PR / SHA:
Cambios realizados:
Tests ejecutados y resultados:
Runs de CI (URL y estado):
Dispositivos/ABI comprobados:
Sufijos realmente verificados:
Comparación visual contra SVG:
Defectos/riesgos:
Decisión ADR (si aplica):
Estado: not_started | in_progress | blocked | complete | verified
Próximo trabajo:
~~~

No asegurar que una fase está cerrada sin evidencias de tests pertinentes. No asegurar que «todo está success» sin consultar el CI.

## Prompt exacto para un nuevo chat

~~~text
Continúa el proyecto Gh0stDeveloper/SP-DECODE, producto SP-DECODE Android.
Utiliza el conector de GitHub para consultar main, PRs y ramas Android.
Lee TODOS los archivos de docs/android/, especialmente README.md,
DESIGN_SYSTEM.md, LOCALIZATION.md, ARCHITECTURE.md, PRODUCT_REQUIREMENTS.md,
DECODER_MATRIX.md, ROADMAP.md, SECURITY_AND_QA.md, ADR.md,
HANDOFF.md, LOCALIZATION.md y status.json. Interfaz traducida en es/en/pt-BR/ar; árabe con RTL; **resultado de decodificadores sin traducir ni modificar**. Conserva EXACTAMENTE el concepto visual
aprobado y las maquetas docs/android/design/home-dark.svg y
docs/android/design/result-dark.svg; no cambies el diseño sin ADR.
App Kotlin+Jetpack Compose 100 % offline, sin login, Telegram,
backend, Termux ni permiso INTERNET. Conserva el bot actual.
Separa «registrado» de «verificado» para los 59 formatos.
Identifica la última subfase comprobada y continúa estrictamente
con la siguiente, en rama/PR, con pruebas y actualización de
docs/android/HANDOFF.md y status.json. Dime primero el estado real.
~~~

## Reglas de memoria visual

No sustituir el tema oscuro por Material 3 default. No cambiar la barra inferior de cuatro destinos. No reemplazar panel hero por lista genérica. No poner credenciales visibles por defecto. El diseño visual es una especificación de producto con SVG/tokens, no una sugerencia desechable.

## Advertencia de alcance

Esta es documentación de arquitectura, NO entrega de app. Cualquier resultado posterior debe diferenciar entre SVG conceptual, código Compose, APK debug y release firmado.

