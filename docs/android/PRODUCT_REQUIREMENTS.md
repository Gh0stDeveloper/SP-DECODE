# Especificación de producto — SP-DECODE Android (PRD v1.0)

## 1. Público, problema y resultado esperado

Usuarios Android que reciben o gestionan archivos de configuración de aplicaciones VPN/túneles compatibles con SP-DECODE y quieren **inspeccionar sus propios archivos autorizados** sin bot, login, VPS ni Internet. El valor entregado es un ciclo completo: importar → identificar → decodificar → entender → guardar/exportar.

**Límites de privacidad:** las credenciales pueden pertenecer a terceros. No publicar, sincronizar ni enviar el contenido sin una acción explícita del usuario. No ampliar la funcionalidad hacia intrusión, interceptación ni acceso a apps ajenas.

## 2. Requisitos funcionales

| ID | Requisito | Aceptación verificable | Prioridad |
|---|---|---|---|
| FR-01 | Arranque sin cuenta ni conexión | Primera ejecución en modo avión sin onboarding bloqueante, red ni token | P0 |
| FR-02 | SAF interno | Selector del sistema con filtro general; acepta los sufijos soportados aunque MIME sea genérico | P0 |
| FR-03 | Apertura externa | ACTION_VIEW para archivos compartidos por gestores de archivos y ACTION_SEND para uno; degradación elegante cuando el proveedor niegue acceso | P0 |
| FR-04 | Importación múltiple | ACTION_SEND_MULTIPLE / selección múltiple, cola con progreso por elemento | P1 |
| FR-05 | Identificación determinista | Registro local y coincidencia longest-suffix; UTF-8, nombres Unicode y .sksrv.png | P0 |
| FR-06 | Motor offline | Ejecución del decodificador empaquetado; cero solicitudes HTTP/DNS y sin intérpretes externos instalados | P0 |
| FR-07 | Salida consistente | Éxito/parcial/fallo/no soportado y salida estructurada más vista cruda siempre que exista | P0 |
| FR-08 | Resultado claro | Resumen formato, nombre, campos, texto completo, colapso de campos vacíos, copiar campo o todo | P0 |
| FR-09 | Exportación | Crear archivo mediante ACTION_CREATE_DOCUMENT, TXT siempre; JSON solo cuando tenga semántica válida | P0 |
| FR-10 | Compartir | ACTION_SEND con contenido redactado por defecto; confirmación para compartir secretos | P0 |
| FR-11 | Historial | Persistencia local, búsqueda, ficha, reabrir, borrar por registro/todos | P0 |
| FR-12 | Favoritos | Marcar/desmarcar registros sin volver a decodificar | P1 |
| FR-13 | Protocolos textuales | Pegar y procesar URI supported; multipart SSC y Dark Tunnel con sesión local explícita | P1 |
| FR-14 | Catálogo | Lista de formatos registrados con estado real: verificado / experimental / no verificado / no disponible | P0 |
| FR-15 | Ajustes | tema automático/oscuro/claro, reducción de movimiento, visibilidad de campos, historial, limpieza, exportación | P1 |
| FR-16 | Feedback | Estados de procesamiento, timeout, cancelación, error parseo, salida vacía, almacenamiento denegado, formato desconocido | P0 |
| FR-17 | Accesibilidad | lectores de pantalla, tamaño de letra Android, tacto mínimo 48dp, contraste verificable | P0 |
| FR-18 | Entorno libre de red | El APK no declara INTERNET; motor prohíbe cualquier llamada de red y app funciona en modo avión | P0 |
| FR-19 | Trazabilidad técnica | Cada decodificación vincula versión de decoder, formato, duración aproximada, origen del archivo y resultado | P1 |
| FR-20 | Copia/exportación segura | Credenciales ocultas por defecto; control revelación momentánea y advertencia al copiar/exportar contenido sensible | P0 |
| FR-21 | Multidioma solo interfaz | es, en, pt-BR y ar en todas las pantallas y estados; elección manual/sistema offline | P0 |
| FR-22 | Resultado inalterado por idioma | rawText, claves, datos y TXT/JSON originales idénticos en los 4 locales; sin traducción automática | P0 |
| FR-23 | UI árabe RTL | Navegación y controles RTL; bloques de texto técnico LTR aislados sin alterar bytes exportados | P0 |

**Priorización:** P0 obligatorio para primera beta funcional; P1 se completa antes de release 1.0 o se excluye con decisión ADR, nunca de manera silenciosa.

## 3. Requisitos no funcionales

- **Offline estricto:** no usar internet para runtime, reconocimiento, búsqueda, historial, configuración, ni decodificación. Gradle descarga dependencias **solo al compilar**, no al usar la APK. Algunos proveedores SAF remotos podrían necesitar su propia conexión; la app informará al usuario sin conectarse por sí misma.
- **Rendimiento:** inicio de UI sin bloquear el hilo principal. Presupuesto inicial orientativo (no medición): interacción al importar < 300 ms hasta que aparezca progreso; archivo pequeño en pocos segundos si el algoritmo lo permite. Registrar mediciones reales en QA.
- **Resiliencia:** procesos largos cancelables, límites configurables por decoder, OOM protegido mediante cotas de tamaño, descompresión y profundidad de JSON.
- **Compatibilidad:** minSdk **24 preliminar**, condicionado a compatibilidad Chaquopy y ruedas de dependencias; targetSdk acorde a política vigente en la fecha de release, no fijarlo de forma anticipada. Soporte prioritario arm64-v8a, x86_64 para CI/emulador; 32 bits solo tras validación.
- **Estabilidad:** sin fallos fatales sobre inputs corruptos, extensiones engañosas o intent repetidos; restauración tras terminación de proceso.
- **Accesibilidad/localización:** interfaz obligatoria en español (es/es-419), inglés (en), portugués brasileño (pt-BR) y árabe (ar); selector propio y preferencias por aplicación en Android 13+, soporte RTL **obligatorio**, strings externalizadas, fechas/UI locales y nada de texto incrustado en bitmaps. **La salida original de los decodificadores se mantiene en su idioma y formato originales**, sin traducción ni cambios al exportar.
- **Privacidad:** nada de analítica ni telemetría; logs técnicos **sin payloads/secretos**; no backup automático de historial descifrado.
- **Confiabilidad:** CI por PR, pruebas unitarias/instrumentadas, matriz física (Android 7, 10, 13, 15/16 si disponible), emuladores y modo avión.

## 4. Flujos de aceptación

### Flujo U1 — Importación interna

Abrir SP-DECODE → Inicio → Importar configuración → SAF → elegir archivo en almacenamiento local → vista Progreso → detectar extensión/algoritmo → Resultado. Guardar historial si la opción está habilitada. Al fallar, mostrar causa y conservar opción de reintentar; jamás mostrar un estado «decodificado» si únicamente hubo stderr o texto genérico de error.

### Flujo U2 — Desde un administrador de archivos

Seleccionar archivo → «Abrir con» o «Compartir» → SP-DECODE → resolver content:// con ContentResolver, no con ruta real asumida → procesar → mostrar Resultado. Limpiar copias temporales aun en cancelación/timeout.

### Flujo U3 — Historial

Inicio → Historial → búsqueda o filtro → seleccionar entrada → ver resultado guardado → favorito/copiar/exportar/borrar. El historial no requiere acceso al archivo original ni permiso SAF persistido si se conserva el resultado; la redecodificación desde origen requiere acceso nuevamente o copia temporal recuperable según ajustes.

### Flujo U4 — Texto y multipart

Pestaña/Formulario «Texto y enlaces» → pegar enlace → detección de esquema → procesar. Para SSC/Dark multipart: crear sesión explícita, añadir fragmentos en orden, indicar N fragmentos y permitir borrar/restablecer; no almacenar fragmentos completos en analytics/logs.

### Flujo U5 — Exportación/compartir

Resultado → copiar/compartir/exportar → si contiene secreto, ofrecer **versión censurada (predeterminada)** o revelación consciente → elegir destino mediante SAF/Android Sharesheet → informar solo sobre el resultado de la acción y no conservar destinos.

## 5. Pantallas y navegación

| Ruta lógica | Propósito | Acciones principales |
|---|---|---|
| Inicio | Marca + importar + reciente + acceso texto | Importar, pegar, reabrir |
| Resultado/{id o temporal} | Detalle con cabecera y campos | Copiar, compartir, exportar, favorito |
| Historial | Búsqueda, filtros, selección múltiple | Ver, favorito, borrar |
| Formatos | Catálogo verificado y sufijos | Búsqueda, filtrar disponibilidad |
| Ajustes | Apariencia, seguridad, datos | Tema, limpiar, privacidad |
| Acerca de | Autor, versión, notas y documentación | Créditos, licencia, privacidad |

**Navegación inferior fija:** Inicio · Historial · Formatos · Ajustes. Resultado es una pantalla de detalle con navegación de retorno y barra de acciones contextual. «Favoritos» vive en filtro de Historial; no añadas quinta pestaña por defecto.

## 6. Pantallas vacías y errores

| Estado | Copy principal | Secundaria/acción |
|---|---|---|
| Sin archivo | Importa tu primera configuración | Elegir archivo |
| Historial vacío | Aquí aparecerán tus resultados | Importar archivo |
| Formato desconocido | Este formato aún no está disponible | Ver formatos compatibles |
| Decodificador experimental | El formato se reconoce, pero aún no está verificado | Ver detalles del estado |
| Error de lectura | No pudimos abrir el archivo | Seleccionar de nuevo |
| Error de decodificación | No fue posible decodificar este archivo | Ver detalle técnico censurado |
| Timeout | El procesamiento superó el límite seguro | Reintentar/cancelar |
| Sin datos de salida | No se obtuvieron campos verificables | Mostrar salida original cuando exista |
| Sin acceso a origen | Ya no podemos acceder a este archivo | Volver a seleccionarlo |

## 7. Entregables y condiciones de rechazo

Se rechaza una entrega que: requiera conectarse a Telegram; incluya permiso INTERNET; prometa 59 formatos sin fixtures; bloquee la UI; use un WebView remoto; guarde secretos descifrados sin protección; exponga cadenas de prueba como resultados reales; presente colores, navegación o jerarquía radicalmente distintos de DESIGN_SYSTEM.md sin ADR.

## 8. Fuente visual

La pantalla principal, la de resultado, el sistema de tarjetas, la cabecera con icono, el CTA rectangular redondeado, el historial y la navegación inferior se consideran elementos esenciales **derivados de la propuesta conceptual aceptada por el usuario**. Su especificación exhaustiva y maquetas se documentan en DESIGN_SYSTEM.md.

