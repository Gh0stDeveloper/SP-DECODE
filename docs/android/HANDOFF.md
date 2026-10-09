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
2. Leer docs/android/README.md, PRODUCT_REQUIREMENTS.md, DESIGN_SYSTEM.md, ARCHITECTURE.md, DECODER_MATRIX.md, DECODER_AUDIT.md, A2_FIXTURE_POLICY.md, A23_GOLDEN_CORPUS.md, SECURITY_AND_QA.md, ROADMAP.md, ADR.md, status.json y este HANDOFF.md.
3. Mirar commits/runs de CI. Distinguir documentado / implementado / probado / publicado.
4. Identificar primera subfase realmente pendiente en ROADMAP. No reabrir fases cerradas salvo defectos.
5. Trabajar en rama y PR; no reescribir main ni lógica del bot innecesariamente.
6. Al cerrar cada subfase, actualizar status.json, HANDOFF.md y matriz de formatos. Adjuntar SHA, links, checks, pruebas, estado y siguiente tarea.
7. Comparar pantallas Compose reales con los SVG y los tokens. Si diseño o condición offline van a cambiar, obtener aprobación explícita y dejar ADR.

## Estado inicial verificable (2026-10-08)

- Proyecto Android: **NO implementado**.
- APK: **NO generada**.
- A.1, A.3, A.4, A.5 y A.6: especificaciones redactadas.
- A.2: 48/48 scripts auditados estáticamente; en A.2.3 hay **60 casos golden sintéticos para 59/59 sufijos**, ninguno sin positivo; validación externa/Android todavía pendiente.
- B, C, D, E, F, G, H: sin iniciar.
- **A.2 auditoría estática verificada (A.2.1 y A.2.2), A.2 general ABIERTA:** 48 scripts auditados; A.2.3 ya dispone de **60 salidas golden sintéticas Linux congeladas para los 59 sufijos**; última ruta `.ssh` añadida en PR #14. El conjunto no avala exportadores/versiones vigentes ni funciona como bridge Android: **A.2.4 no iniciada, 0/59 Android**. El NPV whitebox carga un blob fijo con `pickle.loads` (riesgo pendiente); otras limitaciones: MultiDES emplea una clave de prueba compartida; SKSRV tiene variantes nominales sobre una sola envoltura; los scripts (.cloudy, .uwu, .ost) conservan cabeceras heredadas que no coinciden con su sufijo. Consúltese [A23_GOLDEN_CORPUS.md](A23_GOLDEN_CORPUS.md), [DECODER_AUDIT.md](DECODER_AUDIT.md), el manifiesto y CI exacto. **No declarar toda la fase A.2 ni compatibilidad Android completadas.**
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
DECODER_MATRIX.md, DECODER_AUDIT.md, A2_FIXTURE_POLICY.md, A23_GOLDEN_CORPUS.md, ROADMAP.md, SECURITY_AND_QA.md, ADR.md,
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


### Handoff lote 7 (2026-10-08)

PR #13 `feat/android-a23-batch7-ten-suffixes`: goldens Linux sintéticos `.ehi`, `.epro`, `.gold`, `.npv2`, `.npv4`, `.npvt`, `.roy`, `.sut`, `.tvt`, `.xtp`. Cobertura total **59 casos / 58 de 59 sufijos**. El único sin positivo es `.ssh`. **NO cerrar A.2.3:** ninguna muestra de exportador vigente, 0 Android, falta tratar aleatoriedad SSH, y el `pickle.loads` del blob whitebox NPV permanece pendiente de seguridad. Controles nuevos en `tests/test_android_a23_batch7.py`. Revisar CI success del HEAD antes de integrar.

### Lote final SSH — PR #14 (2026-10-08)

Rama `feat/android-a23-batch8-last-ssh-golden`; `tests/golden/a23_batch8_ssh.py` crea una entrada Blowfish con `example.org`; snapshot íntegro `batch8-ssh.txt`, SHA256 en manifest y pruebas `test_android_a23_final_ssh.py` para bytes, corrupción y aleatoriedad por defecto. La variable de entorno `SPDECODE_SSH_GOLDEN_TEST=1` **solo estabiliza decoración para tests** y no debe emplearse para afirmar compatibilidad externa. **Cierre estricto del corpus L2 Linux sintético: 60 casos/59 sufijos; no hay APK ni verificación Android, 0/59; A.2.4 continúa pendiente.** [CI y PR #14](https://github.com/Gh0stDeveloper/SP-DECODE/pull/14).

## Fase A.2.4 — Primer incremento Android y revisión de seguridad (PR #15)

Rama `feat/android-a24-parity-runtime-security-baseline`. Se añadió `android/` como **host experimental exclusivo de pruebas**, Gradle Kotlin y manifest sin permiso de red. `V2RayReferencePort` porta a Kotlin JCA dos envolturas e-V2Ray documentadas (plana y AES-128) usando únicamente datos ficticios; los instrumentos comprueban salida UTF-8 íntegra y permisos en un emulador API 35. Los assets se exportan desde SHA256 del manifest con `scripts/android_a24_prepare.py`. El NPV whitebox pasó de `pickle.loads` directo a deserialización con filtro de opcodes, presupuesto descomprimido y constructor/globales prohibidos; pruebas Linux de seguridad garantizan que la salida histórica NPV no cambie.

**No confundir prototipo con producto:** la app Compose, importación SAF, puente Chaquopy/Python, ports Node/PHP completos, 59 formatos Android, arm64, 16KiB, versiones reales de exportadores y Play/release siguen pendientes. Mantener `androidVerifiedSuffixes=0` hasta evidencia de dispositivos ABI/formato. **A.2.4 no está cerrada**. Leer [A24_PARITY_SECURITY.md](A24_PARITY_SECURITY.md), consultar PR #15 y verificar ambos jobs CI antes de merge.

### Evidencia de emulador A.2.4, primera iteración

[CI Android conectado #37868719536](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37868719536): **4/4 tests OK en Android 35 x86_64**, dos perfiles `.v2` sintéticos, permisos revisados, Gradle `assembleDebug` y AndroidTest correctos; Linux `validate` también success. Catálogo generado de 59 entradas no afirma soporte nativo: solamente `.v2` está en modo prototipo y **58 siguen sin port**, con **0/59 certificados**. Se añadirán pruebas de catálogo y se deberá volver a validar el HEAD tras el último commit.


## Incremento A.2.4 TLS (rama de trabajo)

- Rama `feat/android-a24-tls-aead-parity`; base `main` posterior a PR #15.
- Nuevo port Kotlin offline `TlsReferencePort.kt`, JCA AES-256-GCM y
  referencia `tls-aesgcm`; genera tres assets sintéticos verificados SHA-256.
- Catálogo registra 2 sufijos en estado experimental (`.v2`, `.tls`);
  quedan 57 sin port, **0/59 verificados con exportadores reales**.
- No marcar `.tls` como pasado en emulador hasta recibir ejecución CI.
- El host Android continúa sin interfaz de importación y sin permisos de red.
- Siguiente paso: revisar workflow, resolver errores, después A.2.4.2
  (otros motores), A.2.4.3 arm64/16 KiB, y Fase B/C UI+SAF.

## A.2.4 — lote de diez adaptadores Android Kotlin

Rama `feat/android-a24-batch10-native-ports`. PR en revisión. Se agregaron ports
de `.phc`, `.mina`, `.vpnlite`, `.cloudy`, `.mij`, `.fnnetwork`,
`.uwu`, `.sksrv`, `.maya`, `.xui`. Cada archivo es su propia ruta
de descifrado con clave, envoltura y salida del motor original. No son puertos
genéricos de «probar todas las claves». Pruebas: 13 muestras en total,
una positiva Android por nuevo formato + negativos y regresión del bot.

**No habilitar en UI** hasta integrar SAF/flujo de importación y recibir
resultados de CI emulador. `.sksrv.png` permanece separado y sin implementar.
Los 59 goldens Linux son sintéticos, 0 certificados en Android físico.

- Evidencia de 10 ports Android en emulador, CI inicial: [run 37872655497](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37872655497), jobs Linux y Android `success`.
- `AndroidOfflineDecoderRouter` enlaza cada sufijo a su propio método; sin fallback de claves. Nuevos tests en PR pendientes de su propia validación CI.

## Continuidad A.2.4 — lote adicional batch20

Rama `feat/android-a24-batch20-native-ports`; diez Kotlin ports:
at, nm, ost, sbr, pcx, nt, pb, aro, ipt, gold. Nuevo
`Batch20InstrumentedTest` compara cada salida byte por byte y el enrutador
estricto; 30 pruebas negativas. Ajustar las fallas CI **antes de fusionar**.
Al aprobar: 22 prototipos, 37 sin port, 0 formatos certificados por exportador.

- Segunda tanda Android CI final `https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37876235386` — Linux `success`,
  Android API35 x86_64 `success` y **31/31 tests instrumentados**.
  `.at` y `.nm` corregidos para la indentación JSON de Python (2 espacios).
- PR #18 listo para cierre tras esta documentación y revisión.
- Catálogo: 22 prototipos, 37 sin implementar y 0 certificados en
  exportaciones de proveedores. Android offline UI/SAF, arm64, 16KiB
  y archivos reales siguen pendientes.

## Continuidad A.2.4 — lote de quince adaptadores

Rama `feat/android-a24-batch15-native-ports`. 15 sufijos, 13 decodificadores
fuente distintos contando agrupaciones MultiDES y SKSRV; no se afirma que
sean quince algoritmos diferentes. Los puertos están en Kotlin y el catálogo
indica 37 prototipos, 22 no implementados. Nuevo test
`Batch15InstrumentedTest`; 38 goldens sintéticos Android totales,
45 casos negativos para 15 nuevos. Confirmar CI y corregir
desajustes exactos antes de autorizar merge. Bot original inalterado.

- CI lote de 15: [#37881078999](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37881078999) Linux y Android
  success, **47/47 pruebas API35 x86_64** (37 sufijos prototipo,
  38 golden positivos por dos variantes V2, 22 sufijos sin portar).
- Añadido guard `test_android_a24_legacy_module_assets.py` contra
  divergencia de `cfg/keyFile.json` y etiquetas inglesas original.
  Su ejecución se confirma en el próximo workflow, no el anterior.
- Cobertura `epro` raw ECB y `npv2` vmess sintética.
  Faltan subvariantes, exportaciones reales, ARM64 físico y 16KiB.

### Incremental A.2.4 final remainder: 11 native source-specific ports

`feat/android-a24-final-remainder-batch` adds source-derived Android Kotlin ports
for rez, rezl, tvt, stk, xtp, roy, sksplus, sks, sut, tnl, ssh.
Tests in `Final11InstrumentedTest`: 11 exact byte-level positive Linux
goldens, strict extension routing and 33 reject assertions.
Reference inventory after passing these tests: 48 experimental of 59,
11 unported. Never claim this batch is verified before GitHub API35
emulator CI succeeds. Do not merge while failing. No change to Telegram bot.
