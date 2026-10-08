# Fase A.2 — Auditoría técnica de decodificadores

**Repositorio:** Gh0stDeveloper/SP-DECODE · **Rama:** feat/android-a2-decoder-audit · **Baseline:** main `39118010f24bac95aea6c3299fc1523a4c9e0522` · **Fecha:** 2026-10-08.

> **Hallazgos basados en lectura del código y registro:** no se ha decodificado una muestra de cada formato, no se ha ejecutado nada en Android y no existe APK. El análisis de patrones no sustituye la ejecución controlada, revisión criptográfica ni pruebas de compatibilidad.

## 1. Resultado del inventario estático

| Control | Resultado |
|---|---:|
| Sufijos registrados en `decoders.json` | **59** |
| Scripts de decodificación referenciados distintos | **48** |
| Python / Node.js / PHP (sufijos) | **48 / 8 / 3** |
| Python / JavaScript / PHP (scripts distintos) | **39 / 6 / 3** |
| Rutas de script del registro comprobadas presentes | **48/48** |
| Scripts Python con función `run(...)` declarada detectada | **12/39** |
| Sufijos Android con pruebas golden + dispositivo | **0/59** |
| Decoders con fixture sintético ya cubierto por test `test_current_decoders.py` | **2 scripts (TLS y EV2RAY)** |
| Archivo de muestra física/verificación Android | **Ninguno** |

**Técnica:** revisión de los 48 scripts actuales mediante el conector GitHub y herramienta repetible `python docs/android/audit_decoders.py`. Escaneo **sin importar ni ejecutar scripts**. El sistema CI genera `a2-static-report.json` y `a2-static-report.md` como artefactos sin claves ni código sensible. Los hallazgos `regex` se tratan como **candidatos**, nunca como demostración de llamadas realizadas.

Los 59 sufijos incluyen alias múltiples hacia un solo archivo: `.ht/.htb`, `.npv4/.npvt`, `.rez/.rezl/.tvt` y `.sksrv/.sksrv.png`. Es obligatorio probar cada sufijo aunque se comparta motor. El componente de nombres de archivo debe soportar `.fɴ` Unicode y **longest-suffix-match** para `.sksrv.png`.

## 2. Hallazgos prioritarios con acciones de ingeniería

| ID | Severidad para port Android | Evidencia de código | Acción propuesta | Gate |
|---|---|---|---|---|
| A2-001 | **P0 antes de empaquetar** | `NPVTUNNEL.py` usa `pickle.loads(gzip.decompress(base64.b64decode(_WHITEBOX_BLOB)))` en un blob **embebido**; no se observó que ese argumento provenga directamente del archivo del usuario | analizar alcance real de confianza; preferir serialización explícita segura o tabla validada; no ejecutar blobs pickle modificables desde inputs | C.4/D.2 |
| A2-002 | **P0 antes de portar** | `modulepro.js` y `chicosp.js` leen y **escriben** `cfg/config.inc.json`; también cargan `cfg/lang`, `cfg/layout`, `lib/methods` | adaptar como configuración de solo lectura por request; eliminar escrituras globales/carrera entre importaciones; port libs transitivas | E.3 |
| A2-003 | **P1 offline** | `gold.py` importa `requests`; búsqueda del archivo no mostró invocaciones `requests.get/post` directas | eliminar dependencia si es innecesaria al integrar; verificar llamadas indirectas, ningún permiso INTERNET | D.4/C.6 |
| A2-004 | **P1 ABI** | `HTTPINJECTOR.py`, `HTTPINJECTORLITE.py`, `TLS.py`, `EV2RAY.py`, `DARKTUNNEL.py` y `_noobcrypt.py` usan Crypto, cryptography, argon2 o msgpack | test temprano de wheels arm64/x86_64 y páginas 16 KB; alternativa port Kotlin sin servidor | C.4 |
| A2-005 | **P1 packaging** | `hat.js` lee `nodehat.json`; las rutas `cfg/config.inc.json`, `cfg/lang/english.lang.json`, `cfg/layout/default.layout.json` y librerías `lib/methods` están presentes en el repo | empaquetar solo assets realmente requeridos; validar permisos/licencias, claves hardcodeadas y no colocar secretos nuevos en APK | E.1/E.3 |
| A2-006 | **P1 pruebas** | Solo dos tests sintéticos directos en `tests/test_current_decoders.py` cubren TLS y EV2RAY; no hay fixtures de paridad para otros 46 scripts | corpus seguro y pruebas golden por sufijo, input válido + truncado/corrupto + versión de aplicación exportadora | D/E/H |
| A2-007 | **P1 contrato** | 27/39 scripts Python no exponen `run(...)` según inspección estática; algunos dependen de argv, open/read y stdout | introducir wrapper determinista por bytes; respetar salida original en inglés y formato; sin subprocess/Termux en APK | C.2/D |
| A2-008 | **P1 versión** | `sockip.py` y la documentación del bot mencionan casos incompatibles VER7 de apps nuevas | no simular éxito; registrar versión de formato y crear corpus autorizado versionado | D.3 |
| A2-009 | **P1 dependencias declaradas** | `requirements.txt` lista PyCryptodome, Argon2, msgpack, requests, pero **no declara directamente `cryptography`** aun cuando los scripts referencian esa biblioteca | decidir conjunto mínimo de runtime Android separado de requirements del bot; fijar versiones y comprobar licencias/ABI | C.4 |
| A2-010 | **P2 mantenimiento** | Se identifican scripts no referenciados por `decoders.json` como `decoders/Python/hat.py`, `tnl2.py`, `v2box.py`, `decoders/JavaScript/hrt.js`, `ziv.js`; `_noobcrypt.py` es auxiliar referenciado por otros módulos | no borrar; clasificar módulos auxiliares vs legacy, documentar inclusión y revisar licencia/estado | A.2/C.1 |

**Precisiones de seguridad:** el uso de `pickle.loads` indicado se refiere al **blob constante embebido** detectado, no constituye evidencia de deserialización directa de bytes importados. El import `requests` no prueba una conexión de red realizada. Los escaneos automáticos son conservadores y pueden requerir inspección manual.

## 3. Inventario por script (48 de 48; formato por alias)

La columna `run(bytes)` identifica presencia sintáctica y **no asegura que el cuerpo sea importable/compatible con Android**. El juicio en la última columna representa trabajo de portabilidad, no validación del descifrado.

| Script origen | Sufijos | Runtime bot | Acceso propuesto | Riesgo/trabajo |
|---|---|---|---|---|
| `decoders/JavaScript/chicosp.js` | .npv2 | node | full local port required | **P0 Android:** reads and writes cfg/config.inc.json, references cfg/lang, cfg/layout and lib/methods; isolate state |
| `decoders/JavaScript/hat.js` | .hat | node | full local port required | **P1:** fs/crypto/Buffer, requires nodehat.json; port with byte-level golden comparisons |
| `decoders/JavaScript/modulepro.js` | .epro | node | full local port required | **P0 Android:** reads and writes cfg/config.inc.json, references cfg/lang, cfg/layout and lib/methods; replace with immutable in-memory config |
| `decoders/JavaScript/rez.js` | .rez, .rezl, .tvt | node | full local port required | Port byte behavior, crypto/JSON and input semantics; fixture required |
| `decoders/JavaScript/sks.js` | .sks | node | full local port required | Port byte behavior, crypto/JSON and input semantics; fixture required |
| `decoders/JavaScript/stk.js` | .stk | node | full local port required | Port byte behavior, crypto/JSON and input semantics; fixture required |
| `decoders/PHP/hrt.php` | .hrt | php | full local port required | Port byte behavior, crypto/JSON and input semantics; fixture required |
| `decoders/PHP/jez.php` | .jez | php | full local port required | Port byte behavior, crypto/JSON and input semantics; fixture required |
| `decoders/PHP/sksplus.php` | .sksplus | php | full local port required | Port byte behavior, crypto/JSON and input semantics; fixture required |
| `decoders/Python/DARKTUNNEL.py` | .dark | python | run(bytes) present | **P1:** Crypto + msgpack; multipart mapping outside file registry |
| `decoders/Python/EV2RAY.py` | .v2 | python | run(bytes) present | **P1:** Crypto + cryptography; run(bytes), synthetic regression already exists |
| `decoders/Python/HTTPCUSTOM.py` | .hc | python | run(bytes) present | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/HTTPINJECTOR.py` | .ehi | python | run(bytes) present | **P1:** Crypto, cryptography, argon2; verify Android wheels and unsupported modes |
| `decoders/Python/HTTPINJECTORLITE.py` | .ehil | python | run(bytes) present | **P1:** Crypto/cryptography; verify native wheel dependency. |
| `decoders/Python/HTTPTWEAK.py` | .ht, .htb | python | run(bytes) present | **P1:** embedded lookup tables/obfuscated blobs in source; verify license/size and format version |
| `decoders/Python/NPVTUNNEL.py` | .npv4, .npvt | python | run(bytes) present | **P0 review:** pickle.loads on embedded constant _WHITEBOX_BLOB; must validate trust boundary and replace unsafe deserialization for Android |
| `decoders/Python/SSCCUSTOM.py` | .ssc | python | run(bytes) present | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/TLS.py` | .tls | python | run(bytes) present | **P1:** Crypto + cryptography; run(bytes), synthetic regression already exists |
| `decoders/Python/aro.py` | .aro | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/at.py` | .at | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/cloudy.py` | .cloudy | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/fnnetwork.py` | .fnnetwork | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/gold.py` | .gold | python | legacy / adapter required | **P1:** requests imported; no requests.get/post calls identified in direct source scan; avoid shipping unnecessary network dependency |
| `decoders/Python/ipt.py` | .ipt | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/maya.py` | .maya | python | run(bytes) present | **P1:** run(bytes), shared _noobcrypt helper; review transitive cryptography use |
| `decoders/Python/mij.py` | .mij | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/mina.py` | .mina | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/mrc.py` | .mrc | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/mtl.py` | .mtl | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/multides.py` | .fɴ, .v2i, .agn, .jvi, .jvc, .cly | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/nms.py` | .nm | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/nt.py` | .nt | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/ost.py` | .ost | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/pb.py` | .pb | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/pcx.py` | .pcx | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/phc.py` | .phc | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/sbr.py` | .sbr | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/sksrv.py` | .sksrv, .sksrv.png | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/sockip.py` | .sip | python | run(bytes) present | **P1:** Java serialization/VER7 version-dependent parser; requires multiple version fixtures and graceful unsupported |
| `decoders/Python/ssh.py` | .ssh | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/sut.py` | .sut | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/tnl.py` | .tnl | python | legacy / adapter required | **P1:** ctypes imported; confirm portability of low-level byte layouts |
| `decoders/Python/uwu.py` | .uwu | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/vpnlite.py` | .vpnlite | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/xscks.py` | .xscks | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/xtproy.py` | .xtp, .roy | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
| `decoders/Python/xui.py` | .xui | python | run(bytes) present | **P1:** run(bytes), shared _noobcrypt helper; review transitive cryptography use |
| `decoders/Python/ziv.py` | .ziv | python | legacy / adapter required | Audit CLI/filesystem/print side effects; fixture required |
## 4. Librerías y archivos de apoyo (no son los 48 scripts del registro)

- `decoders/Python/_noobcrypt.py`: helper compartido por `maya.py` y `xui.py`; el import de `cryptography` se realiza dentro de la función. Sus dependencias deben incluirse en el análisis transitivo del runtime.
- `nodehat.json`: recurso consumido por `hat.js`.
- `cfg/config.inc.json`, `cfg/lang/english.lang.json`, `cfg/layout/default.layout.json`, `lib/methods/*.lib.js`: recursos consumidos por decodificadores Node.js, incluidas llamadas dinámicas.
- `decoders/Python/hat.py`, `tnl2.py`, `v2box.py` y `decoders/JavaScript/hrt.js`, `ziv.js` son archivos fuente detectados pero **no están registrados como entrada principal** en `decoders.json`. Evitar eliminarlos hasta revisar referencias indirectas.
- `requirements.txt` para el bot no se copia sin filtrar a Android: `pyTelegramBotAPI` es una dependencia impropia para APK independiente.

## 5. Matriz de pruebas y metodología para concluir A.2

Ver [A2_FIXTURE_POLICY.md](A2_FIXTURE_POLICY.md) para evidencia requerida, técnicas de fixtures y política de secretos. Conservar original `rawText` sin traducir ni reordenar al cambiar idiomas de UI (es/en/pt-BR/ar). El ensamblado de Android requiere un bridge que no altere el texto impreso por cada decodificador.

**Para cerrar A.2 en el sentido estricto de ROADMAP:** documentar para cada decoder si hay muestra de formato vigente, assets necesarios, compatibilidad del bridge, casos negativos y plan de fixture reproducible. El corpus funcional completo y la compatibilidad real Android corresponden además a D/E/H, por lo que este estudio **no certifica** 59/59. El auditor estático alcanza la totalidad de fuentes; el campo `A.2` permanece **in_progress** hasta completar la evaluación de muestras/fixtures faltantes.

## 6. Evidencia de ejecución CI (2026-10-08)

- [GitHub Actions Validate SP-DECODE — run 37835155484, **SUCCESS**](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37835155484).
- 12 tests unitarios del repositorio aprobados, incluidos 5 tests específicos nuevos de auditoría; no se ejecutó Android.
- Auditoría estática en CI: **59 sufijos, 48 scripts, 12 scripts Python con run(), 1 candidato de import de red, 0 candidatos de llamada de red, 5 scripts con assets conocidos y 1 candidato de pickle**.
- Registros/sintaxis/recursos conocidos: sin errores de integridad en CI.
- [Artifact `spdecode-android-a2-audit` con reportes JSON/Markdown](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37835155484/artifacts/11574907879). El artefacto de GitHub Actions caduca según su retención; el código auditor y esta documentación permanecen en Git.
- Se observó un aviso de deprecación Node.js 20 en acciones existentes; no bloqueó el resultado, pero debe actualizarse el workflow en mantenimiento separado.

## 7. Verificación automatizada y límites

- `python docs/android/audit_decoders.py --output-dir out/android-a2`: escáner local sin importar scripts.
- `python -m unittest discover -s tests -v`: validación del escáner y de dos fixtures sintéticos actuales.
- `.github/workflows/validate.yml`: registra resultados y adjunta artefacto sanitized `spdecode-android-a2-audit`.
- La prueba de compilación/ejecución Android y ruedas Chaquopy es **Fase C.4**, todavía no implementada.
- No marcar un formato «verificado» por compilar Python, encontrar claves o producir stdout; exigir prueba golden y test dispositivo.

## 8. Próximas tareas de auditoría funcional

1. Recolectar muestras **sintéticas o autorizadas** de cada formato, asociadas a versión de app exportadora. A2.1 revisión de I/O, A2.2 dependencia/recursos, A2.3 corpus/fixtures, A2.4 paridad/reporte por sufijo.
2. Prioridad: `.tls`, `.v2` para convertir tests existentes a golden byte-exact; luego `.ehi`, `.ehil`, `.hc`, `.ht/.htb`, `.npv4/.npvt`, `.ssc`, `.dark`, `.hat`.
3. Revisión explícita del caso `NPVTUNNEL` y las escrituras de configuración Node antes de liberar motor portable.
4. Registrar resultados por sufijo en DECODER_MATRIX.md y status.json; marcar verified solo tras paridad + ABI y dispositivo.
