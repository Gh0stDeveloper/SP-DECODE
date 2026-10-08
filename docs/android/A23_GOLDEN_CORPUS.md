# A.2.3 — Corpus de pruebas golden reproducibles

> **Estado al 2026-10-08:** A.2.3 está **EN PROGRESO**. Hay **19 fixtures positivos sintéticos con salida íntegra y SHA-256 para 18 de 59 extensiones**. Quedan **41 extensiones sin caso positivo**. En Android se han verificado **0/59** y ninguna versión reciente de las aplicaciones exportadoras ha sido certificada.

## 1. Alcance verificado frente a soporte de producto

El proyecto genera perfiles falsos localmente para alimentar el **script existente de Linux**, comprueba la salida completa y la congela como `expectedRawUtf8Sha256`. Este método demuestra regresión del algoritmo y la ruta de entrada, no interoperabilidad con archivos exportados en versiones actuales de otras aplicaciones. Los archivos usan exclusivamente dominios reservados y datos artificiales; jamás archivos de clientes ni credenciales reales.

El futuro producto Android conserva `rawText` **sin traducción**, aunque la UI esté en español, inglés, portugués o árabe. Sigue sin implementarse un motor Android: **ninguna extensión puede aparecer como verificada en Android**.

## 2. Cobertura Linux por bloques

| Bloque | Casos | Extensiones nuevas | Scripts implicados |
|---|---:|---|---|
| A.2.3 lote 1 | 6 | `.tls`, `.v2`, `.ehil`, `.ssc`, `.dark` (5) | TLS, EV2RAY, HTTPINJECTORLITE, SSCCUSTOM, DARKTUNNEL |
| A.2.3 lote 2 | 3 | `.ht`, `.htb`, `.hc` (3) | HTTPTWEAK, HTTPCUSTOM |
| **A.2.3 lote 3** | **10** | **`.agn`, `.cly`, `.fɴ`, `.jvc`, `.jvi`, `.v2i`, `.sksrv`, `.sksrv.png`, `.xscks`, `.aro`** | multides, sksrv, xscks, aro |
| **Total** | **19** | **18 de 59** | **11 scripts únicos** |

### Detalle técnico del lote 3

| Extensión | Método del script | Evidencia que cubre el golden | Limitación |
|---|---|---|---|
| .agn | DES-ECB | XML sintético importado por multides.py vía archivo .agn | clave compartida de la primera entrada, **no** la clave específica del exportador .agn |
| .cly | DES-ECB | XML sintético por ruta .cly | no existe entrada diferenciada .cly en el mapa PASSWORDS; no se valida formato vendor |
| .fɴ | DES-ECB | Unicode de extensión y salida CLI exacta | clave compartida, no exportador |
| .jvc | DES-ECB | ruta .jvc y descifrado de la primera clave común | **no** confirma el cifrado específico de .jvc |
| .jvi | DES-ECB | ruta .jvi y salida completa | clave compartida; no exportador |
| .v2i | DES-ECB | ruta .v2i y descifrado de su primera clave | no exportador actual |
| .sksrv | PBKDF2-SHA256 + AES-GCM | XML artificial con tag autenticado y salida original CLI | no versión exportadora |
| .sksrv.png | mismo contenedor SKSRV | extensión **compuesta longest-match** y salida completa | no se valida una imagen PNG real; este es un archivo sintético con nombre compuesto |
| .xscks | SHA-256 + AES-CBC | JSON artificial cifrado y formato CLI original | clave existente en script, sin verificación externa |
| .aro | Base64 + transformación byte -18 | JSON con `CONFIG` artificial; inversa del formato local | no se verifica exportación vigente |

**Limitación crítica:** los seis casos de `multides.py` reproducen el **mismo ciphertext** porque su código intenta la clave DES inicial para todos los sufijos. Son seis pruebas de **enrutamiento por extensión**, no seis familias de cifrado verificadas de forma independiente. Los dos casos SKSRV comparten el mismo contenedor AES-GCM. **No confundir 10 sufijos añadidos con 10 motores independientes**.

Para los formatos previamente cubiertos, e-V2Ray tiene dos variantes (texto plano/AES-128), HTTP Tweak dos variantes de tablas (HT y HTB). La consola de HTTP Tweak devuelve JSON sin banner aunque su función `run` añada cabecera; ambos contratos siguen comprobados por separado.

## 3. Qué se prueba automáticamente

1. **Paridad literal**: se compara `stdout` completo y UTF-8 contra `tests/golden/expected/<caso>.txt`, incluidos saltos de línea, banners, nombres, puntuación y orden original del decoder. En scripts con función `run(bytes)`, se compara también el retorno completo.
2. **Integridad de prueba**: generadores deterministas y `inputSha256` + `expectedRawUtf8Sha256` fijados en `tests/golden/manifest.json`; cualquier cambio de bytes hace fallar CI.
3. **Enrutamiento**: los 59 sufijos deben existir en el registro y los diez nuevos pasan por archivos con su extensión real. Se comprueba `.sksrv.png` por coincidencia más larga y Unicode `.fɴ`.
4. **Entradas inválidas**: smoke tests negativos, asegurando que no aparezca un perfil ficticio de éxito; esto no reemplaza fuzzing exhaustivo por formato.
5. **Ejecución reproducible**: 19 archivos de prueba sintéticos exportables para una futura app local, sin servidores ni descargas.

## 4. Archivos, generación y CI

| Archivo | Función |
|---|---|
| `tests/golden/a23_generators.py` | generadores del corpus original y registro global |
| `tests/golden/a23_batch3.py` | construcción determinista de los diez perfiles nuevos |
| `tests/golden/expected/*.txt` | 19 salidas golden originales congeladas |
| `tests/golden/manifest.json` | 59 entradas, 19 casos, 18 con fixture positivo y 41 sin positivo |
| `tests/test_android_a23_goldens.py` | suite histórica para los primeros 9 casos |
| `tests/test_android_a23_batch3.py` | paridad CLI y negativos de los 10 nuevos |
| `tests/golden/a23_report.py` | metadatos y hashes, nunca volcado de secretos |
| `tests/golden/a23_export.py` | archivos ficticios con nombres/extensiones y `SHA256.json` |
| `.github/workflows/validate.yml` | suite Linux + artifact `spdecode-android-a23-golden-coverage` |

Comandos locales desde la raíz del repositorio, con dependencias del bot instaladas:

```bash
python -m unittest discover -s tests -v
PYTHONPATH=. python tests/golden/a23_report.py --output out/a23/coverage.json
PYTHONPATH=. python tests/golden/a23_export.py --output-dir out/a23/samples
```

**Evidencia preliminar del lote 3:** [CI #37855854741](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37855854741) — 24 tests en success con diez pruebas CLI positivas y negativas. Los SHA-256 se congelaron posteriormente; verificar CI del commit final antes del merge.

## 5. Estado y siguientes diez extensiones

- **A.2.3 continúa IN PROGRESS:** solo 18/59 sufijos tienen golden sintético. 41 sin fixture positivo, y las variantes especiales requieren muestras diferenciadas.
- **A.2.4 continúa NOT STARTED:** sin prueba binaria Android, sin ARM64/16 KB y sin adaptación local Node/PHP/Python.
- **Próxima prioridad técnica:** `.ehi`, `.npv4`, `.npvt`, `.hat`, `.npv2`, `.sks`, `.rez`, `.rezl`, `.tvt`, `.sksplus`; solo incorporarlas al corpus si pueden producir salidas reales positivas y reproducibles.
- Para elevar el nivel de los alias MultiDES, conseguir fixtures autorizados de las aplicaciones correspondientes y probar específicamente las claves/versiones; no asumirlo a partir de un ejemplo de clave compartida.
- La validación completa del bot Linux no certifica la futura APK ni el comportamiento de los exportadores externos.

**Regla de cierre:** una extensión solo se marca Android verificada tras importación offline en dispositivo, paridad literal con el golden, pruebas de seguridad y cobertura de las versiones que se anuncien.
