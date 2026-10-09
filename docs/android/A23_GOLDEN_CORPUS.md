# A.2.3 — Corpus de pruebas golden reproducibles

> **Estado 2026-10-08: CORPUS LINUX SINTÉTICO COMPLETO.** **60 casos golden de salida completa congelada para los 59 sufijos registrados; 0 sin muestra sintética positiva.** El registro de aplicaciones de terceros no está certificado, y **0 de 59 están verificados en Android**. Esta finalización cubre exclusivamente pruebas sintéticas de referencia en Linux.

## 1. Evidencia y alcance

Los generadores reproducen contenedores sintéticos utilizando el método de cifrado y las claves ya existentes en cada script original. Únicamente se emplean `example.org`, nombres ficticios, nonces/IVs fijos **exclusivos de pruebas** y datos sin capacidad de acceso a servicios reales. **No utilizar esos nonces/IVs fijos para cifrado de producción.**

Los tests comparan el **`stdout` original byte por byte**, sin traducción ni normalización, y bloquean modificaciones accidentales mediante SHA-256. Se ejecutan bajo Linux, no Android. El producto Android previsto sigue siendo offline, sin cuentas ni permiso INTERNET; el español, inglés, portugués y árabe son exclusivamente idiomas de interfaz y no alterarán `rawText`.

## 2. Cobertura incremental

| Lote | Casos sintéticos añadidos | Extensiones nuevas | Scripts originales distintos añadidos |
|---|---:|---:|---:|
| 1 | 6 | 5: .tls, .v2, .ehil, .ssc, .dark | 5 |
| 2 | 3 | 3: .ht, .htb, .hc | 2 |
| 3 | 10 | 10: .agn, .cly, .fɴ, .jvc, .jvi, .v2i, .sksrv, .sksrv.png, .xscks, .aro | 4 |
| **4** | **10** | **10: .hat, .sks, .sksplus, .cloudy, .mij, .fnnetwork, .uwu, .phc, .ost, .sbr** | **10** |
| 5 | 10 | 10: .jez, .hrt, .rez, .rezl, .maya, .xui, .mrc, .mtl, .mina, .tnl | 9 |
| 6 | 10 | 10: .nm, .pb, .pcx, .nt, .ziv, .vpnlite, .sip, .at, .ipt, .stk | 10 |
| **7** | **10** | **10: .ehi, .epro, .gold, .npv2, .npv4, .npvt, .roy, .sut, .tvt, .xtp** | **7** |
| **8 — SSH Injector** | **1** | **1: .ssh** | **1** |
| **Total** | **60** | **59 de 59** | **48** |

### Detalle del lote 4

| Sufijo | Runtime de referencia | Generador positivo | Cuidado especial |
|---|---|---|---|
| .hat | Node.js | AES-128-ECB + Base64 + `nodehat.json` | El archivo de layout debe empaquetarse cuando se porte; se compara etiqueta original |
| .sks | Node.js | SHA-MD5 derivado según script + AES-256-CBC | Datos sintéticos de SSH, sin credenciales operativas |
| .sksplus | PHP | JSON array signed-byte + AES-256-CBC/OpenSSL | Comparar su salida original PHP, incluido terminador |
| .cloudy | Python | AES-CBC + Base64 + JSON | El script imprime **(.aro)** en su cabecera; defecto heredado documentado |
| .mij | Python | PBKDF2-SHA256 + AES-GCM | El filtro original concatena el primer campo tras separador sin salto de línea |
| .fnnetwork | Python | PBKDF2-SHA256 + AES-GCM | Comparte sobre sintético el mismo ciphertext con MIJ; el formato de salida difiere |
| .uwu | Python | PBKDF2-SHA256 + AES-GCM | El script imprime **(.tnl)**; defecto heredado documentado |
| .phc | Python | PBKDF2-SHA256 + AES-GCM | El script usa cadena de clave convertida desde hexadecimal |
| .ost | Python | DES-ECB con clave original OST | El script imprime **(.tnl)**; no se debe normalizar `rawText` silenciosamente |
| .sbr | Python | DES-ECB con clave original SBR | Mismo contenedor XML artificial, con clave y script propios |

**Interpretación estricta:** son diez nuevas rutas de archivo con pruebas positivas; no significan diez criptosistemas únicos. Los casos de MIJ/FNNetwork comparten la misma envoltura de prueba; algunos scripts tienen rótulos históricos incorrectos. La validez de las configuraciones exportadas por proveedores reales sigue sin comprobarse.

El lote anterior de seis sufijos MultiDES continúa limitado a **una única clave DES de ejemplo compartida**. En concreto, su golden no prueba las claves exclusivas de todos los exportadores. SKSRV y SKSRV.PNG también comparten su contenedor de prueba. No omitir estas limitaciones en documentación ni en la UI de formatos.

### Detalle del lote 5 — diez casos Linux positivos

| Sufijo | Runtime | Prueba sintética | Limitación conocida |
|---|---|---|---|
| .jez | PHP | AES-256-CBC, SHA-256(password) y Base64 | claves históricas, no exportador actual |
| .hrt | PHP | mismo sobre AES-256-CBC | comparte input JEZ; salidas originales tienen etiquetas diferentes |
| .rez | Node.js | Tea.encrypt original + descifrado TEA modificado, Base64 | **self-roundtrip**, no validación criptográfica independiente |
| .rezl | Node.js | mismo contenedor que .rez | imprime `(.rez)`, rótulo heredado |
| .maya | Python | AES-256-CBC + parseo JSON NoobCrypt | fixture con campos raíz simples; campos interiores especiales no cubiertos |
| .xui | Python | AES-256-CBC + JSON NoobCrypt | variante de clave diferente; no autenticidad de archivo de fabricante |
| .mrc | Python | PBKDF2-SHA256 + AES-GCM y XML | comparte entrada de prueba con .mtl |
| .mtl | Python | PBKDF2-SHA256 + AES-GCM y XML | tiene la misma salida del ejemplo que .mrc |
| .mina | Python | SHA-256(password) + AES-CBC + JSON | password derivado del octal estático del script |
| .tnl | Python | PBKDF2-SHA256 + AES-GCM, parser de entries | esta ruta imprime JSON, sin banner; versiones OPL/OpenTunnel pendientes |

**Nota de compatibilidad:** las diez muestras proceden de generadores internos, NO de versiones actuales de las apps. El generador REZ utiliza la función `Tea.encrypt` que ya forma parte del archivo histórico `rez.js`, aislándola en un contexto de Node sin acceso a `require`/FS/red durante el cálculo; se valida la ruta de descifrado CLI pero **no** es una implementación criptográfica de referencia independiente. El formato `.tvt` figura en el registro apuntando a `rez.js`, sin embargo el filtro de extensión de dicho decoder **rechaza .tvt**, por lo que deliberadamente NO se marca como golden verificado.

La comparación golden usa la salida UTF-8 íntegra **producida por el ejecutable Linux real**; los diez snapshots se recopilaron de una ejecución de CI controlada, se revisaron y se fijaron con SHA-256, después se retiró el paso temporal de captura. No se normalizaron los rótulos `(.rez)` en .rezl ni los espacios y saltos de línea.

## 3. Verificaciones y resultados

- Suite original: casos TLS y EV2RAY, HT/HTB, HC, EHIL, SSC, DARK con salidas completas.
- Lote 3: diez rutas y sus datos falsos, pruebas negativas, matching de `.sksrv.png` y `.fɴ`.
- Lote 4: diez procesos CLI originales, entradas positivas con salida exacta, casos corruptos, determinismo y hashes de entrada/salida congelados.
- Lote 5: diez rutas Python/Node/PHP verificadas con salidas exactas capturadas del propio script (REZ self-roundtrip identificado), incluyendo entradas inválidas y hashes inmutables.
- La validación se hace sin invocar servicios en red. Los ejecutables `python`, `node` y `php` son necesarios **para esta suite Linux**; la futura APK no dependerá de instalaciones externas.
- Los errores específicos de proveedores/formatos modernos y la comprobación de dispositivos Android **no se han realizado**.

[Primera ejecución CI lote 4 (28 tests OK)](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37857077862). Los hashes del lote quedaron fijados después de este pase; revisar el **CI del último commit** como condición para la fusión.

## 4. Archivos permanentes del corpus

| Ruta | Propósito |
|---|---|
| `tests/golden/manifest.json` | inventario íntegro: 59 sufijos, 60 casos Linux exactos, 0 sin prueba positiva |
| `tests/golden/a23_generators.py` | punto de unión de los generadores |
| `tests/golden/a23_batch3.py` | diez fixtures Linux del lote 3 |
| `tests/golden/a23_batch4.py` | diez fixtures Linux del lote 4 (Python, Node y PHP) |
| `tests/golden/a23_batch5.py` | generadores deterministas PHP/Node/Python del lote 5 |
| `tests/golden/a23_batch5_rez.cjs` | reutilización restringida del Tea.encrypt histórico, solo tests |
| `tests/test_android_a23_batch5.py` | exactitud de diez stdout, casos inválidos y hashes lote 5 |
| `tests/golden/a23_batch5_probe.py` | utilidad manual de referencia sintética, **no se ejecuta en CI normal** |
| `tests/golden/a23_batch8_ssh.py` | último cifrado Blowfish sintético para .ssh, sin material personal |
| `tests/test_android_a23_final_ssh.py` | CLI exacto, fallo cerrado, original aleatorio en modo normal y hashes |
| `tests/golden/expected/*.txt` | 60 salidas originales byte-exact |
| `tests/test_android_a23_goldens.py` | nueve fixtures de los lotes 1 y 2 |
| `tests/test_android_a23_batch3.py` | diez casos de CLI lote 3 |
| `tests/test_android_a23_batch4.py` | diez casos de CLI lote 4 |
| `tests/golden/a23_export.py` | genera 60 archivos ficticios físicos y SHA256.json |
| `tests/golden/a23_report.py` | metadatos de los 59 y SHA-256 sin salida sensible |
| `.github/workflows/validate.yml` | tests del bot + artefacto de muestras y auditoría |

Ejecutar desde la raíz del repositorio con las dependencias Linux:

```bash
python -m unittest discover -s tests -v
PYTHONPATH=. python tests/golden/a23_report.py --output out/a23/coverage.json
PYTHONPATH=. python tests/golden/a23_export.py --output-dir out/a23/samples
```

## 5. Problemas y continuación

**A.2.3 / línea de base sintética Linux COMPLETA (59/59):** no quedan extensiones sin caso golden ficticio. Esto **no** certifica que los exportadores actuales produzcan el mismo contenedor ni que exista una APK operativa. Para pasar de evidencia sintética L2 a compatibilidad, faltan vectores externos autorizados versionados, hardening de scripts heredados (incluido `pickle.loads` whitebox) y prueba de paridad real Android en A.2.4.

**A.2.4 pendiente:** aún no existe bridge Android, ni APK, ni prueba arm64/16 KB/RTL de resultados crudos. El soporte real de una extensión debe anunciarse únicamente cuando se haya confirmado en Android y para las versiones explícitas de exportador cubiertas.

**Bugs heredados por resolver durante portabilidad:** cabeceras `(.aro)` para .cloudy y `(.tnl)` para .uwu/.ost, particularidades de espacios/saltos de línea. Durante esta auditoría se conservan tal como los imprime la implementación de referencia para no disfrazar la paridad.

Los generadores y esta documentación deben mantenerse sincronizados en cada PR junto a `status.json` y `HANDOFF.md`.

## 6. Lote 6 — diez extensiones Linux con goldens íntegros

| Sufijo | Motor | Método comprobado | Limitación |
|---|---|---|---|
| `.nm` | Python | AES-ECB/Base64 + JSON | solo primera clave histórica sintetizada |
| `.pb` | Python | PBKDF2-SHA256 + AES-GCM | contraseñas externas no verificadas |
| `.pcx` | Python | PBKDF2-SHA256 + AES-GCM | versión exportadora desconocida |
| `.nt` | Python | PBKDF2-SHA256 + AES-GCM | la fuente tenía solo clave `.NT`; corregido alias minúsculo |
| `.ziv` | Python | PBKDF2-SHA256 + AES-GCM | probada primera de dos claves históricas |
| `.vpnlite` | Python | SHA-256 + AES-CBC/PKCS7 | XML/JSON artificial simplificado |
| `.sip` | Python | AES-ECB + Java Serialization sintética | prueba solo contenedor Java simple; no resuelve VER7 |
| `.at` | Python | dos capas AES-GCM | añadido CLI `run/main`; parche estricto de autenticación de ambas etiquetas GCM con pruebas de manipulación |
| `.ipt` | Python | XXTEA de la fuente histórica | generador usa `Tea.encrypt` de STK, self-roundtrip sin independencia |
| `.stk` | Node.js | XXTEA de la fuente histórica | generador usa `Tea.encrypt` del mismo script, self-roundtrip |

Los diez tienen `expectedRawText` byte-exact, `inputSha256` y `expectedRawUtf8Sha256`, verificaciones de registro, pruebas de determinismo y entradas corruptas en `tests/test_android_a23_batch6.py`. La generación TEA usa un contexto aislado CommonJS con datos ficticios. **Ninguna de estas pruebas demuestra exportación compatible con clientes actuales ni APK Android.**

### Casos expresamente pendientes

**Nota histórica del cierre del lote 6:** los 11 sufijos citados estaban pendientes en aquel momento. El lote 7 añadió diez y el lote 8 completó `.ssh`. No tratar nunca una salida de error como golden positivo.

**Evidencia de exploración (10 salidas positivas):** [GitHub Actions 37861105855](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37861105855). El CI final tras congelar hashes es la fuente autorizada para fusionar este lote.

## 7. Lote 7 — diez nuevas rutas verificadas en Linux

| Sufijo | Método sintético comprobado | Limitaciones verificadas |
|---|---|---|
| `.ehi` | EHI contenedor binario; AES-CBC L1/L2 y XXTEA en variante BYPASS_IV | **solo BYPASS_IV**; capas estándar Argon2/ChaCha, versiones de exportador y Android no comprobados |
| `.epro` | AES-ECB con SHA1 truncado y separadores `[splitConfig]` | usa primera clave del repositorio; Node comparte librerías antiguas |
| `.gold` | SHA-256 + AES-CBC; parsea `network` local | helper de banner faltante reparado; lector de archivo añadido |
| `.npv2` | XOR del módulo Node NPV2 con VMess sintético | primera clave de `cfg/keyFile.json`; referencia de CLI sin proveedor |
| `.npv4`, `.npvt` | whitebox-CTR + prefijos NPV1/NPVTSUB1 | **misma rutina whitebox**; su blob fijo usa `pickle.loads`, riesgo de seguridad abierto |
| `.roy`, `.xtp` | transformación de nibbles + AES-CBC original | exactamente el mismo motor `xtproy.py` y muestra sintética |
| `.sut` | dos capas AES-CBC; 11 propiedades cifradas dentro de JSON | solo ejemplo ficticio; no prueba todas las versiones |
| `.tvt` | motor TEA de `rez.js` y ruta `.tvt` reactivada | reutiliza el ejemplo cifrado REZ; imprime cabecera histórica `(.rez)` |

**Pruebas:** `tests/test_android_a23_batch7.py` compara `stdout` completo, entradas inválidas, hashes SHA256, registro de extensiones y verifica que Node no altere `cfg/config.inc.json` durante una importación normal. Los casos están en `tests/golden/a23_batch7.py` y `tests/golden/expected/`. El generador TEA/REZ sigue siendo una autoparidad del código fuente, no un vector criptográfico independiente.

**Reparaciones incluidas:** `gold.py` admite `archivo.gold` como argumento y ya no falla por `stylize_math` indefinida; `rez.js` acepta `.tvt`; `chicosp.js`/`modulepro.js` no reescriben el archivo de configuración por una simple ejecución de descifrado. Los comandos explícitos de configuración siguen teniendo ese comportamiento heredado.

**Criterio de compatibilidad:** **59/59** indica *exclusivamente* muestras sintéticas Linux con hashes congelados. **0/59 Android verificados** y **0 versiones externas certificadas**. Quedan pendientes las pruebas con exportadores versionados, seguridad y portabilidad; no anunciar soporte Android 59/59.

## 8. Lote final — SSH Injector `.ssh` (Blowfish-CBC)

- Archivo ficticio con entradas `Host=example.org`, `Port=443` y una nota expresamente sintética. Se cifra con **Blowfish-CBC/PKCS#7** y la clave/IV históricos existentes en `decoders/Python/ssh.py`.
- `tests/golden/a23_batch8_ssh.py` obtiene clave e IV directamente del AST del código de referencia para evitar incoherencias. La salida se conserva completa en `tests/golden/expected/batch8-ssh.txt` y se congela con `inputSha256` y `expectedRawUtf8Sha256` en el manifiesto.
- La CLI original elegía un emoji diferente por ejecución. **Solo al establecer `SPDECODE_SSH_GOLDEN_TEST=1`** se usa una elección determinista para comprobar bytes exactos; **el comportamiento normal sigue siendo aleatorio**. Este cambio no toca claves, descifrado ni campos en bruto.
- Se rechazan archivos vacíos, cifrados inválidos y texto descifrado sin ninguna entrada XML; no se publican trazas Python ni falsos perfiles positivos. Los tests verifican explícitamente ese fallo cerrado.
- El alcance positivo es **el contenedor cifrado artificial sobre Linux**. No acredita que la app original use la misma clave en todas sus versiones; no constituye un instalador ni una verificación Android.

La línea de base L2 sintética está finalizada cuando el CI del commit fusionado en `main` confirma el corpus de **60 casos / 59 sufijos**. Los riesgos de aplicación exportadora y APK pertenecen a puertas de verificación posteriores; se mantienen expresamente abiertos.
