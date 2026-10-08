# A.2.3 — Corpus de pruebas golden reproducibles

> **Estado 2026-10-08: EN PROGRESO.** Hay **29 casos sintéticos positivos con salida íntegra congelada en 28 de 59 extensiones**. Faltan **31 extensiones sin muestra positiva**. Ninguna extensión está verificada en Android y ninguna prueba demuestra compatibilidad con versiones modernas de las apps exportadoras.

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
| **Total** | **29** | **28 de 59** | **21** |

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

## 3. Verificaciones y resultados

- Suite original: casos TLS y EV2RAY, HT/HTB, HC, EHIL, SSC, DARK con salidas completas.
- Lote 3: diez rutas y sus datos falsos, pruebas negativas, matching de `.sksrv.png` y `.fɴ`.
- Lote 4: diez procesos CLI originales, entradas positivas con salida exacta, casos corruptos, determinismo y hashes de entrada/salida congelados.
- La validación se hace sin invocar servicios en red. Los ejecutables `python`, `node` y `php` son necesarios **para esta suite Linux**; la futura APK no dependerá de instalaciones externas.
- Los errores específicos de proveedores/formatos modernos y la comprobación de dispositivos Android **no se han realizado**.

[Primera ejecución CI lote 4 (28 tests OK)](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37857077862). Los hashes del lote quedaron fijados después de este pase; revisar el **CI del último commit** como condición para la fusión.

## 4. Archivos permanentes del corpus

| Ruta | Propósito |
|---|---|
| `tests/golden/manifest.json` | inventario íntegro: 59 sufijos, 29 casos Linux exactos, 31 sin prueba positiva |
| `tests/golden/a23_generators.py` | punto de unión de los generadores |
| `tests/golden/a23_batch3.py` | diez fixtures Linux del lote 3 |
| `tests/golden/a23_batch4.py` | diez fixtures Linux del lote 4 (Python, Node y PHP) |
| `tests/golden/expected/*.txt` | veintinueve salidas originales byte-exact |
| `tests/test_android_a23_goldens.py` | nueve fixtures de los lotes 1 y 2 |
| `tests/test_android_a23_batch3.py` | diez casos de CLI lote 3 |
| `tests/test_android_a23_batch4.py` | diez casos de CLI lote 4 |
| `tests/golden/a23_export.py` | genera 29 archivos ficticios físicos y SHA256.json |
| `tests/golden/a23_report.py` | metadatos de los 59 y SHA-256 sin salida sensible |
| `.github/workflows/validate.yml` | tests del bot + artefacto de muestras y auditoría |

Ejecutar desde la raíz del repositorio con las dependencias Linux:

```bash
python -m unittest discover -s tests -v
PYTHONPATH=. python tests/golden/a23_report.py --output out/a23/coverage.json
PYTHONPATH=. python tests/golden/a23_export.py --output-dir out/a23/samples
```

## 5. Problemas y continuación

**A.2.3 permanece ABIERTA:** 31 sufijos siguen sin muestra positiva. Priorizar lotes de hasta diez por PR, **sin falsificar resultados**. Próximos candidatos del roadmap: `.ehi`, `.npv4`, `.npvt`, `.npv2`, `.epro`, `.rez`, `.rezl`, `.tvt`, `.jez`, `.hrt`. Estos incluyen whitebox, PHP y Node y podrían necesitar fixtures autorizados/versionados, además de aislar efectos colaterales Node.

**A.2.4 pendiente:** aún no existe bridge Android, ni APK, ni prueba arm64/16 KB/RTL de resultados crudos. El soporte real de una extensión debe anunciarse únicamente cuando se haya confirmado en Android y para las versiones explícitas de exportador cubiertas.

**Bugs heredados por resolver durante portabilidad:** cabeceras `(.aro)` para .cloudy y `(.tnl)` para .uwu/.ost, particularidades de espacios/saltos de línea. Durante esta auditoría se conservan tal como los imprime la implementación de referencia para no disfrazar la paridad.

Los generadores y esta documentación deben mantenerse sincronizados en cada PR junto a `status.json` y `HANDOFF.md`.
