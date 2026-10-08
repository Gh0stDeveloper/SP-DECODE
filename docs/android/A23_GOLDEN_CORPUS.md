# A.2.3 — Corpus golden incremental y soporte comprobable

> **Estado (2026-10-08): A.2.3 en progreso.** Hay **9 casos sintéticos con salida íntegra y hashes SHA-256 para 8 de 59 sufijos**; **51 sufijos** continúan sin caso positivo. Compatibilidad Android: **0/59 verificados**. No se han ensayado muestras exportadas por versiones actuales de aplicaciones externas.

## Alcance y seguridad

Los casos se construyen con datos falsos (dominios reservados, identificadores sintéticos) y algoritmos de empaquetado derivados del código de referencia actual. **No son archivos producidos por los clientes VPN reales**; demuestran que las rutas de descifrado del repositorio funcionan con contenedores sintéticos y que su salida no cambia en Linux. No garantizan compatibilidad con versiones modernas de exportadores. No se exponen contraseñas operativas ni servicios reales.

La app Android sigue planificada como totalmente offline, sin login ni Telegram. Los cuatro idiomas afectan **solo la interfaz**; `rawText` de los decodificadores conserva exactamente etiquetas, orden, mayúsculas, Unicode y saltos de línea sin traducción.

## Casos que tienen golden Linux

| ID | Sufijo | Decoder | Construcción y ruta ejercitada |
|---|---|---|---|
| `tls-aesgcm` | `.tls` | TLS.py | TLS URI y AES-GCM, reconstrucción de segmentos |
| `ev2ray-plain` | `.v2` | EV2RAY.py | cuerpo eV2Ray decodificado |
| `ev2ray-aes128` | `.v2` | EV2RAY.py | AES-128-ECB, Base64 y XOR |
| `ehil-aescbc-double` | `.ehil` | HTTPINJECTORLITE.py | contenedor binario EHIL, doble AES-CBC |
| `ssc-chacha20` | `.ssc` | SSCCUSTOM.py | ChaCha20 y JSON |
| `dark-aescfb-msgpack` | `.dark` | DARKTUNNEL.py | MsgPack y AES-CFB |
| `httptweak-v1-ht` | `.ht` | HTTPTWEAK.py | **variante 1:** tablas de sustitución, 12 rondas, CBC, zlib y Base64 |
| `httptweak-v2-htb` | `.htb` | HTTPTWEAK.py | **variante 2:** tablas distintas del mismo cifrador, CBC, zlib y Base64 |
| `httpcustom-chacha-rst` | `.hc` | HTTPCUSTOM.py | **new-format**: XOR inicial, ChaCha20 y payload RST/AES-ECB |

**Total:** nueve casos, ocho sufijos, siete scripts principales distintos; 51 sufijos y 41 scripts distintos no cuentan con golden positivo. Los sufijos `.ht` y `.htb` comparten script, pero requieren pruebas individuales. La presencia del golden no autoriza publicar el formato como «Android verified».

## Evidencias de verificación

La suite `tests/test_android_a23_goldens.py` comprueba:
- coincidencia de **todo el texto original**, carácter por carácter, contra `tests/golden/expected/*.txt`;
- SHA-256 congelados del input y del output UTF-8;
- generación determinista y reportes de cobertura que fallan ante una modificación no autorizada;
- CLI para los nueve casos. **Excepción consciente:** `HTTPTWEAK.py` imprime JSON limpio desde `main()`, mientras que su `run()` devuelve una cabecera y pie adicionales. Ambas rutas se prueban contra sus expectativas reales, no se equiparan artificialmente;
- inputs corruptos o vacíos, autenticación TLS manipulada, sufijos simples/compuestos y variantes.

**CI de referencia para el bloque 2 (antes de congelar hashes):** [GitHub Actions #37854337089](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37854337089) — 20 tests correctos, nueve muestras positivas, ocho sufijos, 51 pendientes; los hashes del bloque nuevo se congelaron en `manifest.json`. El commit final debe repetir CI antes de fusionarse.

## Fuente versionada y comandos

| Ruta | Propósito |
|---|---|
| `tests/golden/manifest.json` | inventario de los 59, estados honestos, SHA-256 de nueve casos |
| `tests/golden/a23_generators.py` | generar contenedores sintéticos reproducibles |
| `tests/golden/expected/*.txt` | nueve snapshots de resultado bruto (no traducción) |
| `tests/test_android_a23_goldens.py` | pruebas golden, negativos, CLI, sufijos |
| `tests/golden/a23_report.py` | reporte de cobertura y hashes sin datos sensibles |
| `tests/golden/a23_export.py` | exportar nueve archivos físicos sintéticos, con sumas SHA-256 |
| `docs/android/HANDOFF.md` | continuidad verificada entre chats |

```bash
python -m unittest discover -s tests -v
PYTHONPATH=. python tests/golden/a23_report.py --output out/a23/coverage.json
PYTHONPATH=. python tests/golden/a23_export.py --output-dir out/a23/samples
```

La configuración del workflow `.github/workflows/validate.yml` conserva las pruebas del bot y adjunta el artefacto `spdecode-android-a23-golden-coverage` con JSON de cobertura y samples ficticios. La evidencia en Actions tiene retención temporal, pero los generadores/snapshots de Git persisten.

## Qué falta y próximos lotes

- **51 sufijos sin muestras positivas**; su estado sigue siendo `fixture_missing`. Casos con mayor prioridad: `.ehi`, `.npv4`, `.npvt`, `.hat`; después scripts PHP/Node y los restantes.
- Versiones actuales de aplicaciones exportadoras no verificadas en ningún golden.
- Auditar entradas negativas por variante. Los casos genéricos vacíos/corruptos no reemplazan la matriz completa.
- **A.2.4/C.4:** todavía no existe bridge Python Android ni tests ARM64, ABI/16 KB, modo avión o APK funcional.
- Las variantes HT actuales son específicas de las tablas probadas. No indicar que funciona el formato XV5 autenticado que el código rechaza explícitamente.
- Solo se pueden pasar los formatos a «verificado Android» con paridad funcional de importación, adaptación, seguridad y dispositivo real.

**Cierre honesto:** se integró otro lote progresivo de goldens Linux; A.2.3 y A.2 general **permanecen abiertas**.
