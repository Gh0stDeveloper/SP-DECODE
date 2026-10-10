# SP-DECODE Android — Fase D: RENZ / 7NET

**Rama:** `feat/android-phase-d-renz-16`  
**Destino:** `feat/android-decoder-parity-239`; jamás `main` antes de Fase H.

## Alcance y registro

- 16 nuevas extensiones: `.7net`, `.actunnelvpn`, `.actun`, `.xhypher`, `.tcx`, `.bshield`, `.osp`, `.safetunnel`, `.mhrtunnel`, `.letsvpngo`, `.aloplusvpn`, `.cranetunnel`, `.vipsnipherpro`, `.deshtunnelvpn`, `.hamotunnelplus`, `.gcpvpn`.
- 14 perfiles criptográficos compartidos. `.osp` reutiliza `7net`; `.actun` usa `actunnelvpn`, exactamente como el bot.
- 239 en catálogo = 61 legacy + 81 genéricos + 41 Ultra/Sandok + 16 RENZ + 40 pendientes.
- `.vlx` permanece Ultra/Sandok y `.izph` continúa reservado para Fase F. El código nunca ensaya motores no asignados como fallback.
- No se reclama compatibilidad certificada con exportadores actuales; se necesitan muestras reales autorizadas.

## Componentes Android

| Componente | Uso |
|---|---|
| `RenzPort.kt` | Motor local AES-128/256-CBC, XXTEA fuente-original, Threefish-256, HKDF-SHA256, PBKDF2 y tipos RENZ 0–3 |
| `RenzProfileStore.kt` | Inventario acotado, sin URL externas ni claves privadas |
| `renz_d_profiles.json` | Semillas, IV y sales derivadas estrictamente de `decoders/Python/renz.py` |
| `scripts/android_d_renz_profiles.py` | Generación y validación reproducible; exporta vectores Python para pruebas Android |
| `PhaseDRenzInstrumentedTest.kt` | 16 rutas exteriores, 4 tipos históricos y 2 anidados; compara documentos JSON completos |
| `tests/test_android_d_renz_parity.py` | Valida fuente Python, inventario, alias, claves y resultados de referencia |

## Selección criptográfica

1. Decodificar únicamente extensiones registradas con `migrationPhase=D` (16). Entrada máxima de 2 MiB, procesamiento completamente local.
2. Conservar prioridades del motor `renz.py`: perfiles normales Base64 → AES-CBC → XXTEA personalizado → transformación de bytes por aplicación. `.tcx` aplica el orden especial XXTEA → AES-CBC y claves fijas.
3. Solo para `7net` y su alias `.osp`, ante un fallo de descifrado/JSON, probar los tipos de compatibilidad 0, 1, 2 y 3. Type 1 reproduce la implementación pura Threefish-256 de la fuente Python.
4. En un JSON correctamente reconstruido, descifrar recursivamente campos cifrados por función: `host/path` → HKDF/Threefish-256/AES-CBC; `username/password` → PBKDF2/XXTEA/AES-CBC; otros → método principal y alternativo. Los campos cuyo método falle permanecen originales.
5. Conservar `application`, `extension`, `config` y todos los campos del documento sin truncarlos deliberadamente. No almacenar claves del usuario ni subir datos a APIs.

**Seguridad importante:** AES-CBC, XXTEA y Threefish no incluyen autenticación. Los vectores positivos demuestran paridad con Python, pero JSON parseable no constituye prueba criptográfica de integridad. En caso de corrupción, rechazar fallos de estructura/padding; nunca prometer detección universal de modificaciones de ciphertext.

## Lotes y pruebas

- **D.1:** primeras ocho extensiones por orden estable.
- **D.2:** últimas ocho extensiones.
- **D.3 de regresión transversal:** Type 0, Type 1, Type 2, Type 3, host cifrado con Threefish y username protegido con PBKDF2/XXTEA.
- **22 vectores positivos Python:** 16 externos + 4 tipos históricos + 2 anidados, además de rechazos de entradas malformadas, prefijos equivocados y aislamiento de familias.
- Pruebas previas A–C deben mantenerse íntegramente en SUCCESS.

## Reproducción

```sh
PYTHONPATH=. python scripts/android_a24_catalog.py
PYTHONPATH=. python scripts/android_d_renz_profiles.py --check
PYTHONPATH=. python -m unittest tests.test_android_d_renz_parity -v
PYTHONPATH=. python scripts/android_d_renz_profiles.py --fixtures android/app/src/androidTest/assets/parity/renz-d-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
gradle --no-daemon :app:connectedDebugAndroidTest
```

**Criterio de cierre:** Python green, Gradle green, 22 vectores de referencia en emulador API35, regresión completa y fusión exclusivamente a rama de integración. Las pruebas reales de distintas versiones exportadoras siguen siendo una condición de la Fase H.
