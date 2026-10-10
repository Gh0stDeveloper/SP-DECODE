# SP-DECODE Android — Fase F: motores independientes (13 extensiones)

**Rama:** `feat/android-phase-f-independent-13`  
**Destino exclusivo:** `feat/android-decoder-parity-239` (sin cambios en `main`).  
**Criterio de validación:** paridad exacta con los **nueve módulos Python originales**, sin reescribirlos ni reemplazarlos por otro descifrador.

## F.1 — 6 extensiones

| Extensiones | Origen | Implementación |
|---|---|---|
| `.flex`, `.flexnet` | `decoders/Python/flex.py` | Encabezado FLXCFG, versiones 1–4, locks, 30 perfiles de materiales históricos, PBKDF2-HMAC-SHA512, AES-256-GCM (AAD) y descompresión zlib/gzip; XML properties con todos sus campos |
| `.izph` | `decoders/Python/izph.py` | 4 tipos de algoritmo (AES-CBC+XXTEA, Threefish-256+HKDF, PBKDF2+XXTEA+AES-CBC, HKDF+AES-CBC); descifrado anidado de Servers, Networks, ProxySettings, V2Ray y SlowDNS |
| `.lt`, `.ltm` | `decoders/Python/ltm.py` | PBKDF2-HMAC-SHA256 y AES-GCM autenticado; extracción XML Properties, incluida etiqueta comment |

La F.1 usa `IndependentF1Port.kt` e `IzphNativePort.kt`. Las constantes de Flex se exportaron sin adivinar valores: `android/app/src/main/assets/flex_f_profiles.json` mantiene las **30 variantes originales** de `FLEX_MATERIALS` con la selección version/lock del Python. Los primitivos XXTEA, HKDF y Threefish-256 de IZPH reutilizan el motor ya probado de RENZ, pero se aplican las constantes, el protocolo y el orden de procesamiento propios de IZPH.

## F.2 — 7 extensiones

| Extensiones | Origen | Implementación |
|---|---|---|
| `.crev`, `.cer`, `.cerv` | `crev.py` | XXTEA con delta CREV, 4 claves originales y descifrado de Tweaks anidados |
| `.ktr` | `ktr.py` | Serialización Java, TC_STRING/TC_LONGSTRING, AES-256-CBC, emparejamiento estricto de nombres/valores y extracción Base64 alternativa |
| `.zoba` | `zoba.py` | XXTEA y delta propio, Base64 o bytes originales; decodificación JSON/texto |
| `.dev` | `dev.py` | SkyCrypt XXTEA, transformación de caracteres y AES-CBC en campos |
| `.n4` | `n4.py` | AES-256-ECB exterior, AES-CBC y tablas de caracteres Unicode específicas para cada campo, con decodificación Morse |
| `.vn7` | `vn7.py` | PBKDF2-HMAC-SHA256 y AES-GCM con ambas contraseñas originales |

`IndependentF2Port.kt` implementa CREV, KTR, Zoba, DEV y N4. VN7 se aloja junto con F.1 por compartir extracción AES-GCM, aunque pertenece al lote de 7 extensiones indicado aquí. Ambas tablas de lotes suman las 13 extensiones sin duplicados.

## Inventario de 239 formatos

- Legacy originales: 61.
- Fase B, genéricos: 81.
- Fase C, Ultra/Sandok: 41.
- Fase D, RENZ/7NET: 16.
- Fase E, especializados: 27.
- Fase F, independientes: 13.
- **Total de rutas implementadas: 239; pendientes de implementación: 0.**
- **Certificadas con exportaciones reales actuales: 0**, según el indicador experimental del catálogo. Esto no invalida las pruebas con muestras reales realizadas anteriormente, pero impide extrapolarlas a todas las versiones y formatos.
- La certificación integral y validación con versiones reales de los exportadores será parte de la Fase H.

## Reproducción de pruebas

```bash
PYTHONPATH=. python scripts/android_a24_catalog.py
PYTHONPATH=. python -m unittest tests.test_android_f_independent_parity -v
PYTHONPATH=. python scripts/android_f_independent_fixtures.py --fixtures android/app/src/androidTest/assets/parity/f-independent-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
gradle --no-daemon :app:connectedDebugAndroidTest
```

El corpus se cifra artificialmente usando cada algoritmo original y después se pasa por el `run()` del módulo Python **antes** de probar Android. Contiene 13 vectores exteriores más 12 variantes: FlexNet v2/v3/v4/v4 con encabezado, IZPH tipo1/2/3 y campos anidados, VN7 segundo password, KTR TC_LONGSTRING, Zoba binario y CREV clave alternativa.

## Seguridad y límites

- Máximo **2 MiB** por archivo, tanto al importar por SAF como al descifrar.
- Datos y descifrados procesados localmente, sin conexión y sin almacenamiento externo no solicitado.
- Los formatos con autenticación criptográfica (AES-GCM) verifican el tag; los formatos XOR/XXTEA/CBC sin autenticación no tienen una prueba criptográfica de integridad. No se les atribuye seguridad inexistente.
- Nunca se prueban claves de otra familia ni se sustituyen algoritmos distintos por un AES genérico; se mantienen las claves históricas estrictamente por extensión/módulo.
- No se genera una APK de producción ni se fusiona a `main` en esta fase. Solo se fusiona el PR con la rama de integración cuando todas las comprobaciones finalizan en SUCCESS.
