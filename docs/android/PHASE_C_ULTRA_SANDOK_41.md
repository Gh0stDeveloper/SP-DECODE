# SP-DECODE Android — Fase C: Ultra / Sandok (41 extensiones)

**Rama de integración:** `feat/android-decoder-parity-239`
**Rama de trabajo:** `feat/android-phase-c-ultra-sandok-41`

## Alcance y estado

- Nuevas rutas nativas: **41 extensiones**; `ultra.py` enumera **42**, pero `.ost` permanece en el port histórico `OstPort` y conserva su script `decoders/Python/ost.py`.
- Catálogo Android: **239 registrados = 61 legacy + 81 genéricos B + 41 Ultra/Sandok C + 56 pendientes (D–F)**.
- Se mantienen cero certificaciones formales de exportadores actuales hasta validar exportaciones reales autorizadas.

## Paridad criptográfica con el bot

`decoders/Python/ultra.py` es el referente autorizado. El archivo original tiene **19 perfiles** con contraseñas históricas de descifrado específicas y memoria Argon2id de **4096, 8192 o 16384 KiB**. La app reproduce **Argon2id versión 0x13**, 3 iteraciones, paralelismo 1 y clave derivada de **32 bytes**, usando Bouncy Castle ya disponible en Gradle.

El formato de archivo exterior es Base64 de `salt(16) || nonce(12) || ciphertext || tag(16)`, con autenticación AES-256-GCM. Se acepta la variante con AAD=`salt` y la histórica sin AAD, pero siempre se valida la etiqueta. El archivo puede incluir un prefijo `://` y la fuente admite los candidatos Base64 limpio, con padding añadido y reparación acotada.

El port replica la prioridad de perfil por extensión, detección histórica por contenido y la lista de 16 perfiles de fallback. No consulta APIs de terceros. Las claves de los perfiles se derivan del script Python; la manifestación Base64 no oculta esos valores y **no se confunde con secretos de usuario o claves privadas de firma**.

Si el JSON descifrado contiene campos `BugDNS`, `CustomProxy`, `Payload`, `SNI`, `V2rayAddress`, `V2rayConfig`, `V2rayHost`, `V2raySNI`, `Info`, `Host` o `Server`, se intenta un descifrado AES-GCM adicional con la segunda contraseña del perfil. Las etiquetas inválidas conservan el valor original, igual que Python. Se mantienen todos los campos JSON y se añaden `_vpn_type` y `_vpn_key` para diagnóstico de la familia.

## Artefactos

| Archivo | Responsabilidad |
|---|---|
| `scripts/android_c_ultra_profiles.py` | Genera y comprueba los 19 perfiles y 41 alias a partir de `ultra.py`, más vectores sintéticos de referencia |
| `android/app/src/main/assets/ultra_c_profiles.json` | Inventario nativo de perfiles y parámetros, sin URLs remotas |
| `UltraProfileStore.kt` | Lectura estricta, validación de parámetros Argon2id y aislamiento de `.ost` |
| `UltraSandokPort.kt` | Argon2id + AES-256-GCM, AAD alternativo, descifrado de once campos y resultados JSON completos |
| `AndroidOfflineDecoderRouter.kt` | Selección exclusiva de fase C sin cambiar los 61 casos originales del router |
| `AndroidDecoderCatalog.kt` | Estado nativo C, 183 activos y 56 pendientes |
| `tests/test_android_c_ultra_parity.py` | Registro de origen, fidelidad de perfiles, generador y salida Python |
| `PhaseCUltraInstrumentedTest.kt` | Vectores nativos Kotlin en emulador, sin respuestas simuladas |

## Sublotes de pruebas

- **C.1–C.3:** 10 sufijos por tanda, dos variantes autenticadas (AAD y sin AAD) cada uno.
- **C.4:** últimos 11 sufijos, completando las 41 nuevas rutas nativas.
- **83 vectores positivos para los 41 nuevos sufijos:** 41 exteriores con AAD, 41 sin AAD y uno de perfil alternativo. Se agregan **2 vectores para la colisión `.ost`**, sin sumar una nueva extensión, y se comprueba el golden DES previo.
- Los 11 nombres de campo cifrado se prueban de manera positiva en perfiles con memorias de 4096, 8192 y 16384 KiB, sin repetir derivaciones innecesarias para los 41 alias.
- Pruebas negativas: etiquetas GCM alteradas, contenido truncado, entrada vacía, formatos erróneos y aislamiento entre familias.
- La salida JSON se compara completa con la referencia Python incluyendo valores vacíos, booleanos, arrays y Unicode.

## Verificación reproducible

```bash
PYTHONPATH=. python scripts/android_c_ultra_profiles.py --check
PYTHONPATH=. python scripts/android_a24_catalog.py
PYTHONPATH=. python -m unittest tests.test_android_c_ultra_parity -v
PYTHONPATH=. python scripts/android_c_ultra_profiles.py --fixtures android/app/src/androidTest/assets/parity/ultra-c-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
# Solo con un emulador real conectado:
gradle --no-daemon :app:connectedDebugAndroidTest
```

## Seguridad y restricciones

- AES-GCM verifica siempre el tag; **no** se muestra salida no autenticada.
- Argon2id consume como máximo 16 MiB por derivación, con concurrencia secuencial por archivo.
- No se introducen descargas automáticas de las URLs históricas de Ultra ni se incorpora Python/Node al APK.
- El catálogo de formatos **no contiene claves**; el asset específico de perfiles sí contiene las constantes históricas necesarias, y por tanto es reversible y no debe tratarse como almacén secreto.
- `.ost` conserva primero el motor DES de OUSS, **con fallback Ultra/Sandok AES-GCM autenticado únicamente si DES no reconoce un XML válido**, igual que `decoders/Python/ost.py`. No aumenta el conteo de 41 extensiones nuevas: `.ost` sigue registrada como legacy. Los dos envoltorios Ultra (.ost con y sin AAD) se prueban contra vectores Python, junto al golden DES original y una etiqueta GCM alterada.
- Las otras 56 extensiones continúan bloqueadas. No se publica una APK estable ni se fusiona con `main` antes de superar las fases restantes.

**Criterio de cierre:** generador exacto, batería Python en verde, Gradle en verde y pruebas instrumentadas API35 en verde. Solo entonces fusionar el PR a `feat/android-decoder-parity-239`.
