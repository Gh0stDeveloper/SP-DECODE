# SP-DECODE Android — Fase A: catálogo de 239 formatos

**Alcance:** infraestructura de migración, generador reproducible, lectura Kotlin, estados, seguridad de importación, pruebas y documentación. No incorpora criptografía de las fases B–G.

## A.1 — Fuente canónica y protección de la funcionalidad anterior

- El bot registra **239 formatos** en `spdecode.registry.DECODER_REGISTRY`.
- Los **61 formatos históricos** provienen de `decoders.json`. Sus rutas nativas Kotlin y scripts de referencia se mantienen.
- Los **178 formatos nuevos** figuran en el catálogo Android con estado `registered_not_implemented`, sin motor nativo y sin alegar compatibilidad.
- `.ost` conserva su motor histórico; el fallback Ultra existente no se sobreescribe.

## A.2 — Inventario generado automáticamente

El generador `scripts/android_a24_catalog.py` combina el registro real del bot con `decoders.json`. Si detecta 239/61/178 distintos, una extensión duplicada, un alias sin fase, una ruta legacy remapeada o un asset anticuado, falla explícitamente.

El archivo `android/app/src/main/assets/decoder_catalog.json` utiliza **schemaVersion 3** con los campos `inventorySource`, `legacyInventorySource`, `botRegisteredSuffixes`, `androidExistingSuffixes`, `androidPendingNativeSuffixes`, `migrationCounts`, `syntheticLinuxCoveredSuffixes`, `androidCertifiedSuffixes`, `androidPrototypeSuffixes` y `entries`.

Cada entrada incluye `suffix`, `name`, `script`, `originalRuntime`, `linuxGoldenSynthetic`, `androidPortStatus`, `androidVerified`, `exporterVersionsVerified`, `migrationPhase` y `sourceCatalog`.

Los perfiles pendientes tienen `androidVerified=false`, `linuxGoldenSynthetic=false`, `exporterVersionsVerified=[]` y `sourceCatalog=spdecode.registry`. No significa que sus scripts Python no tengan pruebas: significa que todavía no forman parte del corpus congelado de paridad Android A23.

**El catálogo no contiene contraseñas, claves RSA, bytes de cifrado ni secretos**: solo metadatos necesarios para presentar y seleccionar formatos.

## A.3 — Distribución exacta

| Fase | Nuevas extensiones | Familias |
|---|---:|---|
| B | 81 | AES-GCM/PBKDF2 y DES-ECB genéricos |
| C | 41 | Ultra / Sandok |
| D | 16 | RENZ / 7NET |
| E | 27 | Sentinel, ITV, EUT, V2Box, SlipNet, JuanScript, WyrLite, WyrVPN, IntVPN, FTHP, AR/MSY, EC, XOR |
| F | 13 | IZPH, FlexNet, N4, CREV, KTR, Zoba, LTM, DEV, VN7 |
| **Total** | **178** | Todos pendientes de motor nativo |

Las extensiones compuestas como `.sksrv.png` y Unicode como `.fɴ` conservan la detección de mayor longitud y sin distinción de mayúsculas. Los protocolos de texto de la fase G mantienen un registro separado y no se cuentan como extensiones nuevas.

## A.4 — Barrera de ejecución y UX

- `AndroidDecoderCatalog.kt` valida el esquema 3, 239 sufijos únicos, 61 rutas anteriores, 178 pendientes y cero certificados formales. `hasNativeDecoder` solo es verdadero para los 61 originales.
- `AndroidOfflineDecoderRouter.kt` rechaza los 178 pendientes antes de seleccionar motor, sin intentar algoritmos de otra familia.
- `MainActivity.kt` rechaza el formato nuevo antes de leer su contenido e informa que el motor nativo aún está pendiente.
- `SpDecodeApp.kt` muestra estados diferenciados y FlowRow para los alias largos, evitando desbordes en pantallas pequeñas.
- Mensajes y notas actualizados en español, inglés, portugués brasileño y árabe.

No se modifican los algoritmos criptográficos antiguos, los resultados descifrados, el historial, los permisos ni el acceso sin conexión.

## A.5 — Pruebas y auditoría

- `tests/test_android_a24_catalog.py` comprueba coincidencia exacta contra el registro del bot, nombres, rutas, 61 motores originales, 178 estados pendientes, conteos de fases, ausencia de secretos y generación determinista.
- `PhaseA239CatalogInstrumentedTest.kt` comprueba la lectura del asset en Android real/emulador, clasificación de estados, Unicode, sufijos compuestos y rechazo de formatos nuevos.
- Las pruebas Android anteriores de paridad e historial se actualizan para 239 formatos sin retirar las comprobaciones funcionales de los 61 originales.

Comandos:

```bash
python scripts/android_a24_catalog.py
python -m unittest tests.test_android_a24_catalog -v
python -m unittest discover -s tests -v
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
# Con emulador conectado:
gradle --no-daemon :app:connectedDebugAndroidTest
```

Los checks de Linux y Android API35 son obligatorios; compilar no equivale a ejecutar pruebas instrumentadas.

## A.6 — Límites de fase y publicación

La fase A no incrementa el número de motores disponibles. Mantiene 239 formatos **registrados**, de los cuales 178 no pueden descifrarse todavía en la aplicación. El corpus de CI sigue marcando `androidCertifiedSuffixes=0`; no se inventa validación real de exportadores.

La rama de integración es `feat/android-decoder-parity-239`; los cambios de A entran a esa rama por PR y **no se fusionan a `main`**, para no activar la publicación de APK firmada antes de acabar las fases B–H.

**Cierre A:** 239 entradas reproducibles, ninguna colisión, 61 rutas originales intactas, 178 bloqueadas, UX localizada, tests Python y Android satisfactorios. La siguiente fase B portará los motores genéricos y habilitará formatos progresivamente después de validar su paridad.
