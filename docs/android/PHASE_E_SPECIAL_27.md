# SP-DECODE — Fase E: 27 formatos con motores específicos Android

**Rama:** `feat/android-phase-e-special-27`  
**Integración:** `feat/android-decoder-parity-239` (no `main`).  
**Fuente canónica:** 13 módulos bajo `decoders/Python/`, previamente integrados y probados desde `66.py`.

## Inventario cerrado

| Sublote | Motores originales | Extensiones | Total |
|---|---|---|---:|
| E.1 | Sentinel, ITV, EUT, V2Box, SlipNet, JuanScript | `.st`, `.itv`, `.eut`, `.v2box`, `.slipnet`, `.juanscript`, `.juan`, `.mobi` | 8 |
| E.2 | WyrLite, WyrVPN, IntVPN, FTHP, AR/MSY, EC | `.wyrvpnlite`, `.wyrlite`, `.wyrl`, `.wyr`, `.int`, `.fthp`, `.ftp`, `.ar`, `.msy`, `.ec` | 10 |
| E.3 | XOR VPN (motor compartido) | `.apnalite`, `.apnatnl`, `.bdnet`, `.hxt`, `.fnf`, `.4ulite`, `.omanova`, `.ursa`, `.hsome` | 9 |

**Catálogo tras fase E:** 226/239 nativos, 13 de F sin motor Android, cero certificados respecto a versiones actuales de exportadores. Las rutas legacy de fases A–D se conservan.

## Implementación

- `SpecialCrypto.kt`: AES-GCM, AES-CBC, AES-CFB, ChaCha20-Poly1305, PBKDF2-HMAC-SHA256 para derivaciones con sal vacía, SHA-256 y HMAC, UTF-8 y GZIP acotado. Ningún servicio remoto.
- `SpecialE1Port.kt`: Sentinel combina transformación reversible XOR/bloques, HMAC y GCM; ITV reproduce fielmente la extracción de entradas XML sobre la secuencia AES-GCM **no autenticada** de su script original; EUT recursivo AES-CBC; V2Box con claves fijas y bloqueo honesto cuando hace falta contraseña de usuario; SlipNet GCM con offset de cabecera alternativo; JuanScript AES-GCM + checksum + GZIP + PBKDF2.
- `SpecialE2Port.kt`: WyrLite con variantes autenticadas ChaCha20-Poly1305 y AES-GCM; WyrVPN e IntVPN AES-GCM y campos anidados; FTHP con sus dos derivaciones PBKDF2; AR/MSY CBC y CFB; EC XXTEA con longitud original.
- `SpecialE3Port.kt`: nueve sufijos XOR, hex estricto y descifrado recursivo de cadenas hexadecimales.
- `AndroidOfflineDecoderRouter.kt`: selecciona exclusivamente el motor correspondiente al script registrado. No prueba claves de otro formato.
- `MainActivity.kt`: archivos E aceptan hasta 2 MiB, en igualdad con los motores, para evitar rechazo previo a descifrar.

## Evidencia de paridad

`scripts/android_e_special_fixtures.py` genera un corpus desde los 13 decodificadores Python originales y lo cifra usando sus algoritmos, sin muestras de usuarios. Su contraparte `PhaseESpecialInstrumentedTest.kt` compara el resultado completo en un dispositivo Android real/emulado:

- 27 vectores por extensión y salida integral.
- Cuatro variantes adicionales: WyrLite AES-GCM, SlipNet con cabecera opcional, clave alternativa FTHP y V2Box protegido.
- Rechazo de entradas malformadas, aislamiento frente a formatos F pendientes y regresión A–D.
- `tests/test_android_e_special_parity.py` exige que el Python original reproduzca cada resultado.

## Límites y seguridad

- **V2Box protegido:** la app muestra el requisito de contraseña. No suplanta la clave definida por el exportador, no la deduce y no anuncia un descifrado no realizado.
- **ITV:** su referencia descifra flujo GCM sin verificar etiqueta; para mantener paridad se implementa la secuencia CTR equivalente. **No es autenticación criptográfica**, y el usuario no debe confiar en su integridad.
- **XOR:** codificación reversible, no cifrado seguro.
- Nunca se transmiten datos, claves o contenidos a servidores externos. Ni logs de configuraciones sensibles.
- No se confunde `androidVerified=false` con soporte nativo experimental. La certificación con exportaciones reales actualizadas queda expresamente para la fase H.

## Criterios de aceptación

```sh
PYTHONPATH=. python scripts/android_a24_catalog.py
PYTHONPATH=. python -m unittest tests.test_android_e_special_parity -v
PYTHONPATH=. python scripts/android_e_special_fixtures.py --fixtures android/app/src/androidTest/assets/parity/e-special-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
gradle --no-daemon :app:connectedDebugAndroidTest
```

Para fusionar el PR a la rama de integración deben pasar Python, Gradle y todas las pruebas API 35. No se firma ni se publica una versión de producción en esta fase.
