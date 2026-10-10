# SP-DECODE Android — Fase B: 81 motores genéricos nativos

**Rama de integración:** `feat/android-decoder-parity-239`
**Rama de desarrollo:** `feat/android-phase-b-generic-81`
**Estado de alcance:** implementar AES-GCM/PBKDF2 y DES-ECB nativamente en Android, sin cambiar los 61 motores previos, los textos ni el bot.

## B.1 — Inventario exacto

| Indicador | Cantidad |
|---|---:|
| Formatos del catálogo | 239 |
| Motores Android históricos | 61 |
| Extensiones nativas nuevas de Fase B | 81 |
| Extensiones con perfil AES-GCM | 74 |
| Extensiones con perfil DES-ECB | 13 |
| Extensiones presentes en ambas tablas | 6 |
| Total de rutas Android disponibles en el código | 142 |
| Extensiones C–F pendientes de portar | 97 |
| Compatibilidad certificada con exportadores actuales | 0 |

Las seis extensiones con ambos algoritmos son `.acm`, `.htp`, `.pin`, `.tut`, `.vmx` y `.xsks`. Se comprueba el formato DES primero y AES-GCM autenticado como segunda ruta **únicamente si el sufijo tiene una clave AES propia**. Nunca se prueban contraseñas de otro sufijo.

## B.2 — Archivos principales

- `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/GenericVpnPort.kt`: motor único de descifrado Android con AES-GCM, PBKDF2-HMAC-SHA256 por bytes y DES-ECB con validación estructural.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/GenericProfileStore.kt`: consulta local de los 81 perfiles, validación de esquema, recuentos, unicidad de sufijos y codificación Base64 estricta.
- `android/app/src/main/assets/generic_b_profiles.json`: exportación reproducible de los perfiles históricos para **únicamente** las 81 extensiones nuevas.
- `scripts/android_b_generic_profiles.py`: generador y auditoría del catálogo de claves y de los casos de prueba, derivado directamente de `decoders/Python/generic_profiles.py` y del registro de Telegram.
- `scripts/android_a24_catalog.py`: el catálogo v3 pasa a 61 nativos históricos + 81 genéricos nativos + 97 pendientes.
- `AndroidOfflineDecoderRouter.kt`: selecciona el motor genérico según `migrationPhase=B` sin insertar alias en el `when` de los 61 decodificadores anteriores.
- `tests/test_android_b_generic_parity.py`: valida paridad del inventario, las claves y los vectores de descifrado Python.
- `PhaseBGenericInstrumentedTest.kt`: realiza la comparación de resultados **dentro del emulador Android**, no solo una auditoría estática.

## B.3 — Paridad criptográfica con Python

### AES-GCM

1. Entrada: `Base64(salt).Base64(nonce).Base64(ciphertext || tag)`, con límites de tamaño y tres segmentos exactos.
2. Contraseña: bytes históricos exactos del perfil asociado al sufijo. Algunas incluyen bytes de control (`Ed\x01`), por lo que no se convierten mediante PBEKeySpec en el motor principal.
3. Derivación: PBKDF2-HMAC-SHA256, **1000 iteraciones** y clave de **16 bytes**.
4. AES-GCM con tag de **16 bytes**, verificada obligatoriamente con `doFinal()`. Se rechazan errores de autenticación, corrupción de UTF-8 y contenedores inválidos.
5. Salida: JSON completo, XML con entradas repetidas y vacías, o texto UTF-8 autenticado. Los datos originales no se truncan deliberadamente.

### DES-ECB

1. Clave de ocho bytes: truncada o completada con NUL conforme a `generic_des.py`.
2. Cifrado binario directo; variante adicional de contenido DES envuelto en Base64.
3. No se informa de éxito sin obtener UTF-8 correcto y un contenedor XML con `<entry>` o un objeto/arreglo JSON válido.
4. DES-ECB **no está autenticado**. Este port existe por compatibilidad histórica, no para generar nuevas exportaciones cifradas.

## B.4 — Plan de ocho lotes, completos en esta fase

Los perfiles se ordenan de forma estable por sufijo, sin inferencias a partir del nombre de la aplicación. Se prueban siete lotes consecutivos de diez sufijos y un último lote de once. **7×10 + 11 = 81**. Dentro de cada lote se ensayan todos los vectores presentes, también los seis perfiles duales.

### Cobertura comprobable

- AES-GCM: al menos **74 vectores positivos independientes** creados con el algoritmo Python autorizado.
- DES-ECB: **26 vectores** (13 binarios y 13 con envoltura Base64).
- **100 vectores criptográficos positivos** en total, generados automáticamente antes de compilar tests Android.
- **74 comprobaciones negativas** de etiqueta GCM alterada, además de corpus malformado, tamaño límite y aislamiento de claves entre extensiones.
- Los resultados Android se comparan como documentos JSON completos con la salida de los motores Python, no con capturas o subcadenas parciales.
- Las pruebas estáticas preservan la selección de sufijos compuestos, los 61 motores antiguos y las 97 rutas todavía deshabilitadas.

## B.5 — Reproducibilidad

```bash
PYTHONPATH=. python scripts/android_b_generic_profiles.py --check
PYTHONPATH=. python scripts/android_a24_catalog.py
PYTHONPATH=. python -m unittest tests.test_android_b_generic_parity -v
PYTHONPATH=. python scripts/android_b_generic_profiles.py --fixtures android/app/src/androidTest/assets/parity/generic-b-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
# Con emulador API35 conectado:
gradle --no-daemon :app:connectedDebugAndroidTest
```

En `validate.yml` se exige que el catálogo de perfiles empaquetado coincida exactamente con la fuente Python. Los vectores generados solo se utilizan como *fixtures* de test y no entran en el APK de producción. Los paquetes Android son offline y no requieren ejecutar Python.

## B.6 — Seguridad, estabilidad y distribución

- Los identificadores y contraseñas históricas de aplicaciones que el bot ya publica se incluyen en el APK **solo si son imprescindibles** para esas 81 extensiones. La codificación Base64 **no constituye protección**: cualquier constante incluida en el APK es recuperable. No se empaquetan claves privadas de usuario, contraseñas de cuentas ni secretos de firma.
- No existe comunicación con Telegram, un servidor, una API, Termux o un motor Python en ejecución.
- No se registra contenido sensible; los errores devuelven null y no se fuerzan resultados falsos.
- Los 97 formatos pendientes continúan bloqueados. El catálogo no certifica compatibilidad con versiones actuales de exportadores externos.
- No se fusiona a `main` ni se ejecuta una publicación firmada hasta cerrar las fases C–H.

## B.7 — Condición estricta de cierre

Fase B se considera terminada solo cuando el PR pase **todas las pruebas Python**, compile las clases Android y ejecute **las ocho tandas de vectores** más los casos negativos en el emulador Android API35; después, fusionar únicamente con `feat/android-decoder-parity-239`. La siguiente fase será C: Ultra/Sandok.
