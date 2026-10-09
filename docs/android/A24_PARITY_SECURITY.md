# A.2.4 — Paridad Android, matriz de evidencia y seguridad (en progreso)

> Estado: PR #15, rama \`feat/android-a24-parity-runtime-security-baseline\`. **NO es aplicación de producción.** Cobertura con Linux sintético: 59/59 sufijos (60 casos). **Android certificado 0/59**. Ningún exportador tercero vigente o ABI arm64 están certificados.

## 1. Alcance del primer incremento

Se creó \`android/\` como host nativo **de instrumentación y prueba únicamente**, package \`com.ghostdeveloper.spdecode\`, minSdk 24, compileSdk 35 y JDK 17. No se añadió permiso INTERNET, ACCESS_NETWORK_STATE, almacenamiento total, login, Telegram, conexión HTTP ni servicios remotos. Se deshabilita backup. El Activity de prueba muestra explícitamente que no es una interfaz de importación. Las fases B/C/D/E requeridas para una aplicación usable siguen abiertas.

\`V2RayReferencePort.kt\` porta a Kotlin JCA AES/ECB/PKCS5Padding y XOR de e‑V2Ray y conserva el \`rawText\` histórico para **dos casos sintéticos**. Las entradas y snapshots exactos se generan por CI con \`scripts/android_a24_prepare.py\`, exclusivamente desde \`tests/golden/manifest.json\`. Cambios de digest se rechazan antes de ejecutar Gradle.

| Caso | Referencia Linux | Motor Android | Criterio y limitación |
|---|---|---|---|
| \`ev2ray-plain\` | \`tests/golden/expected/ev2ray-plain.txt\` | Kotlin JCA/Base64 | stdout exacto UTF-8 en AndroidTest; solo combinación conocida de campos |
| \`ev2ray-aes128\` | \`tests/golden/expected/ev2ray-aes128.txt\` | Kotlin JCA AES-128/XOR | stdout exacto UTF-8 en AndroidTest; solo primera clave y contenedor de muestra |
| los otros 58 sufijos | 58+ fixtures Linux | Sin adaptador Android verificado | Pendiente por D/E; no marcar Android compatible |

Nota: \`.v2\` ocupa 2 vectores de 1 sufijo. Un test emulator x86_64 para esos casos **no confirma ARM64, 16 KiB ni compatibilidad de exportadores actuales**. No se han implementado pruebas de idiomas, SAF ni una app Android completa.

## 2. Puertas de CI obligatorias

1. \`validate\` Linux existente: 60 muestras, 59 sufijos, stdout exacto, 47+ pruebas, auditoría de fuentes, seguridad NPV y hashes, pruebas negativas.
2. \`android-parity\` nuevo: JDK17, Gradle8.11.1, AGP8.9.2, SDK35, creación de assets verificando SHA256, \`:app:assembleDebug\` y \`:app:assembleAndroidTest\`, **emulador conectado Android API35 x86_64**, comparación exacta de 2 casos y rechazos de entradas inválidas.
3. Prueba instrumentada de AndroidManifest final: prohibir permisos Internet, red, almacenamiento heredado y all-files.
4. Se publican test reports; el APK debug publicado, si existe, se identifica como **host de prueba sin funcionalidad de usuario**, NO release.

Una compilación Gradle no equivale a una prueba instrumentada. No fusionar si alguno de ambos jobs falla. CI PASS de estas dos muestras no modifica \`androidVerifiedSuffixes\` a 59: requiere pruebas arm64/device y evidencia de exportador por versión.

## 3. Riesgos de motores y medidas

| Área | Hallazgo | Control integrado | Pendiente |
|---|---|---|---|
| Python NPV4/NPVT | blob \`pickle.loads\` embebido: posible deserialización activa si se alterara el artefacto | Unpickler sin globales/classes, rechazo de opcodes constructores/REDUCE, bytes descomprimidos limitados a 96 MiB, trailing bytes prohibidos, pruebas de regresión | Migrar a tablas declarativas inertes con checksum; portar whitebox y validar memoria arm64 |
| Python Gold | \`requests\` importado, no usado | Retirado import para evitar dependencia de red innecesaria | Distinguir deobfuscación de valores; no aceptar URL como servicio en app |
| JavaScript Node (6 scripts) | carga de \`fs\`, recursos JSON, procesos y eventual escritura de preferencias | Sin runtime Node en la app; pruebas Linux siguen con comportamiento previo salvo fixes existentes | Port Kotlin/Java sin IO global, sandbox y fixtures independientes de proveedor |
| PHP (3 scripts) | OpenSSL y diferencias de cadenas/bytes | Solo Linux fuente histórica | Port Kotlin/Python + PKCS y bloques incompletos, sin PHP externo |
| Python wheels nativas | pycryptodome, argon2-cffi, msgpack, cryptography | Solo primer vector e-V2Ray en JCA sin wheels | Spike Chaquopy arm64, x86_64, 16 KiB, reproducción offline |
| Entradas hostiles | cripto fallida, input grande, rutas y metadatos | En prototipo V2Ray entrada limitada a 1 MiB, salida \`null\` para invalidez, error sin stack o red | SAF streaming, ZIP bombs, cuotas por decoder, timeouts, errores localizados |
| Exposición de secretos | salida de herramientas históricas contiene credenciales | Assets CI ficticios; no almacenar histories ni exportar en host | Keystore AES-GCM, privacidad UI, política clipboard y retención |

## 4. Plan restante para cerrar A.2.4

- **A.2.4.1** Contrato y ejecución Android instrumentada de datos sintéticos: en curso, 2 casos .v2 como primer alcance.
- **A.2.4.2** Paridad Kotlin/Chaquopy de cada ruta: 59 sufijos con casos normales/erróneos, labels/rawText, orden y buffers; todo offline.
- **A.2.4.3** ABI arm64, API 24–36, 16 KiB, app real con SAF, emulador + dispositivo físico; costeo wheels y dependencias.
- **A.2.4.4** Matriz versiones de exportador (muestras autorizadas), fuzz/corrupción, auditoría de secretos y hardening sin CRITICAL.
- **Puerta de cierre:** ninguno de los 59 se anuncia como soportado Android por tener un golden Linux. Cerrar solo con trazabilidad versionada, CI y dispositivos representativos.

Comandos de prueba desde raíz:

\`\`\`sh
PYTHONPATH=. python scripts/android_a24_prepare.py --output-dir android/app/src/androidTest/assets/parity
python -m unittest discover -s tests -v
cd android && gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
# Con emulador conectado:
gradle --no-daemon :app:connectedDebugAndroidTest
\`\`\`

## 5. Primer resultado instrumentado confirmado (PR #15)

La ejecución [GitHub Actions #37868719536](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37868719536) compiló el host con Gradle8.11.1/AGP8.9.2 y arrancó un emulador Android API35 **x86_64**. Resultado: **4 pruebas instrumentadas aprobadas**, incluyendo raw UTF-8 exacto de e‑V2Ray plano y AES128, corrupción y permisos de red/almacenamiento. La suite Linux independiente también pasó. Este resultado certifica solamente los **dos vectores sintéticos**; no es una prueba en arm64 ni con exportadores externos. El nuevo catálogo generado registra 59 sufijos, pero mantiene **58 sin motor Android y 0 certificados**. La matriz se actualizará con CI definitivo del PR y de `main` tras integración.
