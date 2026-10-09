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


## 6. Incremento siguiente: TLS Tunnel AES-GCM nativo (PR pendiente)

El [PR #16](https://github.com/Gh0stDeveloper/SP-DECODE/pull/16), rama `feat/android-a24-tls-aead-parity`, incorpora el adaptador nativo
`TlsReferencePort`, sin Chaquopy ni servicios de red. Reproduce el
contenedor sintético `tls-aesgcm` con clave histórica de referencia,
reconstrucción de nonce de 36 bytes, AES-256-GCM **autenticado** y los campos
JSON ordenados sin traducir. La serialización reproduce el comportamiento
`json.dumps(..., ensure_ascii=False)` de Python, sin escapar barras `/` como
`JSONObject.quote` de Android. Un tag incorrecto se rechaza sin producir texto
parcial. El tamaño de entrada se limita a 1 MiB.

La preparación `scripts/android_a24_prepare.py` genera ahora **tres**
referencias con SHA-256 congelado: dos variantes e-V2Ray y un caso TLS.
Hay pruebas instrumentadas de comparación byte por byte para TLS y rechazo de
datos corruptos / input sobredimensionado. El catálogo contempla
`v2` (2 muestras), `tls` (1 muestra), **57 sin port** y **0 certificados**.

**Evidencia pendiente en este PR:** ejecución del job Android real sobre el
nuevo commit; la aprobación del emulador será exclusiva para las muestras
sintéticas. La validación sobre arm64, 16 KiB y exportadores actuales sigue
sin estar realizada. El port TLS se añadió como referencia experimental y no
se habilitó una UI de importación al usuario.

## 7. Incremento A.2.4: lote de diez adaptadores Kotlin (PR #17, en revisión)

**Nuevos formatos experimentales:** `.phc`, `.mina`, `.vpnlite`, `.cloudy`, `.mij`, `.fnnetwork`, `.uwu`, `.sksrv`, `.maya`, `.xui`. Se añaden **diez adaptadores separados**, cada uno con su contraseña/clave, IV/salt/nonce, contenedor y formateador original. Sólo se comparte JCA/PBKDF2, bytes, límites y utilidades neutras; esto no fusiona los algoritmos por extensión.

- `PhcPort`: PBKDF2-SHA256/1000, AES-GCM y XML.
- `MinaPort`: clave octal → SHA256 → AES-CBC, IV cero.
- `VpnLitePort`: SHA256(password UTF-8), Base64(IV + AES-CBC), parser histórico.
- `CloudyPort`: AES-CBC con clave/IV propios, JSON; conserva encabezado heredado `.aro`.
- `MijPort`: PBKDF2-SHA256 con contraseña Ed+U+0001, AES-GCM y XML.
- `FnNetworkPort`: contraseña/criptografía original FNNetwork y filtro XML independiente.
- `UwuPort`: PBKDF2-SHA256 contraseña Ed, AES-GCM y encabezado heredado `.tnl`.
- `SksrvPort`: contraseña propia SKSRV, AES-GCM y XML. El sufijo compuesto `.sksrv.png` sigue no implementado en este lote.
- `MayaPort`: NoobCrypt AES-256-CBC exterior + AES-GCM para campos internos, clave propia.
- `XuiPort`: misma librería NoobCrypt original, pero clave XUI diferente y adaptador separado.

**Puertas de calidad:** 13 fixtures congelados con hashes SHA-256 (`.v2`×2, TLS×1, 10 nuevos), 10 tests positivos Kotlin separados y una prueba con 30 casos fallidos; tests del catálogo y Linux. Las referencias son **sintéticas**; no representan exportaciones actuales. Si CI no ha aprobado la rama, estos diez formatos permanecen `experimental_batch10_synthetic`, no certificados ni disponibles en UI. `androidVerifiedSuffixes=0`; quedan 47 sin port (y el sufijo `.sksrv.png` sin ruta propia). Debe probarse en arm64 y 16 KiB después.

### Resultado CI inicial del lote (sin router)

[GitHub Actions #37872655497](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37872655497):
Linux `validate` **success** y Android emulador API 35 x86_64 **success**.
Los 10 tests de paridad nuevos, pruebas de entrada inválida y regresión anterior
pasaron en emulador. Se añade después `AndroidOfflineDecoderRouter`, que
selecciona 1:1 por extensión y no intenta claves de otros decodificadores.
La versión con router se somete a una segunda ejecución CI antes de fusionar.
Ningún hardware arm64, exportador moderno ni página 16-KiB comprobado.

## 8. Lote A.2.4 adicional — diez extensiones (`batch20`, PR en revisión)

Formatos y métodos originales: `.at` (AES-GCM ×2 con seed + constante),
`.nm` (lista NetMod de claves AES-ECB original), `.ost` y `.sbr`
(DES-ECB con **claves distintas**, no se prueban claves de otro formato),
`.pcx`, `.nt`, `.pb` (contraseñas propias PBKDF2-SHA256/AES-GCM y filtros XML),
`.aro` (Base64 + rotación +18, campos Base64), `.ipt` (descifrado XXTEA personalizado
y filtro), `.gold` (SHA256/AES-CBC y descifrado de campos JSON recursivos).

Se añadieron diez clases Kotlin propias, `Batch20Primitives` para primitivas
JCA/formatos de texto; 10 comparaciones de output UTF-8 byte por byte frente a
Linux y 30 pruebas negativas. `AndroidOfflineDecoderRouter` enruta solo por
sufijo, sin mezclar claves. Se incluyen diez golden SHA-256 congelados en
`android_a24_prepare.py`. Catálogo: 22 sufijos experimentales, 37 sin port,
59 registrados, **0 certificados en exportadores actuales**.

**Gates pendientes:** Linux + Android compile + emulador API35 para los
últimos cambios; después ARM64, páginas 16KB y archivos reales autorizados.

### Evidencia final de la segunda tanda (lote batch20)

CI final de PR #18: [run 37876235386](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37876235386).
Los jobs Linux `validate` y Android API 35 x86_64 terminaron en
`success`. Android informó **31 tests instrumentados ejecutados,
31 correctos**, que incluyen los diez tests nuevos byte por byte,
la selección exacta por sufijo, los 30 rechazos de entradas malformadas
y todas las pruebas de los lotes anteriores. Las diferencias de
indentación detectadas en `.at` y `.nm` durante el primer intento
se corrigieron y se revalidaron en esta ejecución.

**Alcance:** sólo referencias sintéticas, no exportaciones actuales.
`.ost` y `.sbr` utilizan DES heredado y no tienen autenticación;
`.nm` usa AES-ECB y `.gold` AES-CBC, también sin autenticación del
contenedor. Esas debilidades pertenecen a los formatos originales: el
lector Android debe mantener estas rutas desconectadas, con límites y
sin registrar secretos, sin atribuirles garantías de autenticación.

## 9. Tanda Android A.2.4 — quince sufijos nativos (PR en revisión)

Extensiones: `.agn`, `.cly`, `.fɴ`, `.jvc`, `.jvi`, `.v2i`,
`.sksrv.png`, `.xscks`, `.mrc`, `.mtl`, `.jez`, `.hrt`,
`.ziv`, `.epro`, `.npv2`.

- **MultiDES:** seis dispatchers de extensión independientes usan la *misma secuencia de claves*
  del script `multides.py`; éste no diferencia realmente las claves por extensión.
  Los seis golden verifican el **primer miembro** de esa secuencia, no variantes
  actuales de cada proveedor. DES-ECB no autentica los datos.
- `.sksrv.png` reutiliza el motor de `.sksrv` porque `decoders.json` apunta
  ambos al mismo script; detección prioriza el sufijo compuesto.
- `.xscks`: AES-CBC con la contraseña Base64 literal del código original y SHA256.
- `.mrc`/`.mtl`: AES-GCM + PBKDF2 con clave de su propio script y filtro XML,
  manteniendo el formato histórico de cada salida.
- `.jez`/`.hrt`: AES-CBC + SHA256, traducción del comportamiento PHP, con
  filtros de impresión independientes.
- `.ziv`: los dos passwords de ZIV únicamente, autenticación AES-GCM y campos XML.
- `.epro`/`.npv2`: ports de `lib/methods/eProDecryptor.lib.js` y
  `npv2Decryptor.lib.js`, con snapshots offline de las listas de claves fuente
  y el layout inglés original, sin runtime Node, escritura de config ni Internet.

Preparación de **38 vectores SHA256 sintéticos para 37 sufijos experimentales**;
**22 sin portar**; 59 inventariados; **0 certificados de exportador actual**.
La prueba Android nueva incluye 15 comparaciones completas, rutas deterministas
y 45 entradas rechazadas. Pendiente CI API35 x86_64 y ARM64 físico/16KiB.
