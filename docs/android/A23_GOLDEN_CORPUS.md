# A.2.3 — Corpus sintético, golden outputs y cobertura real

> **Estado:** subfase parcialmente implementada. Los primeros 5 sufijos cuentan con 6 muestras sintéticas positivas y comparación de salida completa en Linux; otros **54/59 sufijos siguen sin muestra positiva**. **Ninguno está verificado en Android ni con versiones recientes de las aplicaciones exportadoras.** Nunca deducir compatibilidad universal a partir de estos resultados.

## 1. Objetivo y límites

Fijar ejemplos reproducibles cuya salida original, en inglés y con exactamente las etiquetas/orden/saltos de línea que imprime el decoder, no pueda cambiar accidentalmente mientras se prepara el motor Android offline. La app futura tendrá idioma de interfaz es/en/pt-BR/ar, pero **nunca traducirá resultados, campos ni rawText**.

Se usaron únicamente datos falsos: dominios reservados \`example.org\` y \`example.com\`, identificadores \`dummy\` y nombres de prueba. Los generadores construyen configuraciones a partir de los contenedores y claves ya implementados en los scripts del repositorio. Esas muestras **no proceden de exportaciones reales de versiones actuales de las apps**, por lo que prueban la regresión del propio decodificador, no su vigencia externa.

## 2. Casos positivos implementados

| Caso golden | Sufijo | Script | Generación sintética | Verificación Linux |
|---|---|---|---|---|
| tls-aesgcm | .tls | TLS.py | TLS URI + AES-GCM y contenedor de fragmentos | salida byte-exact; CLI + función |
| ev2ray-plain | .v2 | EV2RAY.py | envoltura eV2Ray en texto decodificado | salida byte-exact; CLI + función |
| ev2ray-aes128 | .v2 | EV2RAY.py | AES-128-ECB + Base64 + XOR periódico | salida byte-exact; CLI + función |
| ehil-aescbc-double | .ehil | HTTPINJECTORLITE.py | cabecera binaria EHIL + doble capa AES-CBC | salida byte-exact; CLI + función |
| ssc-chacha20 | .ssc | SSCCUSTOM.py | JSON y ChaCha20 (counter 1) | salida byte-exact; CLI + función |
| dark-aescfb-msgpack | .dark | DARKTUNNEL.py | MsgPack + AES-CFB + JSON/Base64 exterior | salida byte-exact; CLI + función |

**Cobertura positiva por extensión:** 5/59 (tls, v2, ehil, ssc, dark). El sexto caso es otra variante **del mismo sufijo .v2**, no un nuevo sufijo. **Faltan 54/59**, incluidas variantes como .ht/.htb, .npv4/.npvt, .ehi, .hc, .hat y los puertos JS/PHP.

## 3. Fuentes permanentes, sin depender del chat

| Ruta versionada | Contenido |
|---|---|
| \`tests/golden/manifest.json\` | 59 filas con status por sufijo, 6 cases, SHA-256 congelados de entrada y salida, versión exportadora = no verificada |
| \`tests/golden/a23_generators.py\` | creación determinista en memoria de los seis inputs a partir de datos ficticios |
| \`tests/golden/expected/*.txt\` | seis archivos de resultado **completo original**, no resumen, sin traducción ni normalización |
| \`tests/test_android_a23_goldens.py\` | tests contra snapshots, CLI, URI/sufijos, entradas corruptas, tags alterados y hashes congelados |
| \`tests/golden/a23_report.py\` | genera reporte de metadatos, cobertura, tamaños y digests sin imprimir outputs |
| \`tests/golden/a23_export.py\` | exporta los seis archivos físicos con extensión real y SHA256.json, para pruebas manuales posteriores |
| \`docs/android/A2_FIXTURE_POLICY.md\` | condiciones de procedencia, redacción de datos y niveles de evidencia |

Los archivos binarios de prueba **se generan al ejecutar el exportador**: no es necesario almacenar dos copias opacas de sus bytes en Git. Las fuentes y snapshots son duraderas; los artefactos de Actions tienen retención limitada.

## 4. Ejecutar en Linux/CI

Necesita el entorno del proyecto con \`requirements.txt\`. **En la aplicación Android terminada NO será necesario instalar Python, Node ni PHP desde fuera.**

~~~bash
python -m unittest discover -s tests -v
python docs/android/audit_decoders.py --output-dir out/android-a2
PYTHONPATH=. python tests/golden/a23_report.py --output out/a23/coverage.json
PYTHONPATH=. python tests/golden/a23_export.py --output-dir out/a23/samples
~~~

La ruta \`out/a23/samples\` contiene inputs sintéticos listos para importar manualmente y una lista SHA256. Los outputs congelados correspondientes están en \`tests/golden/expected\`. No subir outputs reales ni archivos ajenos.

## 5. Aserciones de regresión

- **Exactitud total:** \`decode(bytes)\` se compara con **todo** el texto de \`expected/{caseId}.txt\`. No usar comparaciones débiles (\`assertIn\`) como única aceptación de golden.
- **Paridad CLI Linux:** ejecutar CLI Python en archivo temporal; comprobar returncode 0, stderr vacío y stdout = golden + terminador LF que añade \`print()\`. Este test **no es Android**; A.2.4 implementará puente y ABI.
- **Hash congelado:** SHA-256 determinista para datos de entrada y salida; fallo en caso de deriva incluso si cambian accidentalmente muestras o snapshots.
- **Negativos:** entradas vacías, contenedores malformados, claves magic incorrectas, hex SSC impar, AEAD TLS con ciphertext manipulado. Deben terminar sin datos de éxito, nunca inventar campos.
- **Rutas/sufijos:** registry de los 59 y longest-match para \`.sksrv.png\`, Unicode \`.fɴ\`, nombres en mayúsculas.
- **Integridad del manifiesto:** 59 sufijos contra \`decoders.json\`, seis cases, estados honestos para faltantes, Android no verificado.

## 6. CI / evidencia

GitHub Actions ejecuta \`test_android_a23_goldens.py\` como parte del comando de tests general y, si pasa, exporta:
- \`spdecode-android-a23-golden-coverage\`: JSON de cobertura, hashes, y directorio samples con seis archivos sintéticos + SHA256.json. Solo metadata en logs.
- Auditor A.2 previo: \`spdecode-android-a2-audit\`.

**Evidencia previa a la última validación:** [run 37841162225 — success](https://github.com/Gh0stDeveloper/SP-DECODE/actions/runs/37841162225), con 20 tests aprobados y seis casos golden. Antes de cerrar el PR verificar el último SHA, incluyendo hash congelado y exportación.

Ninguna etiqueta Android «verified» debe asignarse basándose en esta CI: aquí solo corren funciones Python en Linux.

## 7. Riesgos, pendientes y siguiente trabajo

1. **Faltan 54 sufijos con fixture positivo autorizado.** Clasificarlos explícitamente en \`manifest.json\` como \`fixture_missing\`. No adoptar ejemplos sin procedencia para aparentar cobertura.
2. **Falta fuente externa de formato vigente:** los seis casos son construcción sintética; versiones de exportadores **no verificadas**.
3. **Faltan negativos específicos** para la mayoría de los restantes 54 sufijos; los corruptos de los 5 cubiertos están en tests.
4. **A.2.4 / C.4:** no existe puente Android, Chaquopy wheels ni ejecución en dispositivo arm64; sin paridad local Android.
5. **E/JSPHP:** los seis casos cubren Python; aún faltan muestras positivas y ports para todos los scripts Node.js/PHP.
6. **Seguridad:** el exportador solo crea datos ficticios; si en el futuro se incorporan muestras autorizadas, usar almacenamiento cifrado privado cuando incluyan datos sensibles, y no adjuntarlas automáticamente a Actions.

## 8. Estados y definición estricta de cierre

- **A.2.3:** \`in_progress\` con corpus inicial reproducible: 6 casos de 5 sufijos, snapshots completos y negativos.
- **A.2.4:** \`not_started\`: paridad Linux ↔ Android con bridge.
- **A.2 global:** \`in_progress\`; no cerrar hasta resolver faltantes de muestras/revisión o documentar exenciones de alcance aprobadas.
- **Android verificadas:** \`0/59\`; **APK:** no existe.

La decisión de qué sufijos quedan \`not_available\` en una futura v1.0 puede evitar bloquear el lanzamiento indefinidamente, **pero jamás anunciar soporte para esos formatos** sin pruebas y decisión explícita del propietario del producto.
