# NPV Tunnel — memoria de investigación del descifrado NPVS v5 y v6

Documento para retomar esta investigación en otro chat o tras una actualización.
Conserva los descubrimientos, el bloqueo resuelto y las comprobaciones que
permiten distinguir un cambio de formato de un error de implementación.
Investigación inicial: 10 de octubre de 2026 UTC. Validación recipient v6: 11 de octubre de 2026 UTC.

## Retomar en dos minutos

- Aplicación comprobada: **NPV Tunnel 124.0.37**, versionCode **577**, paquete
  `com.napsternetlabs.napsternetv`. Archivo real: contenedor binario `NPVS`,
  versión 5, cabecera compacta versión 1, modo app-key 2, keyId 2.
- Script funcional: [`decoders/Python/npvs.py`](../decoders/Python/npvs.py),
  referencia inmutable en commit
  [`a4ca82c2a3b81fd9baa8ef8b802958c6d76755b4`](https://github.com/Gh0stDeveloper/SP-DECODE/commit/a4ca82c2a3b81fd9baa8ef8b802958c6d76755b4),
  rama `analysis/npvs-v5`. Solo requiere PyCryptodome; lleva las tablas de la
  aplicación comprimidas y no usa APK ni emulador durante la ejecución.
- El núcleo Go explica el contenedor y sus AEAD. La pieza que faltaba estaba
  en **`libnpvtunnel.so` + `assets/rt.dat`**: un evaluador white-box del que se
  obtiene el material para abrir la clave del documento.
- Bloqueo principal: **la APK adjunta estaba firmada otra vez**. Su certificado
  de pruebas daba una derivación incorrecta. La huella del certificado original
  se verificó con el HMAC interno nativo, no por una conjetura sobre el texto.
- La muestra terminó con todas las verificaciones válidas: ECDSA, DEK,
  metadatos, contexto, inventario y 107 registros. Se reconstruyeron una
  configuración y 106 valores escalares más su estructura.
- Antes de investigar una versión nueva, probar el script actual con un
  exportado nuevo. No usar el decodificador antiguo `NPVTUNNEL.py` para forzar
  este formato, ni sobrescribir sus métodos existentes.

Guía breve de ejecución: [`NPVS_V5_PYTHON.md`](NPVS_V5_PYTHON.md). Este handoff
no depende de que sobrevivan los archivos temporales de la sesión original.

## Material que identifica la investigación

El adjunto ZIP contenía un APK combinado. Se extrajeron las dos bibliotecas
ARM64, los DEX y el recurso cifrado. La versión Go del núcleo se identificó como
1.27.1; no basta tomar la primera cadena `go1.*` que aparezca en un binario,
porque también contiene referencias a otras versiones.

| Material | Tamaño / SHA-256 |
| --- | --- |
| APK combinado suministrado | 62 579 879 bytes; `246323d3b9979036bd0f5b60b8de7bf25c7adfdef0d3e6952787c3de2daa6379` |
| ARM64 `libgojni.so` | 38 920 432 bytes; `ea5c68f088256b648b91c0ca009ad7f6d144e5d107608f622a5f564c9bc8891b` |
| ARM64 `libnpvtunnel.so` | 58 296 bytes; `6ba05d3ac27f28b1b058b1162c0c0de0009fff47fc876b7e924f3288b1fd7c89` |
| `assets/rt.dat` cifrado | 749 617 bytes; `0c56b43e7a60e312e80ff163088f32ab25c4bdbbcd677f046c78d9f61b0cd9fd` |
| Tablas white-box recuperadas | 749 569 bytes; `35717e8267a115fbf474e3cd622066783feea21305457c840cabd57a73086f7d` |
| Muestra real `.npvs` | 5443 bytes; `2e321bb8c506dbac8a1b2848ff8a05fb4f811df34536853b2a965d6dfd197867` |

Herramientas utilizadas: Python y `zipfile`; Androguard para DEX; pyelftools
para carga ELF/relocaciones; Capstone para ARM64; Unicorn para ejecutar solo el
fragmento nativo necesario; PyCryptodome para SHA-256, HMAC, AES-CTR, HKDF,
ChaCha20-Poly1305 y ECDSA. No se compiló Android ni se realizó una importación
en un emulador Android. La emulación fue del código ARM64 extraído.

## Cómo se localizó el método

1. Se inspeccionó el archivo real antes de probar algoritmos antiguos. Su
   cabecera `NPVS\x05` y las longitudes internas indicaban un contenedor
   versionado, no una cadena Base64 ni el formato de exportados anteriores.
2. Se extrajeron los símbolos de funciones Go de `libgojni.so` usando `pclntab`.
   Las búsquedas por `Compact`, `Sealed`, `Source`, `AppKey` y `fieldconfig`
   localizaron el importador, la apertura de la DEK y el almacén de campos.
3. El enlace DEX es
   `Llibnpvtunnel/Libnpvtunnel;->openCompactEnvelopeForImport(...)`.
   En el APK analizado lo invoca `Lah/m;->i(...)`; ese nombre del llamador está
   ofuscado y no debe tratarse como un identificador estable.
4. Se siguió `OpenCompactEnvelopeForImport` → `OpenCompactEnvelope` y las
   funciones de apertura de metadatos/source. Se recuperaron formato binario,
   firma, AAD, etiquetas HKDF y reconstrucción del documento.
5. `appKeyGen2Kdk` conducía al cargador externo `npvtunnel_rt_load` de
   `libnpvtunnel.so`. Allí se encontró `assets/rt.dat` y la derivación nativa
   dependiente del certificado y del código de la aplicación. Esta era la
   razón de que conocer ChaCha20-Poly1305 no bastara para abrir la muestra.

### Símbolos Go que sirven de punto de entrada

Direcciones virtuales del ELF ARM64 comprobado. Bajo ASLR se suman a la base
real; para leer el archivo hay que convertir VA a offset mediante ELF.

| Función, sin el prefijo común | VA comprobada | Qué permite recuperar |
| --- | --- | --- |
| `appKeyGen2Kdk` | `0x1f1e270` | Paso Go → generador nativo de KDK |
| `openCompactMetadata` | `0x1f20950` | HKDF, nonce y AAD de metadatos |
| `OpenCompactEnvelopeForImport` | `0x1f20e80` | Entrada del importador |
| `decodeSealedWireThroughVersion` | `0x1f22840` | Longitudes, versión y rangos binarios |
| `verifySealedSignature` | `0x1f23440` | R/S P-256 y rango firmado |
| `canonicalSealedJSON` | `0x1f32bd0` | Canonicalización de la cabecera fuente |
| `decodeSourceEnvelope` | `0x1f4acf0` | Camino del documento fuente |
| `openSourceAppKey` | `0x1f4bc90` | Desenvoltura de clave en modo app-key |
| `sourceDocumentContext` | `0x1f4e050` | Unión del documento y los metadatos |
| `fieldconfig.OpenDocument` | `0x13a9150` | Reconstrucción de la estructura |
| `fieldconfig.openStore` | `0x13ab1a0` | Inventario y registros autenticados |
| `fieldconfig.derive` | `0x13abd00` | Claves distintas por registro |

El prefijo de las primeras nueve es
`npv-tunnel-core/MobileLibrary/libnpvtunnel`; el de las últimas tres,
`npv-tunnel-core/core/fieldconfig`. Los métodos de exportación `AppKeySealDek`
y `sealCompactHeader` son útiles para contrastar el orden inverso.

La tabla Go observada comienza con `f1 ff ff ff 00 00 04 08`. A partir de
`header+8`, ocho uint64 little-endian dan `nfunc`, `nfiles`, `textStart`,
`funcnameOffset`, `cuOffset`, `filetabOffset`, `pctabOffset`, `pclnOffset`.
Cada entrada de la tabla de funciones tiene `entryOffset` y `funcOffset`
uint32; el int32 en `header+pclnOffset+funcOffset+4` apunta al nombre relativo
a `header+funcnameOffset`. La dirección es `textStart+entryOffset`.

**Detalle importante del análisis:** algunas listas iniciales del núcleo
quedaron desplazadas 0x50 por usar un origen de texto incorrecto. La tabla de
arriba corresponde a las direcciones corregidas y contrastadas con destinos
de llamadas del desensamblado. Resolver `textStart` mediante su relocación ELF
si procede; no usar ciegamente `.text.sh_addr`. En otra compilación, validar
varios prólogos y llamadas antes de aceptar un mapa de símbolos.

## El bloqueo del certificado y cómo se resolvió

La biblioteca nativa lee el APK/código, calcula resúmenes, incorpora la huella
del firmante y mezcla esos valores. Se localizaron las etiquetas
`npvtunnel/kfold/mix/v1` y `npvtunnel/kfold/salt/v1`. El resultado permite
autenticar y abrir material raíz embebido, del que depende el recurso de tablas.
Hay comprobaciones del código de biblioteca en disco y del cargado en memoria;
no se debe sustituir todo por el hash del archivo ELF completo.

La primera derivación fallaba aun reproduciendo las operaciones porque el APK
combinado tenía un **certificado Android de pruebas**. Su SHA-256 era:

`a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc`

Se contrastó con el certificado original de la distribución de NPV Tunnel,
cuya huella SHA-256 era:

`e03dcc51aad45456b97b6331c08a2f6a67eb9516e931a3e6cefcd0eeee5801d4`

Fuente externa utilizada:
[ficha de distribución de 124.0.37](https://www.apkmirror.com/apk/vonmatrix-co-ltd/napsternetv-v2ray-psiphon-ssh/npv-tunnel-v2ray-ssh-124-0-37-release/npv-tunnel-v2ray-ssh-124-0-37-android-apk-download/).
El catálogo sirvió para obtener una candidata; **la comprobación decisiva fue
criptográfica**. Al usar los 32 bytes de la huella original en la entrada nativa
correspondiente, el HMAC del material raíz coincidió. Después pasaron la
autenticación de `rt.dat`, la desenvoltura de DEK y las etiquetas de la muestra.
No se eligió un certificado porque produjera cadenas con apariencia de JSON.

En futuras actualizaciones, comprobar primero el firmante. Un paquete combinado
puede tener otra firma aunque sus bibliotecas sean las originales. Comparar
certificado y bibliotecas por separado. No parchear una APK y reutilizar el
certificado nuevo como si fuera el original; tampoco aceptar una huella publicada
sin comprobarla contra el camino criptográfico.

## Cómo se ejecutó el fragmento nativo sin Android

La emulación se hizo para recuperar y contrastar las tablas, no para convertir
el script final en un emulador. Estas anclas permiten reconstruir el pequeño
harness de extracción si una actualización cambia el recurso.

| Ancla en `libnpvtunnel.so` | Offset / VA del ELF | Uso observado |
| --- | --- | --- |
| Exportación `npvtunnel_rt_load` | `0x2f8c` | Derivación a partir de sal/configId |
| Función de material raíz | `0x4a8c` | Autenticar y obtener la raíz nativa |
| Resolución de biblioteca/APK | `0x3f9c` | Suministrar base y ruta correctas |
| Lecturas de código cargado | `0x5810`, `0x5cd8` | Comparación del código de las bibliotecas |
| Resumen de segmentos seleccionados | `0x6884` | Hash de las regiones usadas por la rutina |
| Entrada de mezcla de material | `0x8cc0` | Vector de resúmenes; incluye huella del firmante |
| Lectura de recurso ZIP | `0xd058` | Obtener `assets/rt.dat` del APK |
| HMAC-SHA256 | `0xb6c8` | Comprobar material raíz/recurso |
| AES-CTR | `0x5444` | Reproducir lectura de bytes cifrados de tablas |
| Evaluador white-box | `0x79e8` | Capturar tablas y contrastar bloques |
| Punto posterior al bloque white-box | `0x376c` | Captura del resultado de 16 bytes |

Son anclas para esta biblioteca concreta. Una versión nueva requiere localizar
sus equivalentes; no enganchar esos números a un binario con otro hash.

### Receta del harness utilizado

1. Cargar los segmentos ELF `PT_LOAD` ARM64 en Unicorn, respetando `p_vaddr`.
   Resolver `.rela.dyn` y `.rela.plt`: `R_AARCH64_RELATIVE` usa base+addend;
   símbolos externos apuntan a trampolines de Python. Preparar pila, heap y TLS
   (`TPIDR_EL0`). Las bases escogidas eran `0x1000000` para la biblioteca pequeña
   y `0x16000000` para el núcleo Go; son decisiones del harness, no constantes
   del formato. Se reprodujo el arranque auxiliar de `0x2f6c`/`0x2f84`.
2. Proporcionar `malloc`, `free`, `memcpy`, `memset`, `strlen` y las operaciones
   mínimas de archivos/mapas. La biblioteca consulta el APK, las bibliotecas y
   `/proc/self/maps`/`status`. Usar los bytes y segmentos reales, no buffers
   ficticios para los datos que intervienen en hashes.
3. Mantener las operaciones SHA/HMAC y cifrados; se pudieron reemplazar sus
   primitivas por implementaciones equivalentes Python. Se omitieron algunas
   comprobaciones de entorno/diagnóstico, conservando el recorrido criptográfico.
   No basta devolver éxito artificial en una comprobación de autenticación.
4. La mezcla de raíz recibe un vector de resúmenes en `x6` y su número en `x7`
   al entrar en `0x8cc0`. En esta muestra el vector capturado tenía 224 bytes.
   La huella del certificado se corrigió en su entrada, usando **32 bytes de
   digest**, no los 64 caracteres ASCII de la representación hexadecimal.
   Se confirmó el HMAC y se obtuvo la raíz de 32 bytes por `0x4a8c`.
5. Para `npvtunnel_rt_load`, la llamada comprobada preparó `x0=ptr(salt16)`,
   `x1=ptr(configId16)`, `x2=0`, `x3=ptr(output32)`. El cero permitía la ruta
   de resolución observada. Capturar el estado de entrada real si cambia la ABI.
6. En la entrada del evaluador `0x79e8`, el contexto estaba en `x0`: la clave
   AES-CTR de lectura de tablas en `ctx+0x10` (32 bytes), IV en `ctx+0x30`
   (16 bytes) y puntero al recurso en `ctx+0x40`; `x2` daba la longitud.
   **`ctx+0x20` no era el inicio de la clave**: solapa su segunda mitad y el IV.
   Capturar antes de que la rutina borre el material temporal.
7. Descifrar el bloque de tablas con AES-CTR y contador inicial big-endian del
   IV, sin nonce separado. Para lecturas parciales en offset `o`, iniciar en
   `IV+o//16` y consumir `o%16` bytes del flujo antes del tramo solicitado.
   Se obtuvieron 749 569 bytes y el hash de tablas indicado arriba.
8. Contrastar el evaluador Python contra el nativo y la KDK contra la salida
   nativa. Solo después eliminar la dependencia de emulación del script final.

Los archivos temporales de raíz, KDK y DEK de la muestra no se publicaron. No
necesitan conservarse para usar el script: este deriva de nuevo lo necesario
a partir de cada archivo y de las tablas de aplicación incluidas.

## Cómo se reprodujo el white-box

No se recuperó una clave AES convencional y luego se llamó a AES con ella.
Se reprodujo el **evaluador de tablas** observado. La implementación exacta
está en `_whitebox_block()` del script, separado del parser NPVS.

Las tablas descifradas tienen byte inicial 14 (número de rondas). Definiendo
`r=13`, los offsets del bloque son:

```python
xor_tables = 1
first_words = 1 + r * 24576
final_substitution = first_words + r * 16384
second_words = final_substitution + 4096
shift_rows = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
```

Cada una de las 13 rondas principales aplica ShiftRows y dos etapas de tablas
de palabras de 32 bits combinadas por tablas de nibbles. Las palabras se leen
big-endian. La última ronda aplica ShiftRows y 16 tablas finales de 256 bytes.
La entrada y salida tienen 16 bytes. Invertir bytes, cambiar el orden de las
etapas o usar XOR ordinario donde hay tablas de combinación no reproduce el
bloque nativo.

Se compararon ocho bloques independientes con ARM64. Tres quedaron en las
pruebas públicas:

| Entrada hexadecimal | Salida nativa / Python |
| --- | --- |
| `00000000000000000000000000000000` | `4878126b14231f6f522f310686001524` |
| `000102030405060708090a0b0c0d0e0f` | `f659c73d8c0fa5150e3254dfe0a1106d` |
| `ffffffffffffffffffffffffffffffff` | `65c2e1759568da2929e357d637c33664` |

El script almacena las tablas con zlib+Base85 y verifica tamaño/SHA-256 al
cargarlas. Si cambian solo las tablas de una actualización, comparar primero
estos vectores con las tablas nuevas; no reescribir innecesariamente el parser
del contenedor ni conservar un hash antiguo para datos nuevos.

## Formato y claves que finalmente abrieron la muestra

Convenciones: todos los enteros del contenedor son big-endian. `||` significa
concatenación de bytes; los prefijos se codifican ASCII. `HKDF` es HKDF-SHA256
con salida de 32 bytes. Una AEAD transporta texto cifrado seguido de tag16.

### Contenedor exterior y cabecera compacta

```text
NPVS[4] || version[1] || BE32(headerLen) || header || nonce12
        || BE32(bodyLen) || body || signature64
```

La muestra tiene `headerLen=345` y `bodyLen=5009`. La firma es ECDSA P-256
sobre SHA-256 de todos los bytes anteriores a `signature64`; R y S son de 32
bytes cada uno, sin envoltorio ASN.1 DER. Se usa la clave pública de la cabecera.
Esto valida consistencia con esa clave incluida, no identidad de un editor
externo de confianza.

| Offset dentro de `header` | Contenido |
| --- | --- |
| 0 | Versión compacta: 1 |
| 1..16 | configId de 16 bytes |
| 17..49 | Clave pública P-256 comprimida, 33 bytes |
| 50 | Modo: 2 (app-key) |
| 51..52 | Número de destinatarios, BE16 |
| 53 en adelante | Registros de destinatario, 125 bytes cada uno |
| `a=53+125*recipientCount` | keyId BE16: 2 |
| `a+2 .. a+17` | Sal de 16 bytes |
| `a+18 .. a+77` | DEK envuelta: nonce12 + ciphertext32 + tag16 |
| `p=a+78` | Longitud BE32 de metadatos cifrados |
| `p+4` en adelante | Metadatos cifrados y tag16 |

En la muestra `recipientCount=0`, `p=131` y la longitud de metadatos cifrados
es 210 bytes (194 de JSON y 16 de tag). El script puede leer el espacio de
destinatarios, pero su comportamiento con destinatarios no se validó con otro
exportado real; no generalizar a los modos recipient o passphrase.

```python
KDK = SHA256(b"npvtunnel/appkey/v2 " + whitebox(salt16) + configId16)
DEK = ChaCha20Poly1305.open(KDK, wrapped_nonce12, wrapped_cipher_and_tag,
                           aad=salt16)
metadata_key = HKDF(DEK, salt=wire_nonce12, info=b"NPVS-v5/metadata")
metadata = ChaCha20Poly1305.open(metadata_key, wire_nonce12,
                                encrypted_metadata, aad=header[:p])
```

El espacio final de `b"npvtunnel/appkey/v2 "` es parte del prefijo. El nonce
de metadatos es el del contenedor, no el nonce de la DEK envuelta. Esos dos
detalles permiten obtener longitudes correctas y, aun así, fallar la etiqueta.

### Contexto de unión entre metadatos y campos

Se reconstruye la cabecera JSON fuente, sin la clave envuelta:

```python
source_header = {
    "v": 5,
    "configId": raw_base64url(configId16),
    "issuedAt": metadata["issuedAt"],
    "creator": {
        "fp": raw_base64url(SHA256(compressed_public_key)),
        "pk": raw_base64url(compressed_public_key),
    },
    "policy": source_policy,
    "recipients": None,
}
context = SHA256(b"NPVS-v5/source-fields-v1/"
                 + canonical_json(source_header) + wire_nonce12)
```

Base64URL no lleva padding `=`. `source_policy` contiene `onlyMobileNetwork`,
`attestationLevel`, `expiresAt`, `displayMessage`, `customServerMessage` y
`configVersion` cuando no es cero (`omitempty`). Los valores por defecto y el
`null` de destinatarios deben corresponder al camino Go observado.

La canonicalización ordena claves recursivamente, usa separadores compactos y
UTF-8, y reproduce escapes Go de `<`, `>`, `&`, U+2028 y U+2029. Usar otro
orden, convertir `null` en `[]`, añadir un campo omitido o escribir Base64 con
padding cambia el contexto y hace fallar el documento. La función `_canonical`
del script y su prueba conservan el comportamiento comprobado.

### Almacén de campos y reconstrucción

```text
NPF\x01 || context32 || BE16(count)
        || [BE16(id) || BE32(cipherLength) || ciphertext_and_tag]...
        || inventoryHMAC32
```

La muestra tiene 107 registros ordenados por id: 106 escalares JSON y el
registro 65535 que describe la estructura.

```python
inventory_key = HKDF(DEK, salt=context,
                     info=b"NPV-fields-v1/inventory/" + BE16(0))
inventoryHMAC = HMAC_SHA256(inventory_key, body_without_final_32_bytes)
field_key = HKDF(DEK, salt=context,
                 info=b"NPV-fields-v1/field/" + BE16(id))
field_aad = (b"NPV-fields-v1/record/" + context
             + BE16(id) + BE32(cipherLength - 16))
scalar_json = ChaCha20Poly1305.open(field_key, bytes(12), ciphertext_and_tag,
                                   aad=field_aad)
```

El nonce cero es correcto para este formato porque cada id tiene una clave
distinta. No añadir un nonce leído del comienzo de cada campo: no existe allí.
El último BE32 del AAD representa longitud de **texto plano**, sin tag.

El registro 65535 contiene objetos/listas cuyas hojas enteras son referencias
a ids. Se reemplazan por los escalares ya descifrados, preservando strings,
booleanos, números y `null`. El decoder exige que las referencias sean válidas,
que se usen todos los registros y que el documento tenga `configs` como arreglo.
No interpreta el registro de estructura como un campo ordinario del servidor.

## Evidencia de que funcionó con el archivo real

- Firma ECDSA válida sobre el rango binario exacto.
- KDK Python igual a la obtenida de la rutina ARM64.
- DEK envuelta y metadatos con etiquetas ChaCha20-Poly1305 válidas.
- Contexto reconstruido idéntico al del almacén `NPF\x01`.
- HMAC de inventario y etiquetas de los 107 registros válidos.
- Una configuración reconstruida con 106 valores internos y sus tipos JSON.
- Documento canonicalizado para la prueba (UTF-8, claves ordenadas,
  `separators=(",", ":")`, sin formato visual), 2375 bytes; SHA-256:
  `eaa7e033fa9c5677d605628a4bbc32961c1b61c44e0e329393fe8776eaa47bfb`.
  Es el hash de `document`, no el del JSON de salida que también incluye metadata.
- CLI ejecutada con la muestra real y salida JSON completa. Diez pruebas pasan
  con la muestra original, incluidos todos sus prefijos truncados y cambios en
  firma, DEK, metadatos, contexto y HMAC.
- Para comprobar las AEAD de campos independientemente del HMAC, las pruebas
  alteran cada una de las 107 etiquetas y recalculan el HMAC del inventario con
  la clave derivada de la muestra. Se rechaza cada campo en su propia AEAD.

```sh
python -m pip install pycryptodome
python decoders/Python/npvs.py /ruta/muestra-nueva.npvs -o resultado.json
SPDECODE_NPVS_REAL_FILE=/ruta/muestra-original.npvs \
  python -m unittest discover -s tests -p 'test_npvs_v5.py' -v
```

La suite identifica el fixture original por SHA-256 y no imprime credenciales.
No sustituir ese fixture esperado por un exportado de otra versión: añadir una
prueba nueva y conservar la anterior. La comprobación de estos dos métodos
(LinkLayer y NPV Tunnel) volvió a pasar: 20 pruebas, incluyendo ambos archivos
reales.

## Retomar una actualización sin repetir toda la investigación

1. Conservar la versión nueva, APK, firmante y un exportado real nuevo. Calcular
   hashes de APK, bibliotecas y `rt.dat`; conservar script y pruebas existentes.
2. Probar el script actual. Si pasa todas las autenticaciones, documentar la
   versión adicional y comprobar contenido/tipos; una actualización de UI no
   implica por sí sola un cambio criptográfico.
3. Si falla, identificar la primera validación rota con las funciones del script
   (`_signature`, `_whitebox_block`, `_open`, `_document`). No desactivar firmas
   ni tags para obtener una salida aparente.
4. Volver a la función semántica correspondiente en Go o en el cargador nativo,
   usando las cadenas/símbolos como anclas y recalculando direcciones. Comparar
   los bytes que forman claves, AAD y contexto antes de cambiar algoritmos.
5. Si cambia white-box o la derivación raíz, repetir la extracción nativa con el
   certificado correcto y comprobar HMAC, tablas y vectores. Si solo cambió
   el protocolo Go, conservar las tablas que sigan válidas.
6. Exigir otra validación completa con archivo real, etiquetas de todos los
   campos y reconstrucción JSON. Mantener soporte previo separado si aparece
   otra versión o keyId; no aceptar una versión nueva bajo una etiqueta vieja.

| Primer fallo | Dónde concentrar la investigación |
| --- | --- |
| Cabecera/versiones/keyId | `decodeSealedWireThroughVersion`, estructura compacta y modo de exportación |
| Firma ECDSA | Rango firmado, formato R/S, clave comprimida y conversión de VA correcta |
| HMAC de raíz/recurso durante extracción | Firmante original, segmentos de código, mezcla nativa y recurso correcto |
| Vectores white-box | Hash de tablas, offsets, endian de palabras y etapas de combinación |
| AEAD de DEK | White-box, prefijo con espacio, configId, sal, nonce y AAD de envoltura |
| AEAD de metadatos | HKDF, nonce exterior y límite exacto `header[:p]` |
| Unión de metadatos | Canonicalización Go, omitempty, Base64URL sin padding, `recipients:null` |
| HMAC de inventario | HKDF inventory, contexto y rango sin los últimos 32 bytes |
| AEAD de un registro | Id BE16, longitud plana BE32, HKDF field y nonce cero |
| AEAD válidas pero estructura rechazada | Nuevo formato de layout, id reservado, referencias o tipos escalares |
| Script correcto pero fallo en SP-DECODE | Transporte de bytes, JSON metadata/document y paridad del motor integrado |

## Alcance inicial comprobado el 2026-10-10

Está comprobado **NPVS v5 app-key keyId 2 de 124.0.37 con cero destinatarios**.
No se validaron v6, recipient, passphrase ni exportados de versiones futuras.
La política se conserva como metadatos; el decoder offline no simula controles
Android de red móvil, atestación o caducidad. No confundir estas restricciones
de uso con una contraseña externa necesaria para la muestra comprobada.

No publicar APK, exportado privado, servidores, contraseñas ni claves derivadas
del exportado. Las tablas embebidas pertenecen a la aplicación y no contienen
los valores de esa configuración. Mantener `NPVTUNNEL.py`, sus extensiones y
los demás decodificadores. El encargo fue Python y pruebas reales; la integración
Android y compilación de APK quedan para una instrucción posterior.

Para otro chat, entregar este documento, el script vigente, APK nueva y exportado
real nuevo. Con ellos se puede empezar por el primer fallo sin repetir la
búsqueda completa ni depender del entorno temporal original.


## Actualización 2026-10-11: muestra NPVS v6 en modo recipient

**Estado de esta muestra de 1482 bytes: formato e importador analizados; contenido NO descifrado.** Este
hallazgo no amplía el soporte confirmado del script. No confundir la versión
del contenedor con el modo de protección, ni convertir un reconocimiento de
cabecera en una prueba de descifrado.

Se volvió a usar la APK 124.0.37 / 577 identificada arriba. La nueva muestra
privada tiene 1482 bytes y SHA-256
`40065659048a0604eb26511a92007c31fc9daef2f52b4653a844d5b903625246`.
No se adjunta al repositorio ni se publican su identidad destinataria o sus
credenciales.

### Comprobaciones sobre el archivo real

- Magic `NPVS`, versión binaria **6**, compact header versión 1.
- Cabecera de 399 bytes desde offset 9; `header[50] == 0`: modo recipient.
- Contador BE16 `header[51:53] == 1`; un registro de 125 bytes.
- Registro: fingerprint destinatario de 32 bytes y wrapped key de 93 bytes.
  El wrapped key contiene clave pública efímera P-256 comprimida (33),
  nonce GCM (12) y ciphertext con tag (48).
- Después de los registros hay un salt/binding de 16 bytes. **No** interpretar
  esos bytes como un descriptor app-key ni buscar keyId 2 en ese offset.
- Metadata cifrada: 201 bytes. Nonce exterior: 12 bytes. Cuerpo: 994 bytes,
  magic `NPF\x01`. Firma final: 64 bytes.
- Todas las longitudes cierran exactamente en 1482 bytes.
- La firma ECDSA P-256 se verificó con la función `_signature` del decoder
  vigente. La clave efímera también se importó como punto válido P-256.
  Estas comprobaciones acreditan estructura y firma, **no plaintext**.
- El script v5 rechaza la muestra explícitamente:
  `Only NPVS version 5 is supported`. No se creó un JSON descifrado.
- Los 13 tests del decoder NPV, incluidos los de la muestra real v5 y la
  normalización `npvs1:`, siguen pasando.

### Trayecto que demuestra la dependencia de una clave local

DEX de esta APK, con nombres ofuscados específicos de este build:

1. `Luh/t4;->w0` obtiene `Lah/e;->h()` y compara el fingerprint local
   `Lah/j;->b` con los recipients del archivo. Solo después selecciona
   modo 0 y obtiene el secreto mediante `Lah/t2;->a`.
2. `Lah/t2;->a` selecciona la entrada cuyo fingerprint corresponde a una
   identidad local y entrega su wrapped key a `Lah/g1;->e`.
3. `Lah/j;->e` extrae los primeros 33 bytes del wrapped key, reconstruye
   la pública efímera y calcula ECDH usando su backend local `Lah/h`.
4. Backend `Lah/g;->b`: carga la clave privada mediante AndroidKeyStore,
   alias **`npvtunnel.recipient.v1`**; usa KeyAgreement **ECDH** y
   `generateSecret()`.
5. Backend alternativo `Lah/i;->b`: obtiene una clave privada EC PKCS#8
   con `Lah/i;->c` y realiza el mismo ECDH. El fichero privado
   **`npvtunnel_recipient_v1.dat`** vive en `Context.getFilesDir()`;
   está protegido con AES-GCM por otra clave de AndroidKeyStore, alias
   **`npvtunnel.recipient.aes.v1`**. Su archivo `.pub` es público y
   no sustituye a la clave privada ni al secreto ECDH.
6. `Lah/b;->invoke` inicializa esa identidad: genera el par EC con
   KeyPairGenerator/secp256r1; para el backend alternativo cifra el PKCS#8
   antes de guardarlo. El fingerprint es SHA-256 de la pública comprimida.
   No es una constante de la APK ni deriva del nombre del archivo.
7. `Lah/m;->i` pasa al JNI `openCompactEnvelopeForImport` el envelope,
   **sharedX**, **myFp**, passphrase, recipient público, modo y timestamp.
   Sus propias cadenas de validación confirman los nombres de esos datos.

Por tanto, APK + exportado no proporcionan la clave privada destinataria
necesaria. Quitar la comparación del fingerprint o la validación de políticas
no calcula el secreto ECDH ni permite superar el tag AES-GCM. No presentar
ese cambio como solución de descifrado.

### Funciones nativas para retomar el trabajo

Direcciones virtuales ARM64 de `libgojni.so`, recuperadas mediante pclntab;
verificar símbolos otra vez si cambia la APK:

| Función Go, bajo libnpvtunnel | Dirección |
| --- | --- |
| parseCompactHeader | 0x1f1f090 |
| compactRecipientPad | 0x1f1fe80 |
| maskCompactRecipientKey | 0x1f20250 |
| compactMetadataKey | 0x1f203e0 |
| unwrapSealedDEK | 0x1f23f10 |
| openSourceRecipientWithValidation | 0x1f4b4b0 |
| openSourceDocumentKey | 0x1f4b1a0 |
| sourceDocumentContext | 0x1f4e050 |

`unwrapSealedDEK` recibe sharedX (32) y myFp (32), selecciona el
recipient correspondiente y deriva:

```text
unwrapKey = HKDF-SHA256(sharedX, salt=myFp,
                       info="NPVS-v1-wrap" || configId16, length=32)
wrappedDocumentKey = AES-256-GCM.Open(unwrapKey,
                        nonce=wrapped[33:45],
                        ciphertextAndTag=wrapped[45:93],
                        AAD=myFp)
```

**En v6 queda otra etapa:** `openSourceRecipientWithValidation` llama a
`maskCompactRecipientKey` después del unwrap. Esta función XOR del key
con el pad de 32 bytes producido por `compactRecipientPad`. Ese pad usa
`appKeyGen2Kdk`, las mismas tablas white-box y HKDF; su domain separator es
**`NPVS-v6/recipient-binding`**. Conocer el pad no recupera el key envuelto
que todavía requiere ECDH.

La metadata compacta mantiene el domain separator **`NPVS-v5/metadata`**
incluso en la ruta común usada por v6: no reemplazarlo por v6 por intuición.
`sourceDocumentContext`, en cambio, usa el formato
**`NPVS-v%d/source-fields-v1/`** con la versión del header y una cabecera
canónica. **Corrección tras la prueba real siguiente:** la función borra
appKey, passphrase y recipients antes de canonicalizar; recipients debe ser
`null` también en v6. BindingSalt lleva `json:"-"` y queda fuera de ese JSON.
La diferencia respecto de v5 es la versión del prefijo y del campo `v`.

Estas fórmulas están observadas en la APK. Su ejecución completa en esta
muestra sigue **sin validar**, pues no se dispone de sharedX/clave privada.
No implementar soporte declarado como funcional basándose solo en ellas.

### Dato indispensable para continuar con esta misma configuración

Confirmar si este archivo se importa en la instalación NPV Tunnel del usuario.
Si se importa, esa instalación posee una identidad autorizada; una nueva
exportación mediante app-key, sin vincular recipients, permite estudiar la
misma configuración sin depender de una privada de teléfono. Si el creador
puede generar esa exportación, también sirve. Validar el nuevo archivo real
antes de declarar compatibilidad v6 app-key.

Alternativamente, un secreto ECDH de 32 bytes calculado legítimamente en la
instalación destinataria, o su clave privada destinataria correspondiente,
permitiría probar la ruta recipient. Ni device ID, ni fingerprint, ni
`.pub`, ni solo el `.dat` cifrado constituyen ese secreto.

Mantener intacto el soporte v5 y todos los decodificadores anteriores.


## Validación completa 2026-10-11: recipient v6 con privada correspondiente

**Estado actual del Python: NPVS v5 app-key keyId 2 y NPVS v6 recipient
comprobados con archivos reales.** Se conserva la normalización recursiva de
valores `npvs1:`. Esta actualización no declara soporte passphrase,
v6 app-key ni versiones futuras. Las muestras anteriores de terceros
continúan sin descifrar cuando falta su privada destinataria.

### Cómo se consiguió una prueba que sí permite resolver recipient

La privada de NPV Tunnel es una identidad EC generada en cada instalación;
no una contraseña fija contenida en la APK. Las cadenas públicas y HWID
proporcionadas antes no permitían calcular el ECDH correspondiente.

Se generó un par independiente **P-256/secp256r1**, conservando su privada
PKCS#8 en un JSON privado. Se entregó solamente esta pública comprimida
SEC1, codificada Base64URL sin padding:

`Asdg2di20QoPOswmh3UPSY4f7UqJWoJXE09Ou302QkiN`

SHA-256 de sus 33 bytes, identidad usada para seleccionar recipient:

`d5026b18ba623cabeeb79d46a9c7392d0c30112386994d8e33cb0724165ec6b9`

El usuario pegó esta pública en la exportación de la aplicación y envió
el archivo real resultante. **La exportación la realizó el usuario en la app.**
No se ejecutó ni modificó Android; no se compiló APK. Se usó la APK suministrada
para seguir DEX/JNI/Go y reproducir su protocolo en Python.

Muestra autorizada de regresión, nombre local `test v2.npvs`:

- 1084 bytes; SHA-256
  `53736090f3b86b465be39793257f664b6af0a155027e804cfb671c6f06931fae`.
- NPVS v6, compact header 1, modo 0, cabecera de 532 bytes.
- Dos recipients de 125 bytes; uno coincide con el fingerprint calculado
  desde nuestra privada. No es necesario descifrar la entrada del otro.
- Metadata cifrada de 209 bytes, cuerpo NPF de 463 bytes, firma final de 64.
- Firma, AES-GCM recipient, metadata AEAD, contexto de documento,
  HMAC de inventario y AEAD de **los ocho registros** pasan.
- JSON reconstruido: un config SSH, siete valores escalares y un layout.
  El digest del documento normalizado, ordenando claves y usando JSON compacto
  UTF-8 sin espacios, es
  `1eb7c5628bb64fb8fc2f04c18db20967baa8aa33816f6972af6e318cfff73d9f`.
- La salida contiene valores legibles y tipos conservados. No se publican
  el archivo, su contraseña, el JSON privado ni ninguna privada/DEK en GitHub.

### Fórmula exacta, validada sobre este exportado

Todos los saltos de offset se calculan desde el inicio de `header`, situado
en el archivo en offset 9. Enteros de la envoltura y NPF son big endian.

```text
configId = header[1:17]
creatorPk = header[17:50]                         # SEC1 comprimida, 33
count = BE16(header[51:53])
recipient[i].fp = header[53+125*i : 85+125*i]     # 32
recipient[i].wrap = header[85+125*i : 178+125*i]  # 93
bindingSalt = header[53+125*count : 69+125*count] # 16

myPublic = SEC1_compressed(privateKey.publicKey)
myFp = SHA256(myPublic)
wrap = entrada cuyo fp == myFp

ephemeral = P256_import(wrap[0:33])
sharedX = x(ephemeral * privateScalar)            # 32, big endian
unwrapKey = HKDF-SHA256(sharedX, salt=myFp,
                       info="NPVS-v1-wrap" || configId, length=32)
maskedKey = AES-256-GCM.Open(unwrapKey,
                            nonce=wrap[33:45],
                            ciphertext=wrap[45:77],
                            tag=wrap[77:93], AAD=myFp)

kdk = SHA256("npvtunnel/appkey/v2 " || WB(bindingSalt) || configId)
pad = HKDF-SHA256(kdk, salt=bindingSalt,
                 info="NPVS-v6/recipient-binding" || configId, length=32)
DEK = maskedKey XOR pad
```

El espacio final en `"npvtunnel/appkey/v2 "` es significativo. `WB` es
la transformación white-box comprobada por los vectores del apartado v5,
con las mismas tablas embebidas. El orden es WB y luego configId.

Metadata sigue usando:

```text
metadataKey = HKDF-SHA256(DEK, salt=wireNonce12,
                         info="NPVS-v5/metadata", length=32)
metadata = ChaCha20-Poly1305.Open(metadataKey,
                                nonce=wireNonce12,
                                ciphertextAndTag=metadataCipher,
                                AAD=header[:69+125*count])
```

El BE32 de longitud de metadata está inmediatamente después del prefix;
queda fuera de AAD. El nonce exterior viene después de la cabecera completa.
Cambiar el label a `NPVS-v6/metadata` o utilizar maskedKey como DEK
produce fallo de autenticación.

### Contexto de campos: detalle que faltaba en la lectura inicial

Después de abrir metadata, reconstruir SourceHeader con `v:6`, configId
Base64URL sin padding, issuedAt, creator fp/pk y la política. Aplicar los
mismos defaults y omitempty de la ruta v5. El contexto correcto es:

```text
sourceHeader = {
  "v": 6,
  "configId": RawURL(configId),
  "issuedAt": metadata.issuedAt,
  "creator": {"fp": RawURL(SHA256(creatorPk)), "pk": RawURL(creatorPk)},
  "policy": policy_con_defaults_y_omitempty,
  "recipients": null
}
context = SHA256("NPVS-v6/source-fields-v1/" ||
                 canonicalGoJSON(sourceHeader) || wireNonce12)
```

**No incluir las entradas recipient en este JSON.** La función nativa
`sourceDocumentContext` recibe SourceHeader pero pone a cero AppKey,
Passphrase y Recipients antes de `canonicalSealedJSON`.
En esta APK se vio en las escrituras a sp+0x128, sp+0x1c8 y sp+0x1d8.
Se recuperaron además los nombres y tags JSON del tipo Go SourceHeader
(VA 0x23d3368, tamaño 200) para comprobar la correspondencia:

| Offset en SourceHeader | Campo / tag |
| --- | --- |
| 0 | AppKey / appKey,omitempty |
| 8 | Passphrase / passphrase,omitempty |
| 16 | V / v |
| 24 | ConfigID / configId |
| 40 | IssuedAt / issuedAt |
| 56 | Creator / creator |
| 88 | Policy / policy |
| 160 | Recipients / recipients |
| 184 | BindingSalt / json:"-" |

Incluir recipients dio un digest diferente del contexto almacenado en NPF.
Usar `recipients:null` y el label v6 dio coincidencia exacta, seguida de
HMAC de inventario y las ocho AEAD válidas. Esta es evidencia directa del
archivo real, además de la lectura nativa.

La apertura NPF, los HKDF inventory/field, AAD de registro y layout id 65535
son los mismos descritos para v5. No duplicar ni cambiar esa implementación.

### Uso del Python y reproducción rápida en otro chat

Dependencia: `pycryptodome`. El archivo único
`decoders/Python/npvs.py` lleva las tablas; no necesita APK, DEX, ELF,
`tables.bin` ni las claves derivadas durante análisis.

```bash
python -m pip install pycryptodome
python decoders/Python/npvs.py "test v2.npvs" \
  --private-key NPV_Recipient_Test_Key.json -o decoded.json
```

La opción acepta fichero PKCS#8 PEM/DER o el JSON privado que contiene
`private_key_pkcs8_pem`. API: `decode_npvs(data, private_key=None)`
y `run(data, private_key=None)`. El argumento admite bytes PEM/DER,
texto PEM, diccionario JSON o EccKey privado P-256. Las llamadas anteriores
`run(data)` y `decode_npvs(data)` siguen funcionando para v5 app-key.

El decoder rechaza una pública, un HWID, una privada de otra curva o una
privada cuyo fingerprint no está en la lista. No intenta deducir privadas.
No confundir `private key` de otro protocolo en un campo del config
con la identidad recipient de NPV Tunnel.

Pruebas: `tests/test_npvs_v5.py` conserva sus 13 casos, incluidos archivo
real previo y npvs1. `tests/test_npvs_v6_recipient.py` agrega ocho casos:
importación de privada, archivo real completo, API/CLI, ausencia/pública/
privada incorrecta, todos los prefijos truncados, firma, tag GCM/configId
y necesidad del binding pad. Los **21 tests NPV pasaron**, usando ambas
muestras reales; los fixtures y la privada se mantienen externos al repo.

Para ejecutar recipient real, definir `SPDECODE_NPVS_V6_REAL_FILE`
y `SPDECODE_NPVS_V6_PRIVATE_KEY`; para v5 definir
`SPDECODE_NPVS_REAL_FILE`. Los tests cotejan SHA-256 de fixtures y salida,
sin imprimir credenciales ni secretos.

### Si NPV Tunnel se actualiza

Primero probar el Python con exportado nuevo dirigido a una pública para
la que se conserve la privada. Una pública visible en la app solo identifica
destinatario; si no se tiene la privada, no hay una prueba recipient completa.

Comprobar en orden: versión/modo/longitudes → firma → coincidencia fp →
ECDH/GCM unwrap → pad v6 → metadata → canonicalización del contexto →
inventario → cada registro/layout → npvs1. Concentrarse en la primera
validación que falla. Recalcular las VA si cambia APK; utilizar como anclas
los nombres Go y labels literales del protocolo.

Mantener sin cambios los decodificadores anteriores y no declarar otras
versiones o modos como funcionales hasta validar otro archivo real.

