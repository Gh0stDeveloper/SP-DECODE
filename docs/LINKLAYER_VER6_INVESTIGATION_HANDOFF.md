# LinkLayer VPN — memoria de investigación del descifrado VER6

Documento para un agente que retome el trabajo en otro chat o después de una
actualización. Describe cómo se localizó y confirmó el método, además de qué
comparar antes de modificarlo. Investigación original: 9 de octubre de 2026;
documentación y nueva comprobación: 10 de octubre de 2026 UTC.

## Retomar en dos minutos

- Aplicación comprobada: **LinkLayer VPN 3.11.2, build 93**, paquete
  `com.newtoolsworks.linklayer`. Muestra: un `.lnk` que empieza por `VER6`.
- Implementación funcional: [`decoders/Python/linklayer.py`](../decoders/Python/linklayer.py).
  Referencia inmutable: commit
  [`81e53b6ff8b8a61aec1c81b1360663eb6bfcad5d`](https://github.com/Gh0stDeveloper/SP-DECODE/commit/81e53b6ff8b8a61aec1c81b1360663eb6bfcad5d),
  rama `analysis/linklayer-ver6`.
- La importación Java **escribe los bytes y después recarga**. El descifrado real
  está en `configuration.LoadNativeConfig` → `configuration.d`, dentro de
  `libgojni.so`. Buscar solo `importConfigContent` deja fuera el paso decisivo.
- El resultado final es **Go gob**, no JSON ni XML: `NativeConfig`, 25 campos
  raíz y 60 valores hoja. El parser debe restaurar los valores cero omitidos.
- Primero probar el script existente con un exportado nuevo. Si falla, aislar
  la primera capa distinta; conservar la implementación VER6 y su prueba real.

Guía de ejecución complementaria:
[`LINKLAYER_VER6_PYTHON.md`](LINKLAYER_VER6_PYTHON.md). Este documento se entiende
sin disponer de los archivos temporales del análisis original.

## Material y herramientas de la investigación

El adjunto `APK.zip` contenía un paquete de instalación dividido. Se extrajeron
el APK base y los splits; el código ARM64 estaba en el split de arquitectura.
No debe concluirse que falta la biblioteca porque no aparezca en el APK base.

| Elemento verificado | Tamaño / SHA-256 |
| --- | --- |
| APK base de LinkLayer | 33 568 675 bytes; `fc31acd26bf6ca5416eb886bf8b78fc8455aef7ef38f394dfc0ef86b28254f14` |
| Biblioteca ARM64 `libgojni.so` | 39 613 624 bytes; `74045c79dafc840ce8423c64fe431d8372a290183ed60837eeb99bebaedfb3fb` |
| Archivo real cifrado `.lnk` | 7270 bytes; `adf51e275152998b0743c8114a31794077b0cbf34a2bbe1389998b87c1a0799f` |
| Go gob recuperado | 2305 bytes; `1951c999d66b23abbdd082110be1832b3a593ffd5f2fd85a42a9c971b89a74b5` |

Se usaron Python, `zipfile`, Androguard para leer DEX, pyelftools para ELF,
Capstone para ARM64 y PyCryptodome para reproducir los cifrados. La biblioteca
identificaba Go 1.25.0. No hizo falta compilar Android, ejecutar un emulador ni
encontrar una contraseña externa. El script final solo necesita PyCryptodome.

## Cómo se encontró la ruta correcta

1. Se leyó la cabecera del archivo real: los primeros cuatro bytes eran `VER6`.
   Esta señal se contrastó con el código nativo; no se reutilizó un método de
   SocksIP por similitud de extensión o por el aspecto del archivo.
2. En DEX se localizaron `Models.ConfigManager` y los enlaces JNI de
   `androidclient.Androidclient`. El cuerpo de `ImportConfig(content)` obtiene
   `context.getFilesDir().getAbsolutePath()`, llama a
   `Androidclient.importConfigContent(filesDir, content)` y luego a
   `ForceReloadLinkLayerConfig()`.
3. `ForceReloadLinkLayerConfig()` llama a `Androidclient.loadConfig(filesDir)`;
   `GetLinkLayerConfig()` puede usar la misma recarga. En el código Go se vio que
   `ImportConfigContent` guarda los bytes, mientras `LoadNativeConfig` lee el
   archivo, invoca `d` y pasa el resultado a `encoding/gob`.
4. Se desensambló `configuration.d` y se reconocieron las llamadas a
   `github.com/xtaci/kcp-go` y a `golang.org/x/crypto/pbkdf2.Key`. Se inspeccionó
   también `configuration.e`, el flujo de exportación, para resolver los cortes,
   inversiones y claves anexadas. El exportador sirvió para contrastar el orden.

Existe otra ruta `importConfigContentProtected(filesDir, content, password)`.
Fue localizada, pero la muestra correspondía a la ruta VER6 comprobada sin ese
envoltorio. No se debe trasladar automáticamente una contraseña de uso de la
configuración a una clave de descifrado, ni afirmar soporte de esa otra ruta sin
un archivo real y su recorrido de importación.

### Anclas de búsqueda en la biblioteca

Estas son direcciones virtuales del ELF ARM64 analizado, **no offsets del archivo
ni direcciones absolutas bajo ASLR**. En una actualización deben recalcularse.

| Función / ancla | Dirección en la versión comprobada | Motivo para inspeccionarla |
| --- | --- | --- |
| `androidclient.ImportConfigContent` | `0x149cba0` | Confirma que se escriben los bytes importados |
| `configuration.LoadNativeConfig` | `0x11e93b0` | Une lectura, descifrado y gob |
| `configuration.d` | `0x11e9dd0` | Selección VER y capas de descifrado |
| `configuration.e` | `0x11eb000` | Exportación; confirma transformaciones inversas |
| `kcp-go.decrypt` | `0xa4fc40` | Modo CFB y bloque final parcial |
| `kcp-go.NewBlowfishBlockCrypt` | `0xa4d160` | Blowfish y tamaño de clave |
| `kcp-go.NewAESBlockCrypt` | `0xa4d350` | AES y parámetros del modo |
| `kcp-go.NewCast5BlockCrypt` | `0xa4cf20` | CAST5 |
| `golang.org/x/crypto/pbkdf2.Key` | `0xa476d0` | Hash, iteraciones y longitud del resultado |

Los nombres completos llevan el prefijo
`newtools/linklayer/androidclient/configuration`. Conviene buscar por el sufijo
semántico y seguir las llamadas; el prefijo puede cambiar.

### Recuperar símbolos Go aunque el ELF no los publique

En esta biblioteca bastó interpretar la tabla de funciones Go (`pclntab`). Se
buscó el encabezado binario `f1 ff ff ff 00 00 04 08`, se comprobó un número de
funciones plausible y se leyeron ocho enteros little-endian de 64 bits desde
`header + 8`: `nfunc`, `nfiles`, `textStart`, `funcnameOffset`, `cuOffset`,
`filetabOffset`, `pctabOffset`, `pclnOffset`.

Para cada entrada de ocho bytes de la tabla de funciones se leyeron
`entryOffset` y `funcOffset` como dos uint32. El nombre está en
`header + funcnameOffset + int32(header + pclnOffset + funcOffset + 4)`;
la dirección es `textStart + entryOffset`. Si `textStart` aparece como cero,
resolver su relocación ELF en `headerVA + 24` antes de desensamblar.

Las lecturas de código usan el mapeo de sección ELF:
`fileOffset = sh_offset + VA - sh_addr`. Capstone permitió anotar los destinos
`bl` con los nombres recuperados. Esta receta corresponde a la tabla observada;
si cambia la versión Go, comprobar su formato antes de reutilizar esos offsets.

## Cómo se reconstruyó el algoritmo

La implementación Python se escribió siguiendo los cortes de buffers del
ensamblador y se ejecutó por etapas con el archivo real. Las constantes del
programa son:

```python
IV = bytes.fromhex("a7734f9c12ac1b01a415f2c1fc78e66b")
XOR_SALT = b"sH3CIVoF#rWLtJo6"
```

El IV se toma completo para AES y sus primeros ocho bytes para Blowfish/CAST5.
En PyCryptodome es imprescindible establecer `segment_size=block_size*8`:
CFB128 para AES y CFB64 para los otros dos. El modo CFB de ocho bits por defecto
no reproduce `kcp-go`. No se añade ni retira padding PKCS#7.

| Paso | Operación recuperada | Longitud en la muestra |
| --- | --- | --- |
| 1 | Eliminar `VER6`; separar los ocho bytes finales como clave Blowfish; descifrar el resto con Blowfish-CFB64 | 7258 bytes |
| 2 | Separar 72 bytes finales. Clave AES = primeros 16 de ese material + últimos 16 invertidos. AES-CFB128 sobre el resto | 7186 bytes |
| 3 | Primeros 32 = clave Salsa20; ignorar los últimos 32; invertir el segmento intermedio. Conservar sus primeros ocho como nonce y descifrar el resto con Salsa20 | Paquete de 7122 bytes |
| 4 | Después del nonce, leer longitud BE32. Exigir tres segmentos de esa longitud; tomar el central. Sus últimos 16 son la clave CAST5-CFB64 | Segmento central 2370; texto CAST5 2354 bytes |
| 5 | Quitar el byte de bandera. Con bandera 1, `inner[split:][::-1] + inner[:split]`, donde `split=len(inner)//2`; con 0, conservar el orden | 2353 bytes antes del prefijo PBKDF2 |
| 6 | Primeros 16 = contraseña PBKDF2. SHA-1, sal fija, **32 iteraciones, 1500 bytes de salida**. XOR solo los primeros `min(len(buffer),1500)` bytes del resto | 2337 bytes de buffer |
| 7 | Últimos 32 del buffer = clave AES; intercambiar primer y último byte. Texto cifrado = `buffer[-42:-32] + buffer[:-42][::-1]`. AES-CFB128 | 2305 bytes de gob |
| 8 | Decodificar las definiciones y el valor `NativeConfig` de gob; consumir exactamente los mensajes | 25 campos raíz / 60 hojas |

Las longitudes intermedias ayudan a localizar una regresión; no son constantes
del formato para todos los exportados. Las claves de estas capas vienen del
propio contenedor. No se incorporaron claves ni credenciales de la muestra en
el decodificador.

### Puntos que resolvieron los errores de interpretación

- La llamada PBKDF2 recibe **32 como iteraciones y 1500 como longitud**. No es
  una clave de 32 bytes con 1500 iteraciones. El XOR tampoco repite una clave
  corta sobre todo el contenido.
- Los tres segmentos no son tres capas a descifrar: se usa el central. Los
  exteriores sirven de relleno en la estructura observada.
- El trailer de 32 bytes que aparece tras Salsa20 no se usa como una segunda
  clave. Usarlo cambia por completo el resultado.
- La bandera de orden debe aplicarse antes de separar el prefijo PBKDF2; los
  tamaños impares importan. La prueba sintética cubre las dos banderas.
- Llegar a bytes legibles no bastaba: el gob debía declarar el esquema esperado
  y todos sus mensajes tenían que consumirse sin sobrantes.

## Cómo se confirmó el contenido completo

Se implementó inicialmente un lector de gob para descubrir las definiciones de
tipo del texto recuperado. Los tipos primitivos observados son bool=1, int=2 y
string=6; los ids de structs son asignados por gob y no deben fijarse a los de
una única muestra. Los enteros usan la codificación propia de gob y los campos
de struct se indican mediante deltas de índice.

El parser final valida los nombres, orden y tipos del esquema `SCHEMA` del
script. Incluye `SSL`, `HTTP`, `HTTPSSL`, `WS`, `DNSTT`, `UDPHysteria`,
`HTTPDual`, `SSH` y los campos raíz. Go omite valores cero en la codificación;
se restauran `False`, `0` y `""` antes de aplicar los campos presentes. Omitirlos
habría producido una salida aparentemente válida pero incompleta.

La prueba real fija el SHA-256 del gob de 2305 bytes. Se confirmó la estructura
de 25 campos raíz y 60 hojas y se ejecutó la muestra por el `spdecode.executor`
del repositorio: salida 0, stderr vacío y JSON idéntico al descifrado directo.
No se realizó una importación en un emulador Android; la evidencia proviene del
flujo DEX/nativo, la reproducción de sus operaciones y las pruebas de la muestra.

```sh
python -m pip install pycryptodome
python decoders/Python/linklayer.py /ruta/muestra-nueva.lnk > resultado.json
SPDECODE_LINKLAYER_REAL_FILE=/ruta/muestra-original.lnk \
  python -m unittest discover -s tests -p 'test_linklayer_ver6.py' -v
```

Las diez pruebas pasaron con la muestra real, y se rechazaron además los 7270
prefijos truncados en la comprobación original. El fixture privado no está en
GitHub: su variable debe apuntar al archivo cuyo hash figura arriba. Para una
nueva versión, añadir otro caso real; no reemplazar la referencia antigua.

## Qué hacer cuando se actualice LinkLayer

1. Conservar el APK, versión, SHA-256 y un exportado nuevo. Guardar una copia del
   script vigente. Probar primero ese script con el nuevo archivo y mantener
   el caso antiguo como regresión.
2. Comprobar cabecera y arquitectura. Si aparece `VER7` u otra cabecera,
   localizar su rama en `configuration.d`; no quitar la comprobación VER6 para
   forzar un resultado.
3. Extraer DEX y todas las bibliotecas de los splits. Volver a seguir
   `ImportConfig` → recarga → `LoadNativeConfig`; no asumir que sigue igual.
4. Recuperar los símbolos Go y comparar las funciones de descifrado/exportación,
   las constantes, los modos CFB, PBKDF2 y las transformaciones de buffer.
5. Ejecutar por etapas. Si el gob final es válido pero cambia `NativeConfig`,
   el problema puede ser solo el parser. Comparar las definiciones declaradas
   por la nueva muestra y actualizar el esquema para esa versión, conservando
   el esquema anterior. No buscar otra clave mientras todas las capas ya pasan.
6. Validar un exportado real completo, tipos, campos cero, entrada del bot y
   manejo de errores. Ampliar pruebas con evidencia del cambio concreto.

| Síntoma | Primera comprobación útil |
| --- | --- |
| Primera capa incoherente | Cabecera, clave Blowfish final, IV y CFB64 |
| Longitud de tres segmentos no cuadra | Material AES, inversión del paquete y nonce Salsa20 |
| Gob ilegible al final | Orden de bandera, parámetros PBKDF2, máscara no repetida, intercambio de extremos de clave AES |
| Gob legible pero `UnsupportedSchemaError` | Nuevas definiciones `NativeConfig`; ids variables frente a nombres/tipos |
| Faltan campos vacíos o falsos | Restauración de valores cero de gob |
| El script funciona y SP-DECODE falla | Comparar los mismos bytes, salida JSON y ruta del ejecutor antes de modificar la criptografía |

## Límites que debe recordar el siguiente agente

Este VER6 **no contiene MAC ni etiqueta de autenticación**. El esquema y las
longitudes permiten rechazar muchos daños, pero no prueban autenticidad ni
detectan todo cambio en relleno ignorado o en datos estructuralmente válidos.
Las pruebas documentan ese límite. No describir este resultado como un archivo
criptográficamente autenticado.

El script limita la entrada a 8 MiB, cada cadena a 1 MiB y los tipos a 16 structs.
Versiones distintas, esquemas distintos y el envoltorio protegido no están
validados. El usuario pidió un método Python para integrar posteriormente:
conservar los decodificadores anteriores y no modificar Android ni compilar APK
como parte de una investigación futura salvo nueva instrucción.

Para abrir otro chat basta compartir este documento, el script, la APK nueva y
un archivo nuevo real. Los dumps temporales originales no son un requisito.
