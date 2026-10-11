# HTTP Injector 6.5.0/244: importación cloud reproducida en Python

Fecha: 2026-10-11. Script separado: `decoders/Python/HTTPINJECTOR_CLOUD.py`. Se reutiliza `HTTPINJECTOR.py` sin modificarlo. Trabajo exclusivamente Python; sin Android, compilación, integración en main ni release.

## Resultado real y límites

Se importó el enlace cloud proporcionado por el usuario con una petición firmada hecha en Python, sin ejecutar la APK. La API devolvió HTTP 200. Se verificó el HMAC de transporte, se descifró AES-CBC y se descomprimió zlib. Su `config_data` pasó por el motor EHI existente: perfil `standard-2`, etiqueta XChaCha20-Poly1305 válida y **48 campos** en el JSON final. La CLI nueva entregó exactamente el mismo documento que la reconstrucción independiente de investigación.

El motor transformó `/configMessage`, `/sniHostname` y `/tlsVersion`. Conservó otras 26 cadenas no vacías, incluyendo modos literales, hashes, JSON guardado como cadena y claves concatenadas. **No está probado que todas esas cadenas sean cifradas ni que todas sean relleno.** Se conserva su contenido y se informa en `--audit`; no se separan nombres ni se inventan valores. `achilles` está presente en el JSON de importación, pero no se ha demostrado su derivación y el script no afirma verificarlo. No es el SHA-256 directo de `config_data` ni de su Base64 en la muestra examinada.

El enlace contiene una referencia, no un archivo completo. La descarga necesita el servidor disponible y un enlace válido; expiración, revocación, fallos de firma y cambios de versión se notifican como errores.

No publicar el enlace real, la respuesta, las configuraciones, las APK ni credenciales en Git. Los resultados y las evidencias completas se conservan de forma privada.

## Ejecución

Colocar `HTTPINJECTOR_CLOUD.py` y `HTTPINJECTOR.py` en el mismo directorio:

```bash
python -m pip install pycryptodome argon2-cffi
python HTTPINJECTOR_CLOUD.py https://ehi.link/CLAVE -o cloud.json --audit cloud_audit.json
python HTTPINJECTOR_CLOUD.py enlace.txt -o cloud.json
python HTTPINJECTOR_CLOUD.py --response respuesta_original.json -o cloud.json --audit cloud_audit.json
```

La última orden funciona sin red con el JSON HTTP externo original (`code` y `data`), no con la página HTML del enlace. `decode_cloud(reference, audit)` devuelve un diccionario tipado o lanza `CloudError`. `decode_response(response, audit)` permite trabajar con respuestas guardadas. `run(bytes)` conserva el estilo del bot y devuelve texto o `None`; para diagnóstico usar la API que expone el error. No se añadió routing al bot.

## Cómo se localizó

La APK suministrada es `com.evozi.injector`, 6.5.0, código 244. SHA-256 de `base.apk`: `5dc3976ad0d90c14b79f5848109296998f930c9d36be88fba9115c078f60dfe3`. La extracción ELF inicial está documentada en [HTTP_INJECTOR_650_METODO.md](HTTP_INJECTOR_650_METODO.md).

La página pública `ehi.link` sólo contiene una landing con URI `ehi://ehi.link/CLAVE` e intent Android; no contiene el ciphertext. El paso decisivo fue recuperar las cadenas ofuscadas y leer el interceptor y el descifrador de la API, no extraer contenido de esa página.

En `libdatajar.so` ARM64, el primer bloque empieza en `0x4018`. El frame Zstandard en `0xe89018`, longitud `0x4de074`, se descomprime a `0x1e00000` bytes. Además del DEX primario se recuperaron metadatos de dos DEX dentro del frame:

| DEX | Base en frame descomprimido | Map-list | Clases |
| --- | --- | --- | --- |
| Secundario | `0x581000` | `0x6ee49c` | 10 461 |
| Terciario | `0x16cc000` | `0x172c228` | 2 637 |

Estos DEX son auxiliares de análisis: no son ejecutables completos. El terciario tiene prototipos y algunos campos sustituidos por placeholders; no usar sus firmas reconstruidas como si fueran originales.

El descifrador de cadenas está en `com/google/android/gms/common/internal/ۦۙ۠`, `<clinit>` en `0xc86e4` del DEX terciario. Inicializa 17 bloques de cadenas UTF-16 y delega en `ۦۙۖ`/`j20`. Se reprodujeron sus operaciones con enteros Java, registros wide y conversión a short. **No sustituirlo por una biblioteca Paranoid genérica**: la rotación entera seguida de `int-to-short` debe coincidir con esta APK. El checkpoint privado contiene `recover_secondary_dex.py`, `deobfuscate_strings.py`, `constant_fold_dex.py` y los dumps anotados; leerlos antes de repetir la extracción.

## Petición HTTP exacta

Endpoint: `POST https://www.ehi.tools/httpinjector/import_config`. Cuerpo form UTF-8: `config_key=CLAVE`.

Anclas del DEX primario, offsets de `code_item`:

| Ancla | Offset | Qué buscar |
| --- | --- | --- |
| `yk0.intercept` | `0x3efbf8` | Construcción de petición |
| `yk0`, método firmado | `0x3efc34` | Cabeceras, parámetros ordenados, firma |
| `yk0`, HMAC | `0x3ef990` | `HmacSHA1`, Base64 y URLEncoder |
| `yk0`, codificación | `0x3efa14` | UTF-8; sustituye `+` por `%2B` |
| `yk0`, cuerpo y ordenación | `0x3efa84`, `0x3efae0` | Cuerpo form, sort por nombre |
| `zk0`, SignKeys | `0x3f57a8` | `SignKeys(null, null, Constant.ࡶ)` |
| `ｚ.<clinit>` | `0x465de4` | Literales de firma y cifrado de API |

Las nueve cabeceras que se firman son `x-nonce` (UUID), `x-timestamp` (segundos Unix), `x-sign-version=1.0`, `x-uid`, `x-did`, `x-platform=android`, `x-device`, `x-os-api` y `x-app-build=244`. La prueba real aceptó identificadores sintéticos SHA-1/MD5 en mayúsculas y metadatos `Android`/`35`; no fue necesario copiar una identidad ni clave privada de un teléfono. Esto no elimina restricciones futuras del servidor.

Agregar los parámetros de query y del cuerpo a las cabeceras firmadas; ordenar lexicográficamente por nombre y unir `k=v` con `&`. La app procesa el form reemplazando `+` por `%2B`, separando por `&` y por el primer `=`; los valores de ese cuerpo no se URL-decodifican otra vez. El script restringe la clave a letras ASCII, dígitos y `_`, por lo que no hay ambigüedad de codificación en `config_key`.

Definir `enc` como Java `URLEncoder(..., UTF-8)` seguido de reemplazar `+` por `%2B`. Preserva `*`, codifica `~` y no convierte espacios a `%20`.

```text
base = enc("POST") + "&" + enc(endpoint_sin_query) + "&" + enc(parametros_ordenados)
secret_app = "xn1WSCjY25RKW1pDQr0s3cdg6VSiQLb0"
key = enc("-1") + "&" + enc(secret_app)
x-signature = enc(Base64(HMAC-SHA1(UTF8(key), UTF8(base))))
```

El `-1` procede del token nulo del cliente anónimo. No enviar Bearer ni sustituirlo por HWID. Las cabeceras auxiliares Content-Type, Accept y User-Agent se agregan después de calcular la firma. Una petición sin cabeceras devolvió 401; la petición reconstruida devolvió 200.

## Descifrado de la respuesta

El JSON HTTP externo tiene `code=200` y `data` en Base64 estándar. Tras decodificar:

```text
IV = bytes[0:16]
MAC = bytes[16:48]
ciphertext = bytes[48:]
key = UTF8("GialHt24BQOZ+pwUE2++82H/EtnTqFh4")  # 32 bytes LITERALES
MAC esperado = HMAC-SHA256(key, ciphertext)
plaintext = zlib.inflate(PKCS7_unpad(AES-256-CBC-decrypt(key, IV, ciphertext)))
```

No decodificar esa clave como Base64. La app reutiliza la misma clave para AES y HMAC. **El HMAC sólo cubre ciphertext, no IV**: conservar esa limitación al describir autenticidad. Se verifican MAC, padding, zlib y JSON; luego se verifica la etiqueta EHI interior cuando el perfil la incluye.

Anclas: clase `ث`, métodos API en `0x402798` y `0x402a98`; clase `יּ$ﾠ⁬͏`, constructor en `0x462d54`, separa IV/MAC/ciphertext; clase `יּ`, descifrado en `0x463030`; `cq0.ࡢ` en `0x386cb0` usa `InflaterInputStream`. La clave proviene de `ｚ.ࡴ`, literal con seed `-524042641775386`; la firma de `ｚ.ࡶ`, seed `-524214440467226`.

El resultado zlib es `ImportConfig`: `status`, `config_data`, `achilles`. La muestra real produjo 16 095 bytes de JSON; `config_data` Base64 contiene 11 984 bytes CBC **sin cabecera EHI**. Se comprobó que estas bytes son la carga que acepta el motor EHI, no un archivo EHI entero. El script construye una cabecera local mínima sólo para adaptar esa carga a `decode_ehi`, sin modificar los seis perfiles ni el motor anterior. El informe distingue `adapter_sha256` del SHA de la carga cloud original; no presenta la cabecera artificial como archivo recuperado.

## Verificación y próxima actualización

```bash
python -m unittest discover -s tests -p 'test_httpinjector*.py' -v
EHI_REAL_FILE=/privado/muestra.ehi EHI_CLOUD_RESPONSE=/privado/respuesta.json \
EHI_CLOUD_EXPECTED=/privado/resultado_independiente.json \
python -m unittest discover -s tests -p 'test_httpinjector*.py' -v
```

Pasaron 20 pruebas, incluidos archivo EHI privado anterior, respuesta cloud privada, seis IV, backends, firma con vector fijo, HMAC alterado, IV alterado, zlib truncado/acotado y codec emoji. Las dos pruebas con entradas privadas se omiten sin variables de entorno. También se ejecutaron las CLI cloud y emoji contra el servidor real; el caso emoji positivo se explica en su documento, pues la secuencia original del usuario es inválida.

Si cambia la app: comprobar package/versión/hash; exportar una configuración mínima con valores conocidos; conservar respuesta HTTP original; localizar `import_config`, `config_key`, `x-signature`, `HmacSHA1`, `SignKeys`, `config_data` y `InflaterInputStream` después de descifrar cadenas. Comparar cabeceras, canonicalización, offsets IV/MAC, claves literales y perfil EHI. Un 401 apunta primero a firma/reloj/versión; MAC inválido a transporte; zlib inválido a capa API; etiqueta EHI inválida a carga interior. No reemplazar claves del lector EHI cuando sólo cambió la firma cloud.

Ver [HTTP_INJECTOR_EMOJI_METODO.md](HTTP_INJECTOR_EMOJI_METODO.md) para la entrada mediante emojis.
