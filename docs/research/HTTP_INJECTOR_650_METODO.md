# HTTP Injector 6.5.0: archivo real, valores internos y continuidad

Fecha: 2026-10-11. Trabajo Python exclusivamente. Sin cambios Android, compilación, integración en main ni release.

## Resultado comprobado y límite

El motor del bot en main `56f037fef1fe9e55e0346a6ed28611f12af5e1eb` ya abría el archivo real proporcionado. El formato de ese archivo **no requiere sustituir las claves ni inventar otro cifrado**: utiliza el segundo IV estándar, Argon2id y XChaCha20-Poly1305. La etiqueta Poly1305 se verificó. El JSON interior tiene 43 campos y el decodificador transformó 11 cadenas: `host`, `dnsttNameserver`, `sniHostname`, `user`, `configMessage`, `password`, `tlsVersion`, `payload`, `dnsttPublicKey`, `dnsttDnsResolverAddr` y `remoteProxy`.

Otras 17 cadenas no se transformaron. La lista incluye valores legítimamente literales (`tunnelType`, modos DNSTT, rutas, lista de bloqueos, hash) y claves concatenadas como `htrServerHosthtrServerPort` o `dnsttDnsResolverAddroverwriteServerData`. **No se demostró un segundo cifrado para esas cadenas ni que sean relleno generado por el exportador.** Se conservan íntegramente; no se separan claves por adivinación, no se borra contenido y no se afirma que todo esté descifrado. El informe `--audit` distingue transformación de conservación; no identifica automáticamente las cadenas conservadas como cifradas.

El cambio aporta JSON tipado completo, diagnóstico sin valores y una reparación verificable: el backend alternativo `cryptography` antes recibía el nonce XChaCha de 24 bytes directamente, aunque `ChaCha20Poly1305` requiere 12. Ahora deriva la subclave HChaCha20 y usa `00000000 || nonce[16:24]`. **El mismo archivo real autentica y entrega el mismo JSON con ambos backends.** Se mantienen los seis IV, las claves, XXTEA, XOR y la salida `run(bytes)` del bot. La salida de texto nueva y anterior fue idéntica byte por byte con el archivo real y los seis perfiles sintéticos.

## Entradas privadas y reproducción

No añadir APK, configuración, JSON descifrado ni credenciales a Git.

| Entrada | Identificación |
| --- | --- |
| EHI real, 13 304 bytes | SHA-256 `54889797633ac07f192061659d821f8f7a456dd9f5101fdc7966fc66c1501444` |
| ZIP APK, 38 832 542 bytes | SHA-256 `2eeab20e7a2193d63730fbae3dcee8ac439b4f644e45465640ed80c68a92e6e4` |
| base.apk, 12 439 507 bytes | SHA-256 `5dc3976ad0d90c14b79f5848109296998f930c9d36be88fba9115c078f60dfe3` |
| Aplicación | `com.evozi.injector`, `versionName=6.5.0`, `versionCode=244` |

Dependencias recomendadas:

```bash
python -m pip install pycryptodome argon2-cffi
python decoders/Python/HTTPINJECTOR.py archivo.ehi --json -o resultado.json --audit auditoria.json
python decoders/Python/HTTPINJECTOR.py archivo.ehi
```

La segunda orden conserva la interfaz del bot. `--json` conserva números, booleanos, objetos, arrays y campos desconocidos, sin convertir a un texto decorativo que otro parser pueda truncar. Las cadenas que contienen JSON continúan siendo cadenas, con su contenido exacto. Para el backend alternativo instalar `cryptography` y `argon2-cffi`.

API:

```python
from decoders.Python.HTTPINJECTOR import decode_ehi, run
audit = {}
document = decode_ehi(data, audit)  # dict o None; no escribe ni contacta servidores
text = run(data)                 # formato histórico del bot o None
```

`None` no es un resultado parcial. Una autenticación fallida nunca produce el JSON interior. La CLI rechaza rutas de salida que sobreescribirían la entrada o el informe. Los parámetros Argon2 del archivo se acotan a 1–16 pasadas, 1–16 hilos y hasta 262 144 KiB; un perfil legítimo que exceda esto necesitará revisar conscientemente los límites. Bypass no requiere Argon2. Las cabeceras truncadas o con magia distinta de `ehi` se rechazan.

## Capas del archivo, en orden

1. Contenedor `DataInputStream`: UTF con longitud big endian de 16 bits (`ehi`); 8 bytes; UTF de versión; 8 bytes; longitud de ciphertext de 32 bits big endian; otros 8 bytes; ciphertext. En el archivo real la carga empieza en el byte 40 y tiene 13 264 bytes. La cabecera se valida, pero los enteros de versión antiguos no se fuerzan a 244.
2. AES-256-CBC con `EHIConstants.L1_KEY`; recorrer los tres IV bypass y tres estándares ya existentes. Comprobar PKCS#7 y UTF-8. El resultado es `base64(iv_interior):campo_intermedio:base64(ciphertext_interior)`.
3. AES-128-CBC con `L2_KEY_STATIC` e IV de la primera parte. PKCS#7 válido obligatorio.
4. XXTEA little endian con `EOO_MASTER_KEY`; localizar y parsear el JSON exterior. Esto por sí solo no autentica CBC.
5. En bypass, ese objeto es el documento. En estándar, descodificar `configData` con el `configSalt` exterior y el envoltorio de campos explicado abajo; Base64 estándar da la carga autenticada.
6. Carga estándar: byte versión; pasadas LE32 `[1:5]`; memoria KiB LE32 `[5:9]`; paralelismo `[9]`; sal Argon2 de 16 bytes `[10:26]`; nonce XChaCha de 24 bytes `[26:50]`; ciphertext `[50:-16]`; tag `[−16:]`. AAD = primeros 26 bytes. La muestra real usa versión 1, 5 pasadas, 65 536 KiB, 4 hilos.
7. Secreto Argon2: SHA-256 de la concatenación histórica de `configAesKey`, `configIdentifier`, `configSalt`, timestamps, `lockModes`, `lockModesHash`, HWID y operador, exactamente como `_generate_master_key`. No descodificar previamente los campos exteriores ni cambiar su orden o los ceros por defecto.
8. Argon2id, versión 0x13, salida de 32 bytes. Verificar XChaCha20-Poly1305 antes de parsear el documento interior.

Las constantes existentes siguen en `EHIConstants`, evitando duplicarlas aquí. No tratar el hash de `lockModes` ni una clave pública DNSTT hexadecimal como otro ciphertext sólo por su aspecto.

## Envoltorios de campos

`_decrypt_xor_layer`: invertir la cadena → eliminar `?` → traducir el alfabeto Base64 personalizado a estándar → Base64 → texto hexadecimal ASCII → bytes → XOR con caracteres de `configSalt` de forma cíclica → UTF-8. Se conserva el comportamiento histórico que omite los bytes NUL. Si la representación no es válida se conserva la cadena original. La transformación no es un cifrado autenticado; su éxito es estructural, a diferencia del tag interior.

`configMessage` tiene otra ruta: Base64 estándar → UTF-8 → unidades Java UTF-16 → XOR cíclico con `EHIMSG` → texto. La recursión existente se mantiene en objetos y listas hasta 32 niveles. No aplicar Base64 arbitrario a todos los valores ni repetir XOR hasta obtener texto legible.

## Qué se pudo recuperar de la APK

El DEX principal tiene siete clases `com/secneo/apkwrapper`, no el código de la aplicación. Los DEX en `assets/audience_network` son de Facebook; no confundirlos con un DEX de HTTP Injector. El código protegido está en las bibliotecas del split ARM64, entre ellas `libDexHelper.so`, `libdatajar.so`, `libdexjniehi.so`, `libevozi.so` y `libevozi_sentinel.so`.

Se recuperaron ELF válidos de `libDexHelper.so` y `libdexjniehi.so`: el cargador descifra los primeros 64 bytes del ELF interior con RC4 y el resto con XOR de un byte. `scripts/research/httpinjector_650_unpack_native.py` reproduce este paso **para esta APK concreta** y valida las magias ELF. No es un desempaquetador universal y no ejecuta Android.

Anclas verificadas en ARM64 `libdexjniehi.so` empaquetado: KSA RC4 en `0x2780..0x27b4`, PRGA de la cabecera de 64 bytes en `0x27b8..0x2814`, XOR del resto en `0xcec`. El bloque de parámetros está en offset de archivo `0x4000`; carga ELF en `0x5000`; clave RC4 y byte XOR en `0x1762e0`. En `libDexHelper.so`: parámetros `0xc000`, carga `0x18000`, clave y XOR `0x114ead`. Estas claves son del empaquetador, **no de EHI ni del dispositivo**.

La biblioteca interior `libdexjniehi` registra `com/fort/andjni/JniLib`. Su `.data` contiene LZ4 y MessagePack: se recuperó parcialmente un pool de referencias y constantes y un flujo con 783 métodos virtualizados. No se reconstruyó un ejecutor completo. La continuación cloud/emoji se resolvió mediante métodos Dalvik directos y cadenas recuperadas, sin necesitar ese ejecutor; ver sus documentos independientes.

`libdatajar` tiene un bloque en `0x4018`, metadatos DEX y un frame Zstandard en `0xe89018`. El frame de `0x4de074` bytes se descomprime a `0x1e00000` bytes. Se reconstruyeron metadatos de 9 103 clases a partir del mapa y las cadenas, omitiendo anotaciones/valores estáticos no recuperados. **Ese DEX es sólo para análisis: no está completo ni es ejecutable.** Después se recuperaron otros dos DEX parciales del frame y se reprodujo el descodificador de cadenas con constantes `long`; los offsets y las limitaciones están en el documento cloud. Los wrappers de `ConfigActivity` remiten a `JniLib`.

## Pruebas realizadas

```bash
python -m unittest discover -s tests -p test_httpinjector_diagnostics.py -v
EHI_REAL_FILE=/ruta/privada/muestra.ehi python -m unittest discover -s tests -p test_httpinjector_diagnostics.py -v
```

Las 9 pruebas EHI pasaron con el archivo privado habilitado: seis IV, ambos backends, tag modificado, cabecera/truncamiento, límites antes de Argon2, bypass sin Argon2, preservación de desconocidos/tipos/CRLF, CLI JSON y prohibición de sobreescribir entrada, y la muestra real. El caso privado sólo compara SHA, perfil y cuentas; no publica valores. En CI sin muestra se omite ese único caso. La continuación añade 11 pruebas cloud/emoji: 20 en total pasaron con las dos entradas privadas habilitadas. También se importó el enlace cloud real por las dos CLI; el caso emoji positivo es derivado de ese enlace, mientras que la secuencia original del usuario es inválida. No se ejecutó Android.

## Próxima sesión / actualización

Primero reproducir la muestra mediante su SHA y comparar el JSON tipado, no sólo la apariencia de la pantalla. Si la app SP-DECODE todavía presenta ciphertext de alguno de los 11 campos comprobados, comparar con el JSON Python para separar un motor antiguo de un fallo de presentación; no sustituir otra vez las claves.

Para cadenas conservadas, obtener un ejemplo mínimo cuyo valor original se conozca y cuyo campo activo se confirme en el exportador. Aislar su representación con `configSalt` y revisar la función de lectura de ese campo. No convertir una hipótesis de relleno en compatibilidad publicada.

Para cloud y emojis continuar desde [HTTP_INJECTOR_CLOUD_METODO.md](HTTP_INJECTOR_CLOUD_METODO.md) y [HTTP_INJECTOR_EMOJI_METODO.md](HTTP_INJECTOR_EMOJI_METODO.md). Ya se conserva una respuesta cloud real y se verificó el algoritmo emoji de la APK. Hace falta volver a copiar la exportación emoji original inválida para certificar ese ejemplo concreto. Mantener los ejemplos fuera de Git y distinguir pruebas reales de vectores sintéticos o derivados.
