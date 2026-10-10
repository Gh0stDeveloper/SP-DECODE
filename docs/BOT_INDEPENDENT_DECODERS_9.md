# SP-DECODE Telegram bot — lote de nueve motores independientes

## Fuente y alcance

Este lote se extrajo del archivo `66.py` autorizado por el propietario.
Se implementó **solo en Python para el bot de Telegram**: cada familia tiene
un archivo separado bajo `decoders/Python/` y un contrato estándar:

- `run(file_bytes: bytes) -> str | None` produce JSON UTF-8 completo o texto
  válido, o `None` en caso de error.
- CLI: `python decoders/Python/<motor>.py /ruta/config.ext`, con salida por
  `stdout` solo en caso de éxito y código distinto de cero en fallo.
- `config_independent_registry.py` es el único catálogo de las 13
  extensiones y evita duplicar los métodos.
- `spdecode.registry` registra los formatos únicamente en el bot, sin alterar
  los 61 formatos estáticos de Android en `decoders.json`.
- El descifrado es local, sin peticiones de red, servicios externos ni
  dependencia del bot de Telegram dentro de cada módulo.

## Mapeo definitivo

| Motor | Archivo Python | Extensiones / alias | Fuente de 66.py |
|---|---|---|---|
| IZPH VPN Pro | `izph.py` | `.izph` | `izph_*()`, líneas 9682–10142 |
| FlexNet | `flex.py` | `.flex`, `.flexnet` | `FLEX_MATERIALS`, `flex_*()`, líneas 3917–4123 |
| N4 VPN Pro | `n4.py` | `.n4` | `n4_*()`, líneas 11124–11281 |
| CREV | `crev.py` | `.crev`, `.cer`, `.cerv` | `crev_*()`, líneas 7406–7563 |
| KTR | `ktr.py` | `.ktr` | `ktr_*()`, líneas 17924–18141 |
| Zoba VPN | `zoba.py` | `.zoba` | `decrypt_zoba_file()`, líneas 11790–11875 |
| LTM Tunnel | `ltm.py` | `.lt`, `.ltm` | `ltm_*()`, líneas 6586–6683 |
| DEV VPN | `dev.py` | `.dev` | `skycrypt_decrypt()`, `decrypt_dev_file()`, líneas 14762–14884 |
| VN7 | `vn7.py` | `.vn7` | `decrypt_vn7_file()`, líneas 15160–15178 |

**CREV**: el original enumera `.cerv` en la lista global pero llama al
decodificador específico desde `.cer`. Ambas extensiones quedan asignadas
al mismo motor `crev.py`, además de `.crev`, sin afirmar equivalencia
verificada para todas las versiones del exportador.

**LTM**: el original admite `.ltm` y `.lt`; su motor es el mismo.

## Algoritmos conservados

**IZPH**: cuatro caminos históricos de descifrado:
0. AES-128-CBC, XXTEA y desplazamiento inverso de bytes;
1. Threefish-256, derivación HKDF-SHA256 y AES-128-CBC;
2. XXTEA, PBKDF2 y AES-256-CBC;
3. AES-256-CBC con IV prefijado y clave HKDF.
Se conservan el reconocimiento de `izph://` y `izphvpnpro://`, la
recuperación de servidores/redes y el tratamiento de campos internos.
La implementación de Threefish utiliza el código puro Python que ya estaba
presente en `66.py`, sin requerir PySkein.

**FlexNet**: encabezado `FLXCFG`, tabla de 30 materiales de claves
`FLEX_MATERIALS` por versión y lock, derivación PBKDF2-HMAC-SHA512,
AES-256-GCM, compresión zlib/gzip y propiedades XML. En versiones con lock,
el GCM autentica también los bytes AAD del encabezado. Se conserva el
mapa `rawProperties` para mostrar todos los campos recuperados, además
de los campos estructurados.

**N4**: JSON externo cifrado con AES-ECB, contraseña `jdk` y clave SHA-256;
campos internos con tablas de caracteres personalizadas, AES-CBC y clave
derivada de `modmkk`; puerto codificado en alfabeto Morse específico.

**CREV**: XXTEA de delta no estándar con varias claves históricas; primera
capa JSON más descifrado selectivo de campos en `Tweaks`.

**KTR**: inspección del flujo Java Serialization (`AC ED 00 05`),
extracción de TC_STRING/TC_LONGSTRING y emparejamiento de nombres y valores;
AES-256-CBC para cadenas cifradas. **No** es un deserializador Java completo,
sino el extractor de campos del original.

**Zoba**: XXTEA con delta personalizado negativo, aritmética de enteros
Java de 32 bits y trailer de longitud. Prueba de formato de texto o JSON
antes de presentar el resultado.

**LTM**: formato Base64 `salt.nonce.ciphertext+tag`, PBKDF2-SHA256,
AES-GCM autenticado y propiedades XML. El original usaba la librería
`cryptography`; esta adaptación reproduce los parámetros con
`pycryptodome`, ya presente en `requirements.txt`.

**DEV**: SkyCrypt (XXTEA de delta no estándar) para JSON externo y ruta
AES-CBC de campos internos, con clave derivada de contraseña.

**VN7**: formato `salt.nonce.ciphertext+tag`, dos claves históricas,
PBKDF2-HMAC-SHA256 y AES-GCM autenticado. Las etiquetas GCM se verifican.

## Validación y seguridad

Ejecutar:

```bash
python -m unittest tests.test_independent_batch_registry -v
python -m unittest tests.test_independent_batch_crypto_a -v
python -m unittest tests.test_independent_batch_crypto_b -v
python -m unittest discover -s tests -v
```

Las pruebas usan contenedores cifrados sintéticos con datos ficticios para
validar los parámetros y el flujo hasta el resultado de salida, e incluyen
errores por archivos malformados y pruebas de regresión de familias previas.

Los métodos AES-ECB/CBC y XXTEA no son autenticados y no garantizan
integridad frente a alteración del texto cifrado. FlexNet, LTM y VN7
sí verifican etiquetas GCM según el código original.

**Importante:** integración y pruebas sintéticas no equivalen a
certificación contra exportaciones reales recientes de todas las
aplicaciones. Validar muestras auténticas, autorizadas y no sensibles
antes de afirmar paridad con nuevas versiones.

## Próxima etapa

La portabilidad Android queda pendiente. No se deben marcar estas
13 extensiones como disponibles en la APK hasta tener motores nativos
y pruebas de paridad con los Python que están aquí.
