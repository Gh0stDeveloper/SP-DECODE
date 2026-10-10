# SP-DECODE — motores genéricos AES-GCM/PBKDF2 y DES-ECB

## Objetivo y procedencia

Esta fase integra los últimos **dos motores criptográficos genéricos** del
archivo `66.py` suministrado por el propietario, preservando las tablas
históricas `VPN_PASSWORDS`, `MULTI_PASSWORDS` y `DES_PASSWORDS`, pero
sin copiar los manejadores de Telegram ni convertir el bot en un monolito.

Código principal:

- `decoders/Python/generic_profiles.py`: material histórico de descifrado
  y tabla de perfiles. El contenido deriva de las líneas 469–608 de `66.py`.
- `decoders/Python/generic_aes.py`: motor autenticado compartido
  AES-GCM + PBKDF2-HMAC-SHA256; rutas originales `decrypt_vpn_config()`
  y `decrypt_vpn_with_multi_keys()` de `66.py` (15760 y 17255).
- `decoders/Python/generic_des.py`: DES-ECB compartido; ruta original
  `decrypt_des_ecb()` (15718). Permite recuperar la versión AES-GCM cuando
  la extensión pertenezca a ambas tablas originales.
- `spdecode/registry.py`: enlaza perfiles aún no registrados con
  los dos scripts, solo en el bot.
- `tests/test_generic_profiles_registry.py`,
  `tests/test_generic_aes_profiles.py`, `tests/test_generic_des_profiles.py`:
  auditoría y vectores cifrado→descifrado independientes.

**No se modificó** `decoders.json`, que continúa como inventario estático
de 61 extensiones de Android. Tampoco se modifica el código Kotlin, la APK,
la keystore ni los workflows de publicación.

## Auditoría exacta de extensiones

| Inventario | Cantidad |
|---|---:|
| Extensiones registradas en el bot antes de esta fase | 158 |
| Claves únicas originales en `VPN_PASSWORDS` | 95 |
| Claves AES con contraseña no vacía | 94 |
| Extensiones AES sin motor previo registrado | 74 |
| Extensiones `DES_PASSWORDS` originales | 21 |
| Extensiones DES sin motor previo registrado | 13 |
| Extensiones nuevas presentes en ambas tablas | 6 |
| Nuevas extensiones únicas | **81** |
| Extensiones totales del bot después de esta fase | **239** |

No sumar 74 + 13 como 87 formatos nuevos: las 6 repetidas deben contarse
una sola vez. Las 6 son:

```text
.acm  .htp  .pin  .tut  .vmx  .xsks
```

El origen enviaba primero todos los archivos coincidentes por la ruta
DES, incluso los que también tenían contraseña AES. Este port respeta la
prioridad **DES→AES-GCM**, pero solo acepta DES si obtiene un XML con
`<entry key="...">` o una estructura JSON verificable. De lo contrario
prueba únicamente el perfil AES-GCM de esa misma extensión y exige
`decrypt_and_verify`; **nunca prueba contraseñas pertenecientes a otra
extensión**.

### 74 extensiones pendientes AES de la fuente original

```text
.1300 .ace .acm .act .ai .aip .aipr .bbb .bdi .cbp .ccc
.cks .cln .cnet .cyber .cyh .ddd .dkarl .dvd .dzd .edan
.eee .etun .eug .ezi .fks .fnet .garuda .gibs .grd .gv
.hbd .hdb .hq .hqp .hta .htp .hub .ignix_vpn .jph .kt
.max .mc .nac .nd4 .net .nhi .ntr .nx .pausa .pin .pir
.pkm .purple .pxp .sds .sksx .skvoid .sky .spd
.sshbrasil .ssi .tcv2 .temt .tito .tmt .tpp .tsd .tut
.utn .vmx .wcm .wt .xsks
```

### 13 extensiones pendientes DES de la fuente original

```text
.acm .clay .dak .ftr .htp .it .nxp .pin .tut .vmx
.vpc .wrld .xsks
```

De esas 13, 6 tienen también perfil AES. Los 7 perfiles exclusivos
DES son `.clay`, `.dak`, `.ftr`, `.it`, `.nxp`, `.vpc` y
`.wrld`. **Las extensiones de esta lista ya registradas previamente
se conservan con sus scripts originales**, sin crear alias alternativos
ni alterar decodificadores específicos.

## Algoritmo genérico AES-GCM/PBKDF2

El fichero exportado sigue el esquema original:

```text
Base64(salt).Base64(nonce).Base64(ciphertext || GCM-tag)
```

1. Localizar la extensión de archivo en `AES_PROFILES`.
2. Decodificar las tres partes Base64 y validar los tamaños del
   contenedor. Limitar la entrada a 2 MiB.
3. Para **cada clave históricamente asociada a esa misma extensión**,
   derivar la clave de 16 bytes con `PBKDF2(password, salt, dkLen=16,
   count=1000, hmac_hash_module=SHA256)`. No cambiar estos defaults:
   coinciden con la llamada original de PyCryptodome.
4. Descifrar usando `AES-GCM` y verificar siempre los 16 bytes de
   etiqueta con `decrypt_and_verify`.
5. Convertir a UTF-8. Preservar el JSON completo o bien todos los
   elementos `<entry>` del XML, incluidos duplicados y vacíos.
   Conservar también `raw_xml`, sin censurar campos de configuración.
6. Si todas las claves fallan, devolver `None` y código de salida no cero;
   nunca se expone texto descifrado sin etiqueta GCM válida.

### Casos que requieren especial atención

- `.cks` utiliza `MULTI_PASSWORDS` por encima de `VPN_PASSWORDS`.
- Los perfiles `.ziv`, `.pb` y `.tnl` tienen varias claves históricas;
  siguen con sus decodificadores especializados, pero sus listas se
  conservan para comprobar fidelidad de la fuente.
- `.tsd` aparece dos veces en `VPN_PASSWORDS`. En Python, la última
  definición prevalece, por lo que se usa la contraseña `Ed\\x01`.
- `.ignix_vpn` también aparece dos veces; prevalece la segunda.
- `.Tcv2` y `.NT` se normalizan a minúsculas para detectar nombres
  reales de archivo independientemente de mayúsculas.
- `.vpnlite` tiene contraseña AES vacía en la tabla antigua: no se
  registra como un nuevo perfil genérico y conserva su motor original.

## Algoritmo genérico DES-ECB

1. Buscar la extensión en `DES_PROFILES`.
2. Obtener la clave histórica: truncar a ocho bytes o rellenar con
   bytes NUL si fuera más corta.
3. Descifrar el contenido binario con `DES-ECB`. Como variante adicional,
   se admite entrada Base64 de los mismos bytes cifrados.
4. Decodificar UTF-8 y exigir entradas XML reconocibles o un JSON válido
   antes de reportar éxito. Los bytes aleatorios no generan falsos éxitos.
5. Conservar todos los campos y el XML original, evitando la pérdida de
   información que tenía el formateador heredado.
6. Si el formato no coincide y la extensión también tiene perfil AES-GCM,
   delegar al motor autenticado AES.

**DES-ECB no ofrece autenticación criptográfica y no es un algoritmo
seguro para exportaciones nuevas.** Su inclusión es exclusivamente para
compatibilidad histórica con las aplicaciones que ya produjeron estos
archivos. No usarlo para cifrar datos nuevos.

## Registro, uso y mantenimiento

Cada extensión queda vinculada a **un script concreto** en el bot:
`generic_aes.py` si solo aparece en AES, o `generic_des.py` cuando
aparece en DES (este último puede llamar internamente al primero).

La función `generic_specs(registry)` registra únicamente extensiones
sin decodificador previo. Si una fase posterior incorpora un decodificador
especializado de `.ace` o `.vmx`, dicho motor se debe registrar antes
de los genéricos y tendrá prioridad automática.

```bash
python decoders/Python/generic_aes.py /ruta/config.ace
python decoders/Python/generic_des.py /ruta/config.clay
python -m unittest tests.test_generic_profiles_registry -v
python -m unittest tests.test_generic_aes_profiles -v
python -m unittest tests.test_generic_des_profiles -v
python -m unittest discover -s tests -v
```

En GitHub Actions se comprueba el descifrado sintético de cada perfil,
la precedencia de claves, la verificación de etiquetas GCM, colisiones,
formatos malformados, preservación íntegra de XML, salida CLI y regresiones
de decodificadores preexistentes.

**Alcance de validación:** los vectores criptográficos sintéticos demuestran
que este port reproduce los parámetros usados por la fuente. No prueban
que las versiones más recientes de las aplicaciones externas continúen
usando esos parámetros ni que todas las claves históricas sigan vigentes.
Antes de declarar compatibilidad real, utilizar exportaciones auténticas,
autorizadas y no sensibles para verificar cada aplicación.
