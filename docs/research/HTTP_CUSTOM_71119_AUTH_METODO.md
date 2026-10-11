# HTTP Custom 7.11.19: contraseña y HWID mediante un script independiente

Fecha: 2026-10-11. Script: `decoders/Python/HTTPCUSTOM_AUTH.py`. Autónomo: no importa otros decodificadores del repositorio. Los archivos `HTTPCUSTOM.py` y `_hc_hccfg.py` permanecen intactos. No se integró Android ni se compiló o publicó APK.

## Resultado y origen del método

El motor HCCFG existente ya incluye derivación por contraseña y HWID. La ruta `HTTPCUSTOM.run(bytes)` llama a `decrypt(data)` sin esos parámetros y su CLI acepta sólo la ruta: por eso los archivos bloqueados reportan requisitos y no se descifran desde esa entrada. El cambio necesario es ofrecer las credenciales explícitamente, no retirar el bloqueo ni reemplazar las claves.

Se tomó como referencia `_hc_hccfg.py`, blob `4cd48ca6f27520587bd1b189e716bf98f3315768`, desde main `46e75fb89ed9dd9eea03d8cedda998daa9529b2a`. Se reprodujeron sus primitivas y calendarios en un archivo nuevo y se contrastaron ambos motores con las tres exportaciones comerciales del usuario. Se comprobó la identidad de la APK por el manifest y se inspeccionaron DEX y bibliotecas. La app tiene numerosos métodos convertidos en bindings nativos y nombres ofuscados; **no se afirma haber reconstruido todo su código nativo ni ejecutado su exportador**. La evidencia funcional son los archivos reales autenticados y la comparación con el motor de referencia.

APK: paquete `xyz.easypro.httpcustom`, versión **7.11.19**, build **885**. ZIP suministrado: SHA-256 `603ad81ffa3f436bc5b22ca5d4147840bc00721e45a8b1f793ace289516ef103`. `base.apk`: SHA-256 `8ceb143ec596e24f689b7a7daa544711278d7d06193f579bee620dd30b4696ca`.

| Muestra | SHA-256 | Bloqueo | Resultado |
| --- | --- | --- | --- |
| `Test4.hc` | `28a82138a3dfc8a9c7b538cde83b50d7acef1471d3acf9fe3a2753c1acc97915` | Ninguno | 2 perfiles |
| `Test4 password.hc` | `71813243ada25ddaf24afd71676e7b2ba16b723420fb14307dc2669adfaa7895` | Contraseña | 2 perfiles |
| `Test4 HWID.hc` | `ff408b0ea2253ed362b3dec1ed9e15d311c72ec336c814f0b5b1312e6ac11635` | HWID | 2 perfiles |

En cada archivo se verificaron tres secciones XChaCha20-Poly1305 y dos envolturas HPR1 internas. El resultado mantiene los valores del decoder anterior y además conserva `flags`, fecha de actualización, label, opciones anidadas y la sección principal completa, antes omitidos en su proyección final. Contraseña y HWID incorrectos producen `AUTH_FAILED`; no se entrega configuración parcial.

**Ambos bloqueos:** la combinación `n8` + `h=1` funciona en una fixture generada con un writer independiente. Se probó exigir ambos datos, pedir sólo el faltante y rechazar cualquiera incorrecto. No se recibió un archivo comercial exportado con ambos: **la compatibilidad de ese caso con el exportador de la APK queda pendiente de esa muestra real**. Una prueba generada no sustituye esa confirmación.

Las configuraciones, contraseña de exportación, HWID y JSON reales se conservan fuera de Git.

## Uso

```bash
python -m pip install pycryptodome argon2-cffi
python HTTPCUSTOM_AUTH.py archivo.hc --inspect
python HTTPCUSTOM_AUTH.py archivo.hc --password 'CONTRASEÑA' -o resultado.json
python HTTPCUSTOM_AUTH.py archivo.hc --hwid 'HWID_DE_32_CARACTERES' -o resultado.json
python HTTPCUSTOM_AUTH.py archivo.hc --password 'CONTRASEÑA' --hwid 'HWID_DE_32_CARACTERES' -o resultado.json --audit auditoria.json
```

Sin bloqueo basta la ruta. La CLI no pregunta ni usa `input()`. Devuelve JSON tipado; errores JSON en stderr y código de salida 1. `--inspect` sólo obtiene requisitos, no configura ni descifra perfiles. No llamar a Argon2 durante esa inspección.

API para un formulario futuro:

```python
from HTTPCUSTOM_AUTH import inspect_requirements, decode, HCError

requirements = inspect_requirements(data)
# Mostrar únicamente los campos marcados por password_required / hwid_required.
try:
    document = decode(data, password=entered_password, hwid=entered_hwid)
except HCError as error:
    response = error.to_dict()
```

`PASSWORD_REQUIRED`, `HWID_REQUIRED` y `CREDENTIALS_REQUIRED` incluyen `error.required`, una lista con `password`, `hwid` o ambos. `AUTH_FAILED` indica fallo de autenticación por credenciales incorrectas o corrupción; el tag no permite atribuir con certeza cuál dato falló. Otros códigos: `INVALID_HWID`, `INVALID_FILE`, `UNRECOGNIZED_FORMAT`, `UNSUPPORTED_VERSION`, `RESOURCE_LIMIT`, `DEPENDENCY_MISSING`, `INVALID_OUTPUT`, `IO_ERROR`.

`run(data, password=None, hwid=None)` devuelve texto JSON; `decrypt` es alias de `decode`. La salida usa `config` con los perfiles completos y `options` anidado; `main_config` guarda el objeto principal íntegro y `protections` su proyección legible. No confundir `config[*].password` (credencial del servidor) con la contraseña de exportación: esta última es una entrada de la KDF y no se añade al resultado.

## Capas confirmadas

1. **Carrier:** los tres archivos reales contienen bytes lógicos representados como caracteres Latin-1 y guardados en UTF-8. Se revierte esa representación sin ignorar errores ni perder bytes. La carga lógica tiene 3 372, 3 400 y 3 584 bytes, respectivamente.
2. **Sobre:** los tres usan `stream-v3`: nonce de 24 bytes, ciphertext y 16 bytes finales reservados. El decoder existente usa `OUTER_KEY_V3` para XChaCha20 con contador de bloque 1. **No se verificó un MAC exterior de esta variante.** `header_authenticated=False` deja claro que la inspección es una pista para pedir credenciales; la autenticidad del contenido se establece después con las secciones. También se conserva la ruta exterior estándar autenticada y su AAD `HCX1|xyz.easypro.httpcustom|1`.
3. **HCCFG:** `a=HCCFG`, `b=7`, `c=s1`, `d=h1`, `f=[ssh,profiles]`, `n=885`; `g` es una clave/seed de **32 bytes decodificados de hex**. `e=n7` en normal/contraseña y `e=n8` en HWID. `h=1` indica contraseña; `h=0` no la usa.
4. **Derivación:** transcript, HMAC del calendario, Argon2 opcional y HKDF-SHA256. Para HWID el resultado abre un slot y recupera la clave real de contenido.
5. **Secciones:** `i` contiene JSON principal; `j` contiene perfiles. Cada sección usa XChaCha20-Poly1305 con nonce de 24 bytes y AAD específico de su label. No interpretar plaintext tras un tag fallido.
6. **HPR1/HPC1:** los dos perfiles de cada muestra tienen `HPR1`, otro nonce y otra etiqueta verificable; su plaintext es `HPC1`, con 11 campos binarios big endian. `HPC1` guarda nombre, protocolo, host, puerto, usuario, contraseña, payload, opciones, flags, timestamp uint64 y modo. Las cadenas tienen longitud uint32 y bytes UTF-8. El script nuevo **exige el tag HPR1**; no conserva el fallback no autenticado del motor de referencia.

## Contraseña, HWID y doble bloqueo

Conservar el orden de `f`; no ordenar features. La versión interna del transcript es el literal **1**, aunque el esquema sea 7. `n=885` participa como texto decimal. El transcript usa delimitadores NUL y las etiquetas de AAD usan delimitadores `|`.

Para `n7/n8`, `_transcript` calcula HMAC-SHA256 sobre `D3 || C0_PREFIX[:32] || transcript`, usando `N7_HMAC_KEY`. Para calendarios antiguos `n1/n2` conserva `_c0 = SHA256(C0_PREFIX || transcript)`. Las constantes exactas están en el script y proceden del motor de referencia probado; no son las credenciales que debe introducir el usuario.

**Contraseña:** bytes UTF-8 exactos, sin quitar espacios ni cambiar mayúsculas. Argon2id versión 19, una lane; salt `g[:16]`, salida 32 bytes. En la muestra real `l=2` y `m=67108864`: **m está en bytes**, equivale a 65 536 KiB. Concatenar la salida Argon2 al material del calendario **antes de HKDF**. La AAD también incluye `|1|ARGON2ID13|2|67108864`; sin contraseña incluye `|0`.

**HWID:** quitar espacios externos y convertir a mayúsculas; usar esos 32 caracteres como bytes UTF-8. No interpretar el HWID como hex ni sustituirlo por otra identificación: el formato de HTTP Custom puede incluir `h`. Agregar `hwid\0HWID\0` al transcript y `|hwid|HWID` al info de HKDF. Con la clave derivada, abrir cada slot `o` usando AAD de base más `\0w`; el plaintext válido de 32 bytes es la clave de secciones. La muestra comercial contiene un slot y el HWID del usuario lo autenticó.

**Ambos:** hacer simultáneamente los dos pasos anteriores: transcript/info con HWID y material con la salida Argon2. El slot queda ligado a ambos datos; poseer sólo uno no permite obtener la clave de contenido. El AAD incluye los parámetros de contraseña. Esta composición está implementada y probada con fixtures, con la limitación comercial indicada arriba.

Límites antes de KDF: 16 MiB de entrada, 256 secciones/slots, 1–16 pasadas y máximo 256 MiB de memoria Argon2. Un archivo legítimo fuera de ellos necesitará revisar el límite; no ejecutar sus parámetros sin validar. No escribir sobre la entrada ni sobre el informe con la misma ruta.

## Pruebas y futura actualización

```bash
python -m unittest discover -s tests -p test_httpcustom_auth.py -v
HC_REAL_DIR=/ruta/privada HC_REAL_PASSWORD="$PASSWORD" HC_REAL_HWID="$HWID" \
python -m unittest discover -s tests -p test_httpcustom_auth.py -v
```

Pasaron **10 pruebas**, con los tres archivos reales habilitados. Cubren ambos bloqueos, parámetros faltantes, credenciales erróneas, normalización HWID, múltiples slots, exactitud de contraseña, preservación de tipos/CRLF/Unicode, tags de secciones y HPR1 alterados, límites antes de Argon2, backend alternativo, CLI y prohibición de sobreescribir. El caso comercial se omite sin variables de entorno. La fixture no usa `_derive`, `_transcript` ni `_pw_kdf` del nuevo decoder para construir la clave.

En una actualización, primero comparar package/versión/hash y abrir una muestra sin bloqueos con el motor de referencia. Luego exportar el mismo contenido con contraseña, HWID y ambos; comparar `a/b/c/d/e/f/h/k/l/m/n/o` sin publicar `g` ni ciphertexts completos. Si el sobre abre pero falla una sección, revisar transcript, unidades Argon2, normalización HWID, info/AAD y slots antes de cambiar las constantes. Si las secciones autentican pero no aparece HPC1, revisar HPR1 y su AAD `label:r`. Conservar perfiles/campos desconocidos y registrar qué tags se verificaron. No certificar una versión nueva sólo porque coincide la cabecera.
