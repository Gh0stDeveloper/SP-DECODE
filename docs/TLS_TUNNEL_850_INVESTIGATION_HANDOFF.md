# TLS Tunnel 8.5.0 — método de descifrado y guía para futuras actualizaciones

Fecha: 2026-10-11. Repositorio: `Gh0stDeveloper/SP-DECODE`. Alcance: Python y análisis local de la APK suministrada. Leer también `docs/VER6_NEW_FORMAT_CODEX_HANDOFF.md` para respetar el alcance del proyecto.

## Resultado y punto de partida para otro chat

**El archivo real suministrado se descifra y autentica correctamente.** El motor anterior ya reconstruía correctamente el contenedor, pero solo conocía una clave antigua. En la APK 8.5.0 encontré una lista de **seis claves AES de configuración**; la primera autentica esta muestra y la antigua sigue incluida como sexta. No fue necesario obtener una contraseña, HWID, clave privada del teléfono ni datos de un servidor para este archivo.

El motor actualizado es `decoders/Python/TLS.py`. Conserva `AES_KEY`, las funciones públicas anteriores, `run(bytes)` y el CLI sin interacción. Añade las cinco claves faltantes, verificación estricta, salida JSON opcional y conservación de todos los campos. Los demás decodificadores no se modifican. La integración Android queda para otra sesión.

Para empezar una revisión futura, probar primero el archivo nuevo con este script. Si la autenticación GCM funciona, no hace falta volver a desempaquetar la APK para obtener claves. Si falla, revisar las claves y el layout en el importador de la nueva versión. Los nombres ofuscados y direcciones de este documento pertenecen exclusivamente a la APK identificada abajo.

## Materiales y evidencia reproducible

Aplicación: `com.tlsvpn.tlstunnel`, versión `8.5.0`, `versionCode=516`, `minSdk=24`, `targetSdk=37`, según su manifest. Se recibió un ZIP con una APK y una configuración `.tls` real. Los binarios, la configuración y su resultado privado no se incluyen en GitHub.

| Material | Tamaño | SHA-256 |
| --- | ---: | --- |
| ZIP de la APK | 16 063 822 bytes | `9b189ddd17c4ceca4430af26ba00ced502e03ca055a5c8a1acbe2d73965fbfd9` |
| APK extraída | 17 842 636 bytes | `939586121d0fc2fe11e0e3d5b255ca41583537dcd57f21ca8a34f6298d7854c7` |
| Configuración `.tls` real | 22 163 bytes | `cc0b05dedbe3000f980b3ba25f3f5c171a0771e27786dddfb14302d87c6ccbd2` |
| Texto autenticado, antes de interpretarlo | 16 470 bytes | `880214f467d4252781636c0ec6ca8d6c15e44dd58d57a492880d287cc2d3a425` |
| DEX recuperado para inspección | 12 873 920 bytes | `e3d77952ba67af4389a6fe92f2ae6eeaafd2c12a021bb75101756aeced6abdaf` |

La muestra produce 58 posiciones delimitadas por `:` y comienza con el valor `516`. El perfil 1 verifica la etiqueta GCM; la clave del script anterior no la verifica. PyCryptodome y cryptography entregan exactamente el mismo diccionario. La recuperación completa desde la APK se repitió en otro directorio y produjo el mismo SHA-256 del DEX.

No se ejecutó la interfaz Android ni se comprobó una conexión VPN. La evidencia de descifrado consiste en el bytecode de la propia APK, la autenticación criptográfica del archivo real y la reproducción exacta del texto autenticado; no se afirma haber validado todos los controles de uso de la aplicación.

## Cómo encontré el método

1. Revisé el `TLS.py` existente. Ya usaba Base64 invertido, dos fragmentos de ciphertext, nonce de 36 bytes y AES-GCM. Al aplicarlo al archivo real, la etiqueta GCM fallaba: reconocer el contenedor no bastaba para declarar éxito.
2. Inspeccioné la APK. Sus DEX visibles eran un cargador pequeño y dos stubs; el código principal estaba protegido por DexProtector en `assets/assets.dat`, con un cargador ARM64 `lib/arm64-v8a/libdexprotector.so`. Buscar únicamente en los DEX visibles no mostraba el importador real.
3. Recuperé el runtime nativo y reproduje sus derivaciones y transformaciones, con emulación ARM64 de las rutinas necesarias y sustitutos locales de las funciones del sistema. Recuperé el DEX principal desde los assets sin instalar Android ni reconstruir la APK. Los auxiliares reproducibles están en `tools/tls850_research/`.
4. En el DEX recuperado busqué `AES/GCM/NoPadding`, `SecretKeySpec`, las inversiones de bytes y constantes 12, 18, 36, 84, 96 y 102. La clase relevante es **`Ldd;`**. Su constructor **`<init>(B)V`** crea dos listas de claves distintas. La lista del campo **`d`** corresponde a las configuraciones; la del campo `c` corresponde a listas de servidores.
5. Seguí **`Ldd;->o([B)[B`**, que reconstruye los fragmentos e intenta las claves de configuración hasta que `Cipher.doFinal()` termina sin error. Contrasté con **`Ldd;->t([B)[B`**, que exporta usando el primer elemento de esa lista. **`Ldd;->p([B)Ljava/lang/String;`** procesa listas de servidores con otro layout: no usarlo para el archivo `.tls`.
6. El constructor pasa los literales de clave por **`Lm02;->y0(Ljava/lang/String;)Ljava/lang/StringBuilder;`** y después los convierte a UTF-8. Reconstruí su transformación como una inversión de caracteres: produce las seis claves de 32 bytes de abajo y la primera autentica el archivo real. El cuerpo de ese helper no apareció en el DEX principal recuperado; la inversión está confirmada funcionalmente para esta muestra, no mediante inspección de ese cuerpo. Hay caracteres no ASCII: **invertir caracteres antes de codificar, no invertir los bytes UTF-8**.
7. Tras añadir las claves faltantes, el mismo contenedor del archivo real autentica con el primer perfil. Conservé el algoritmo anterior y añadí pruebas negativas para impedir que una etiqueta inválida produzca una configuración aparentemente correcta.

## Claves de configuración de esta APK

Representación hexadecimal de los bytes que llegan a `SecretKeySpec`, en el orden del campo `d`. Son constantes presentes en la APK, no claves privadas de usuarios.

| Perfil | Clave AES-256, hexadecimal |
| --- | --- |
| 1, exportación actual y muestra real | `2474763534327665643235345671c38b72775742627236c2b324254856232433` |
| 2 | `33cf82ceb7cf84e1baa135566ec6b0686e33d8b661d0bed0bdd0b12578745630` |
| 3 | `23e4bc9acf82ceb7cf84e1baa135676ec6b0686e3332d8b661d0bed0bdd0b125` |
| 4 | `23e4bc9ae685a246e1baa14235676ec6b0686e3332d8b661d0bed0bdd0b12534` |
| 5 | `234673486ee1baa14246355c3332d8b6612534407c666433653247462847c38b` |
| 6, `AES_KEY` del motor anterior | `6b303068c2acc2b9c2b221352473c2b0c2b725c2a824614b674433c2b0467856` |

No es una búsqueda de contraseñas: se prueban exclusivamente las seis claves observadas y solo se acepta una tras verificar el tag. No atribuir versiones históricas concretas a los perfiles 2–6 sin archivos de esas versiones. Su presencia en la APK está confirmada; la muestra real valida el perfil 1.

## Especificación del contenedor `.tls`

El archivo es texto. La muestra termina en `:::::`. Tomar únicamente el segmento anterior al primer `:`; esos sufijos no forman parte del ciphertext. El CLI también acepta `tls://` y espacios de transporte.

Invertir el texto Base64, completar su padding y decodificar. Sea `raw` el resultado, `N = len(raw)` y `H = (N - 132) // 2`. Los rangos siguientes usan índices Python, con extremo final exclusivo:

| Rango en `raw` | Uso |
| --- | --- |
| `raw[:12]` | Relleno exterior ignorado |
| `raw[12:H+12]` | Primer fragmento de ciphertext, invertido |
| `raw[H+12:H+30]` | Primer fragmento de nonce, invertido; 18 bytes |
| `raw[H+30:N-102]` | Segundo fragmento de ciphertext, invertido |
| `raw[N-102:N-84]` | Segundo fragmento de nonce, invertido; 18 bytes |
| `raw[N-84:]` | Relleno exterior ignorado |

Invertir **cada fragmento individual**, después concatenar primero con segundo. El nonce resultante tiene 36 bytes. Los últimos 16 bytes del ciphertext concatenado son la etiqueta GCM; el resto es el ciphertext real. Aplicar **AES-256-GCM, tag de 128 bits, sin AAD**, con las claves de la tabla en orden.

En la muestra: `N=16618`, `H=8243`, ciphertext con tag de 16486 bytes, plaintext de 16470 bytes. La autenticación protege el ciphertext y depende del nonce; no cubre el relleno exterior ni los sufijos. No afirmar que cambiar cualquier byte del archivo completo necesariamente causa un error GCM.

El plaintext es UTF-8 delimitado por `:`. No lleva compresión en esta capa. Algunos campos internos son Base64 de texto: eso es codificación, no otro cifrado. El script decodifica estrictamente UTF-8/Base64 y conserva el valor original si esa interpretación falla.

## Salida y campos: evitar pérdidas o nombres inventados

Se mantienen los nombres heredados para los campos comunes: versión, selección de servidor/puerto, SSH, payload, SNI, proxy y mensaje. La semántica completa del esquema nuevo no se ha reconstruido mediante exportaciones controladas de cada opción.

En particular, las posiciones **20–23** contienen booleanos en la muestra 516; el script antiguo las interpretaba como opciones DNS. Por eso los perfiles nuevos no publican los nombres heredados `legacy_dns_mode`, `dnsP`, `dns_port`, `nameserver` ni `public_key` de posiciones 20–24. Sus valores se conservan por índice. El perfil de la clave antigua mantiene esos nombres para compatibilidad. Esta decisión se basa en la muestra disponible; revisarla al obtener otras variantes.

El objeto añadido `_tls` contiene:

- `authenticated`: resultado positivo de la verificación AES-GCM.
- `key_profile`: posición de la clave utilizada, de 1 a 6; no equivale automáticamente a una versión de app.
- `field_count`: cantidad total de campos, incluidos vacíos y finales.
- `fields`: lista ordenada de `{index, raw, value}`. `raw` conserva exactamente cada campo del texto autenticado; `value` decodifica Base64 en las posiciones heredadas 4, 5, 6, 7, 9, 12, 14, 16, 18, 19, 24 y 27 cuando es válido.

Así se pueden reconstruir los bytes originales con `':'.join(f['raw'] for f in result['_tls']['fields']).encode('utf-8')`. Esto evita perder posiciones no mapeadas, ceros, booleanos y cadenas vacías. Para una futura integración, utilizar `raw` como referencia completa y confirmar los nombres modernos con exportaciones controladas. Descifrado completo confirmado; nombres de todos los campos nuevos, pendientes.

## Uso del decodificador y pruebas

Requiere Python 3.10+ y una de las dos bibliotecas de AES. Para ejecución normal basta PyCryptodome:

```bash
python -m pip install pycryptodome
python decoders/Python/TLS.py configuracion.tls -o resultado.json
```

Sin `-o` mantiene la salida de texto con el encabezado `TLS Tunnel`. `decrypt_tls_payload(text)` devuelve un diccionario o lanza un error; `run(bytes)` conserva el contrato anterior de devolver texto o `None`. CLI: 0 éxito, 1 entrada/descifrado inválido, 2 error de lectura/escritura. Si no está disponible PyCryptodome, el motor utiliza `cryptography`.

Las siete pruebas de `tests/test_tls_decoder.py` se ejecutaron con la muestra real: seis perfiles sintéticos, nombres heredados con la clave antigua, archivo real con ambos backends, alteración de ciphertext rechazada, entradas malformadas, campos desconocidos conservados y URI/CLI. Los casos sintéticos no sustituyen la validación real del perfil 1.

```bash
python -m pip install pycryptodome cryptography
TLS_REAL_SAMPLE=/ruta/privada/archivo-real.tls \
  python -m unittest discover -s tests -p test_tls_decoder.py -v
```

Sin `TLS_REAL_SAMPLE` la prueba privada se omite expresamente y el resto se ejecuta. Esa prueba usa el SHA-256 exacto de esta muestra; para validar otra, registrar su hash y resultado por separado. No subir el archivo ni credenciales a fixtures públicos.

## Recuperación reproducible del DEX protegido

Este apartado permite retomar la investigación cuando las claves cambien. **No es necesario para ejecutar TLS.py.** El driver comprueba el SHA-256 de la APK y rechaza otros builds, porque utiliza direcciones específicas de 8.5.0.

```bash
python -m pip install pycryptodome unicorn pyelftools androguard
# Si el sistema no dispone de libzstd:
python -m pip install zstandard
python tools/tls850_research/recover_tls_850.py \
  "TLS Tunnel_8.5.0.zip" --work-dir /tmp/tls850-inspection
```

También acepta la APK directamente. El directorio de trabajo debe estar vacío. Produce `analysis_tls/real_classes_parse.dex` y checkpoints de investigación. Se interpreta únicamente el pequeño bloque aritmético requerido del protector; no se ejecuta el código recuperado de la aplicación. El nativo sí se emula localmente con Unicorn.

Los scripts conservan los pasos que resultaron necesarios:

| Script | Función |
| --- | --- |
| `unpack_native.py` | Emular el cargador ARM64, recuperar `libdp`, resolver relocaciones y reproducir el borrado de metadatos |
| `open_assets_metadata.py` | Reconstruir la raíz HKDF con firma, DEX visibles y hash nativo; autenticar metadatos de assets |
| `open_java_mix.py` | Interpretar el bloque Java aritmético y las dos tablas de sustitución que modifican la raíz |
| `open_segments.py` | Derivar claves por etapa y abrir los segmentos requeridos |
| `chacha8.py` | Reproducir ChaCha de 8 rondas, usado por el DEX principal |
| `recover_tls_850.py` | Coordinar lo anterior, descomprimir Zstandard y preparar el DEX de inspección |

### Anclas nativas importantes de esta compilación

Direcciones virtuales relativas al `libdp` **desempaquetado**, no offsets del `.so` exterior. Su dump contiene 0x1000 bytes anteriores a la base del runtime. El cargador exterior comienza en su constructor `0x380`; su resolución se intercepta en `0x169c`. La entrada JNI recuperada apunta a `libdp+0x57a48`.

| Ancla en `libdp` | Propósito observado |
| --- | --- |
| `0x4dd48`, `0x20e84`, puntero `0xac340` | Inicialización/copia de las 27 round keys del descifrado de cadenas nativas |
| `0xa9ae8` / `0xa9b74` | IKM de 64 bytes / salt de 32 bytes para HMAC-SHA256 inicial |
| `0x4bc60`, `0xa976c` | Firma de la APK y selección del blob AES-KWP de 40 bytes |
| `0x9ad44` | Incorporar hasta 1024 bytes de cada uno de los tres DEX visibles |
| `0x83b58`, blob `0xaa121` | Hash del runtime y AES-KWP de otro secreto incorporado a la raíz |
| `0x574dc` | Mezcla de datos mediante HKDF-expand seguido de HMAC-SHA256 |
| `0x57580` | Derivación de raíz siguiente y clave hija por etapa |
| `0xaa0fc`, `0x79460` | Semilla de 32 bytes y mezcla Java adicional |
| `0x31a60`, `0x31cf0` | Stream ChaCha8 del segmento principal |

La cadena recuperada, resumida con sus comprobaciones, fue:

1. Restaurar relocaciones y ejecutar inicialización del runtime. El resolver original borra símbolos, strings y relocaciones después de resolverlos. **Ese borrado debe reproducirse:** el hash posterior del código depende de él.
2. Inicializar el descifrado de cadenas antes de usarlas. Incorporar los cambios de IKM del entorno válido: byte `0x37 XOR 1` por la verificación ART y byte `0x3a XOR 0xab` en la ruta de comprobación nativa. El helper reproduce este último llamando a `0x790d0` con el acceso ZIP sustituido.
3. Formar la raíz HMAC-SHA256. Obtener el agregado SHA-256 de certificados del Signing Block de la APK; con SDK 37 se usa el bloque v3. El agregado válido de esta APK es `cbe550ba13b6bf57ed9d9986a04335e02a3c3edadcfdf4b6025df54da05fff87`. Autentica el cuarto blob AES-KWP, en `0xa97e4`. Incorporar su secreto y los tres DEX visibles.
4. Calcular SHA-256 del runtime desde su base hasta longitud `0x9ca90`, una vez aplicado el borrado. El hash observado es `fc7ebd4372fc442cae243f4be2aee9868a0887c5a4e47731f73cecf67c419de0`; permite abrir por AES-KWP el blob de `0xaa121` y mezclar su secreto.
5. En cada mezcla: `salt = HKDF-Expand(prk, LE64(0x07ffcfc433e03432), 32)` y `prk = HMAC-SHA256(salt, datos)`. La raíz resultante debe producir `607bb009` con `HKDF-Expand(prk, LE64(0x91a4fb076b659459), 4)`. Esta comprobación nativa permite detectar una derivación equivocada antes de seguir.
6. Derivar 44 bytes con info `LE64(0x5d4e7ccff0335568)`: clave de 32 y nonce de 12. Los metadatos finales de `assets.dat` usan **ChaCha20-Poly1305**, tag de 16 y AAD del último byte. En esta APK ese byte vale 34: `ciphertext=assets[-51:-17]`, `tag=assets[-17:-1]`, `AAD=assets[-1:]`.
7. Los metadatos autentican nueve segmentos. El segmento tipo 9 ocupa 1700 bytes desde offset 0 y contiene un DEX auxiliar de 1684 bytes; se abre con ChaCha20-Poly1305 y info `LE64(0x3045c9c1c2460b68)`. Su clase `ProtectedApp$w` aplica operaciones XOR, suma y rotación sobre ocho palabras de 32 bits. Antes pasa la semilla por las dos tablas de `ProtectedApp.a([B)[B`; **el orden observado es `table0[table1[byte]]`**. El auxiliar reproduce ese bloque y mezcla sus 32 bytes en la raíz.
8. Para cada etapa, HKDF-expand de 64 bytes deja los primeros 32 como siguiente raíz y los últimos 32 como clave hija. Para el segmento principal tipo 5, info `LE64(0x873552bc11e8ff0e)`, expandir la hija con info vacía a 44 bytes. Abrir sus 5 881 533 bytes desde offset 1700 mediante **ChaCha8, contador 0**, no ChaCha20. Los primeros cuatro bytes del resultado anuncian 13 910 452 bytes descomprimidos; lo siguiente empieza con magic Zstandard `28b52ffd`.
9. Descomprimir. El resultado incluye un tráiler del protector. Recortar al `file_size` DEX, 12 873 920 bytes, y recalcular Adler-32 para la copia de inspección que acepta Androguard. No utilizar esa copia para reconstruir o distribuir una APK.

Los segmentos autenticados posteriores, incluido el tipo 4 con info `LE64(0xf9a939c6fcae9717)`, verificaron correctamente, confirmando el orden de derivación. Los errores que más hicieron perder tiempo fueron omitir cambios del IKM, no reproducir el borrado de metadatos, invertir el orden de tablas Java y usar ChaCha20 en el segmento que realmente utiliza ChaCha8.

**Esta criptografía de DexProtector solo protege el código de la APK. El archivo de usuario `.tls` utiliza AES-GCM con las seis claves de configuración. No trasladar HKDF, firma APK, ChaCha8 ni Zstandard al decodificador del archivo.**

## Lista breve para revisar otra actualización

1. Registrar hashes y versión de la nueva APK/archivo. Probar el motor y exigir tag válido; un texto legible aislado no es prueba suficiente.
2. Si autentica, conservar la clave usada y verificar número de campos y Base64 interno. No cambiar claves por un fallo de nombres de campos.
3. Si no autentica, localizar de nuevo el cifrado de configuración. Buscar las operaciones y tamaños anteriores, la lista de `SecretKeySpec` y su inversión Unicode. Los nombres `dd`, `m02` y `fe` pueden cambiar por ofuscación.
4. Si los DEX son solo stubs, revisar la nueva protección. El harness incluido se limita al hash de 8.5.0: adaptar offsets, Signing Block, semillas y etapas a la nueva APK; no desactivar la comprobación de hash y suponer que siguen válidos.
5. Añadir claves nuevas conservando las anteriores cuando la app mantenga el formato. Si cambia el layout, añadir una ruta separada y comprobar también fixtures de la anterior.
6. Para asignar nombres a los campos nuevos, exportar configuraciones propias cambiando una sola opción cada vez y comparar el plaintext autenticado por índice. Mientras tanto conservar todos los `raw`.
7. Validar al menos un archivo real nuevo y uno corrupto, actualizar esta guía y entregar Python en una rama independiente. No fusionar cambios Android ni publicar APKs como parte de esa revisión.
