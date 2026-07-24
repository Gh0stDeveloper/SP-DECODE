# Estado de investigación SocksIP `.sip` / `VER7`

Rama de trabajo: `analysis/sockip-ver7`

Este documento registra únicamente conclusiones comprobadas durante la investigación. La rama `master` permanece sin estos cambios experimentales.

## 1. Capa exterior confirmada

Para la línea pública moderna de SocksIP analizada, el flujo de importación es:

```text
archivo .sip (texto Base64)
    -> Base64.decode
    -> nativo.xyz(bytes, 2)
    -> ObjectInputStream
    -> readObject
    -> SerSocksIP
```

El JNI exportado `Java_newtoolsworks_com_socksip_utils_nativo_xyz` fue desensamblado en ARM64. Su operación equivalente es:

```java
byte[] key = hex("192e04080804040905592959385f5417");
SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
Cipher cipher = Cipher.getInstance("AES");
cipher.init(mode == 1 ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec);
return cipher.doFinal(input);
```

En Android/JCE, `Cipher.getInstance("AES")` en este caso corresponde al comportamiento reproducido por el decoder actual: AES-128-ECB con padding PKCS#7/PKCS#5 compatible.

Por tanto, la capa exterior actual de `decoders/Python/sockip.py` no debe sustituirse por el paquete Go `aes256` encontrado como código no relacionado dentro de `libgojni.so`.

## 2. Ruta de importación confirmada

Se rastrearon las rutas principales:

- `ImportActivity` lee el URI como texto y lo reenvía sin transformar a `MainActivity` mediante `READFILE` / `FILE`.
- `MainActivity` entrega el contenido a `ConfigSocksIP.LoadConfigStream`.
- `LoadConfigStream` llama a `Configuration.DecodetoBytes`.
- `DecodetoBytes` aplica Base64 y `Cifrado.Decrypt`.
- `Cifrado.Decrypt` llama a `nativo.xyz(data, 2)`.
- El resultado pasa directamente a `ObjectInputStream`.

No se encontró una segunda transformación Java entre `nativo.xyz` y la serialización.

## 3. Resultado de la búsqueda histórica pública

Se inspeccionaron builds públicas de `com.newtoolsworks.sockstunnel` con versionCode:

- 108
- 109
- 110
- 112
- 114
- 116
- 119
- 120
- 121
- 122
- 124

En esta línea no se encontró una implementación literal `VER7`. El núcleo `Configuration -> Cifrado -> nativo -> ObjectInputStream` conserva el mismo modelo de descifrado.

También se inspeccionó el paquete histórico separado `com.newtoolsworks.socksiptunnel`, versionCode:

- 5
- 7
- 10
- 13

Esas builds tampoco contienen `VER7` y no presentan la misma arquitectura `.sip`/`ConfigSocksIP` de la línea moderna.

Conclusión actual: las muestras que después de la capa exterior producen `VER7` no están explicadas por ninguna de las builds públicas inspeccionadas. Esto apunta a una variante, fork, build privada/modificada o distribución diferente de SocksIP. Esta conclusión no pretende afirmar que se hayan inspeccionado todas las builds que hayan existido.

## 4. Cambios experimentales en esta rama

`decoders/Python/sockip.py` ahora:

1. Separa `decode_outer_layer()` para la capa Base64 + AES confirmada.
2. Conserva la ruta de serialización Java existente.
3. Si aparece `VER7`, prueba únicamente transformaciones deterministas y acotadas:
   - serialización Java desplazada dentro del contenedor;
   - JSON directo;
   - Base64 interno;
   - hexadecimal interno;
   - GZIP;
   - ZLIB;
   - ZIP con límites de tamaño.
4. No prueba claves criptográficas inventadas ni devuelve contenido desconocido como si estuviera descifrado.
5. Añade `inspect_profile()` y la opción CLI `--inspect` para obtener:
   - tamaño;
   - SHA-256;
   - entropía;
   - prefijo hexadecimal;
   - posición de una posible cabecera Java;
   - alineación a bloque del payload VER7;
   - transformaciones estructurales candidatas.

Se añadieron pruebas en `tests/test_sockip_ver7_probe.py` para:

- `VER7 + JSON`;
- `VER7 + Base64(JSON)`;
- `VER7 + ZLIB(JSON)`;
- `VER7 + GZIP(JSON)`;
- rechazo explícito de un `VER7` desconocido para evitar falsos positivos.

## 5. Validación

Se abrió un draft PR de investigación contra `master` para ejecutar la validación sin fusionar cambios.

El workflow fue creado, pero el primer job terminó antes de ejecutar cualquier step y GitHub no entregó logs del runner. Por ello, ese fallo no demuestra un error del código ni un éxito de las pruebas. La rama debe considerarse todavía experimental hasta ejecutar la suite completa en un runner funcional.

## 6. Pieza técnica que falta

Para reconstruir el algoritmo VER7 real hace falta al menos uno de estos artefactos exactos:

- una muestra `.sip` que produzca `VER7` después de `decode_outer_layer()`;
- el APK/binario exacto instalado que realmente importe esa misma muestra.

Con una muestra real, el nuevo `--inspect` permite determinar inmediatamente si el payload es un wrapper estructural conocido o datos de alta entropía que indiquen una segunda transformación criptográfica. Con el APK exacto, la ruta que consume ese payload puede rastrearse hasta su implementación real.

No se debe fusionar a `master` una implementación VER7 basada en conjeturas.
