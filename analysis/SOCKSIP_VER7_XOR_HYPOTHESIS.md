# Hipótesis SocksIP VER7: capa hexadecimal + XOR

## Información recibida

Se recibió la afirmación de que una segunda capa de los perfiles SocksIP utiliza XOR y que todavía existirían cuatro capas adicionales.

El fragmento proporcionado usa la misma clave de 16 bytes ya confirmada para el AES exterior:

```text
192e04080804040905592959385f5417
```

También convierte una cadena hexadecimal a bytes antes de aplicar XOR repetitivo.

## Orden de capas coherente con la evidencia previa

El código recibido intenta aplicar XOR directamente al archivo `.sip`, pero esto contradice el flujo exterior ya demostrado. El orden investigado en esta rama es:

```text
archivo .sip
  -> Base64 exterior
  -> AES-128-ECB + PKCS#7
  -> marcador VER7
  -> texto hexadecimal
  -> XOR repetitivo con la clave conocida
  -> hasta cinco transformaciones estructurales acotadas
  -> JSON o Java Object Serialization válida
```

La hipótesis no se considera confirmada hasta ejecutarla contra una muestra VER7 real.

## Implementación experimental

Archivo:

```text
decoders/Python/sockip_ver7.py
```

Restricciones:

- requiere el marcador `VER7`;
- requiere hexadecimal estricto después del marcador;
- usa exclusivamente la clave conocida;
- conserva los bytes XOR sin decodificación UTF-8 con `errors="ignore"`;
- limita la profundidad a cinco transformaciones posteriores;
- limita el análisis a 96 candidatos únicos;
- sólo declara éxito si obtiene un objeto JSON o una serialización Java válida.

Transformaciones posteriores permitidas mediante el analizador existente:

- Base64;
- hexadecimal;
- GZIP;
- ZLIB;
- ZIP;
- serialización Java encontrada con desplazamiento.

## Problemas detectados en el fragmento recibido

1. `decrypt_sip_with_xor()` aplica XOR antes de Base64/AES, aunque la capa exterior ya está confirmada.
2. El XOR se ejecuta sobre el contenido completo en lugar del payload posterior a `VER7`.
3. `decode("utf-8", errors="ignore")` elimina bytes y puede fabricar texto aparentemente válido.
4. El resultado `{"raw_decrypted": ...}` se acepta sin una firma estructural verificable.
5. `format_sip_advanced_output()` no retorna `result` en el fragmento proporcionado.
6. Se usan símbolos no definidos dentro del fragmento: `logger`, `get_premium_icon`, `sc` y `decrypt_sip_file`.
7. El lector Java y la capa AES son esencialmente la misma implementación que ya existía en SP-DECODE; no aportan evidencia nueva sobre VER7.

## Pruebas añadidas

Archivo:

```text
tests/test_sockip_ver7_xor.py
```

Cubre:

- reversibilidad del XOR repetitivo;
- `VER7 -> hex -> XOR -> JSON`;
- una cadena con cuatro transformaciones después del XOR;
- rechazo de payload no hexadecimal;
- prevención de falsos positivos cuando el XOR produce bytes sin estructura válida.

## Uso experimental

Diagnóstico:

```bash
python decoders/Python/sockip_ver7.py archivo.sip
```

Intento de decodificación estricta:

```bash
python decoders/Python/sockip_ver7.py archivo.sip --decode
```

Sin una muestra real, el resultado de las pruebas sintéticas sólo demuestra que el pipeline propuesto está implementado correctamente; no demuestra que SocksIP use realmente esta secuencia.
