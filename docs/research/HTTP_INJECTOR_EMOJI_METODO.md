# HTTP Injector 6.5.0/244: codec de emojis y acceso cloud

Fecha: 2026-10-11. Script independiente: `decoders/Python/HTTPINJECTOR_EMOJI.py`. Necesita `HTTPINJECTOR_CLOUD.py` y `HTTPINJECTOR.py` junto a él. No modifica el lector EHI ni integra Android.

## Qué contiene la secuencia

La exportación `💉…🚀` codifica **una clave de configuración cloud**, no todo el archivo ni una contraseña criptográfica. Primero se recupera esa clave; después se usa el mismo endpoint, firma y descifrado de respuesta descritos en [HTTP_INJECTOR_CLOUD_METODO.md](HTTP_INJECTOR_CLOUD_METODO.md). Sólo resolver la clave funciona sin Internet; recuperar la configuración depende del servidor y de que el enlace siga disponible.

## Cómo se encontró el algoritmo

Se analizó la APK suministrada `com.evozi.injector` 6.5.0/244. SHA-256 de `base.apk`: `5dc3976ad0d90c14b79f5848109296998f930c9d36be88fba9115c078f60dfe3`. La recuperación de DEX parciales y cadenas está documentada en el documento cloud y en el checkpoint privado. No fue necesario ejecutar Android ni reconstruir su máquina virtual entera.

El codec real se localizó en el DEX primario, clase `com/google/android/gms/common/internal/ۦۤۘۤ`:

| Método / code_item | Evidencia |
| --- | --- |
| `<clinit>`, `0x438a94` | Constante decimal **128467**, hexadecimal **0x1F5D3**; `Character.toChars` |
| Decode, `0x438af8` | `codePointAt`, `charCount`, resta del desplazamiento, Base64, UTF-8 |
| Encode, `0x438bc8` | UTF-8, Base64 NO_WRAP, suma del mismo desplazamiento |

La clase Base64 `ʱ` usa el alfabeto estándar `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`. El flag de este flujo es `2` (`NO_WRAP`), **no `8` URL_SAFE**. El padding `=` se incluye. No usar el alfabeto Base64 personalizado de las capas EHI.

El importador maneja los marcadores `💉` y `🚀` fuera del codec. Para el interior, iterar puntos de código Unicode, no bytes UTF-8 ni unidades UTF-16 aisladas. El codec hace:

```text
ascii_base64 = concatenar(chr(codepoint(emoji) - 128467))
raw = Base64_estándar_decode(ascii_base64)
config_key = UTF8_decode(raw)
```

La exportación inversa hace Base64 estándar de los bytes UTF-8 de la clave y convierte cada carácter ASCII en `chr(ord(char) + 128467)`, entre los dos marcadores. La constante **no es 0x1F600**; deducirla por la apariencia de las caras da resultados falsos.

El script exige marcadores, alfabeto válido, Base64 canónico con padding, UTF-8 válido y clave cloud válida. Sólo elimina espacios externos y acepta BOM en archivos de texto. No normaliza emojis, no elimina selectores de variación ni sustituye caracteres por otros parecidos.

## Pruebas reales y límite del ejemplo recibido

La secuencia original recibida se conservó exactamente. Al aplicar el codec real produce:

```text
Base64: cjlHZo5HREw=
Bytes:  72 39 47 66 8e 47 44 4c
```

`0x8E` en el índice de byte 4 no es UTF-8 válido. Por ello el script la rechaza antes de contactar al servidor. Android `new String(..., UTF-8)` puede reemplazarlo por U+FFFD, pero ese reemplazo no recupera una clave válida. No se cambió ningún emoji para adivinar una referencia. Hace falta copiar de nuevo la exportación original para probar **ese ejemplo exacto** de principio a fin.

Para probar el flujo completo se convirtió la clave del **enlace cloud real del usuario** a emojis usando el método inverso demostrado en la APK. La CLI emoji recuperó esa clave, descargó la configuración real, verificó HMAC y etiqueta EHI, y produjo exactamente el mismo JSON de 48 campos que la CLI cloud. **Ese ejemplo positivo es una representación derivada del enlace real, no una segunda exportación emoji original suministrada por el usuario.** El enlace, la representación derivada y las salidas se guardan de forma privada.

El vector sintético público de las pruebas es independiente de las configuraciones:

```text
💉😩😘😩😧😩😗😘🙌😠🙍😤😐🚀
-> VEVTVDEyMzQ=
-> TEST1234
```

Las pruebas incluyen Unicode, padding no canónico, marcadores truncados, símbolos extra, UTF-8 inválido y dependencia de red. La prueba cloud privada reutiliza una respuesta real y comprueba que la entrada emoji llega al mismo motor. Pasaron 20 pruebas conjuntamente con las del EHI anterior y cloud.

## Uso y continuidad

```bash
python -m pip install pycryptodome argon2-cffi
python HTTPINJECTOR_EMOJI.py emojis.txt -o emoji.json --audit emoji_audit.json
python HTTPINJECTOR_EMOJI.py '💉…🚀' --key-only
```

`--key-only` devuelve `config_key` y URL sin descarga. Sin esa opción devuelve el JSON de configuración, con tipos y campos intactos. `decode_emoji_key(token)` resuelve la referencia; `decode_emoji(token, audit)` recupera el documento completo; `encode_emoji_key(key)` permite comprobar exportación inversa; `run(bytes)` devuelve el texto del bot o `None`. Usar las funciones que lanzan `EmojiError`/`CloudError` para mostrar el motivo de un fallo. No se añadió reconocimiento al bot.

Ante una actualización: guardar una pareja conocida enlace/emojis exportada por la nueva APK; localizar `codePointAt`, `Character.toChars`, UTF-8 y Base64 en la ruta de importar/exportar. Comparar el desplazamiento, los marcadores, alfabeto, flags y padding. Validar primero que los emojis recuperan exactamente la clave conocida y luego comprobar la respuesta mediante el script cloud. Si la clave es correcta pero falla la descarga, revisar firma y API cloud; si la clave no es válida, revisar copia/Unicode/codec antes de tocar AES o claves EHI. No dar compatibilidad nueva por demostrada con un simple roundtrip generado por el propio script.
