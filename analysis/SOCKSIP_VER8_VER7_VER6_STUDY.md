# Investigación SocksIP: VER8 como referencia, VER7 pendiente, VER6 futuro

**Fecha:** 2026-10-09 · **Alcance:** análisis de formatos y preparación reproducible.
Este documento separa el comportamiento demostrado por `sipnew.py`, las
observaciones del repositorio y las hipótesis no verificadas.

## 1. Hechos confirmados del código VER8 aportado

En `sipnew.py`, `decrypt(p)` realiza, exactamente en este orden:

```text
archivo .sip (texto Base64 con saltos de línea opcionales)
    └─ Base64 -> bytes de ciphertext AES-ECB
       └─ AES-128-ECB con clave histórica de 16 bytes
          └─ eliminación de padding PKCS#7
             └─ exigir cabecera ASCII "VER8" (4 bytes)
                └─ x = plaintext_exterior[4:]
                   ├─ nonce = x[:12]                  (12 bytes)
                   ├─ ciphertext = x[12:-16]           (longitud variable)
                   └─ tag de autenticación = x[-16:]   (16 bytes)
                      └─ AES-256-GCM; descifrar Y AUTENTICAR
                         └─ Java Object Serialization (AC ED 00 05)
                            └─ recorrido de campos -> JSON
```

- La clave AES-ECB es la misma del decodificador histórico. No se
  sustituye ni se aplica una clave diferente a esa etapa.
- **La clave GCM literal aportada es funcional según confirmación directa
  del propietario del proyecto**, no un valor ficticio por el aspecto
  de su nombre. No modificar el literal de Python/Kotlin.
- La verificación del *tag* GCM es obligatoria; sin ella, no existe
  autenticidad del contenido interno. `sipnew.py` utiliza
  `decrypt_and_verify`; Android utiliza JCA y `sockip.py` PyCryptodome.
- El formato de salida es la serialización Java ya conocida y debe
  interpretarse como **datos**, sin instanciar clases procedentes del archivo.
- El parser VER8 **no prueba** ningún detalle criptográfico del VER7/VER6.

### Diferencias entre código fuente, pruebas y evidencias

| Afirmación | Evidencia | Estado |
|---|---|---|
| Capa Base64 + AES-ECB compartida | `sipnew.py` + `sockip.py` actual | Demostrada por código; cubierta con fixtures |
| Cabecera `VER8` de 4 bytes | Comparación de marcador en `sipnew.py` | Confirmada |
| Nonce 12, tag 16, AES-GCM | Slices y `decrypt_and_verify` | Confirmada por código |
| La clave GCM literal funciona | Confirmación directa del propietario (2026-10-09) | Declaración explícita del usuario |
| Serialización Java | `javaobj.loads` + lector Kotlin de solo datos | Confirmada por código |
| VER7 emplea la misma capa GCM | Ninguna evidencia | **No confirmado** |
| VER6 emplea la misma capa GCM | Ninguna evidencia | **No confirmado** |

## 2. Conocimiento anterior de VER7 recuperado del repositorio

Existe trabajo histórico en la rama
`analysis/sockip-ver7` y el PR
`#2` sobre una hipótesis
`VER7 -> hexadecimal estricto -> XOR repetitivo con la clave AES-ECB`,
seguido hipotéticamente de capas Base64/hex/comprimidos/Java.

- Esa hipótesis utiliza la **misma capa exterior Base64 + AES-ECB**,
  pero nunca quedó confirmada con un archivo VER7 auténtico.
- Sus pruebas son **sintéticas** y no se pueden presentar como una
  implementación validada de SocksIP VER7.
- Los scripts históricos del PR #2 importan funciones del `sockip.py`
  antiguo que no coinciden con la interfaz de `main` actual; no copiarlos
  ni fusionarlos sin adaptación y regresiones.
- Otros APK analizados anteriormente mostraban un trayecto Java
  clásico sin implementación identificable del envoltorio VER7. Eso
  tampoco prueba que otros builds/exportadores no usen VER7.

## 3. Estructura comparada sin inventar algoritmos

```text
                            archivo .sip
                                 |
                             Base64
                                 |
                     AES-128-ECB + PKCS#7
                                 |
                         cabecera interior
                          /      |       \
                   Java ACED   VER8     VER7 / VER6
                       |        |          |
                 lector Java  nonce12   CONTENEDOR
                             AES-GCM      NO DETERMINADO
                              tag16        |
                               |        requiere prueba
                           lector Java   de estructura
```

Un marcador `VER7` o `VER6` **no demuestra** una variante de AES-GCM.
Cambiar solo la condición `VER8` por `VER7` no basta: es necesario
confirmar mediante fuente o muestra conocida el formato, clave/derivación,
nonce/IV, AAD, tag y el tipo de bytes resultantes.

### Datos que faltan para VER7 y VER6

1. Uno o más archivos `.sip` creados/exportados legalmente con la
   versión concreta de la aplicación y de preferencia su número de build.
2. Una configuración controlada cuyo contenido original conozca el
   propietario (por ejemplo, campos ficticios `example.org`), a fin de
   comprobar la salida sin inventar un éxito.
3. Idealmente el APK del **mismo build** que exportó la muestra, para
   localizar el procedimiento de cifrado y no inferirlo de otra versión.
4. Al menos una muestra negativa/truncada o modificada y, si procede,
   muestra con protección habilitada para separar autenticación de cifrado.

## 4. Herramienta local de diagnóstico estructural

`scripts/inspect_socksip_versions.py` analiza solo la envoltura exterior:

```bash
python scripts/inspect_socksip_versions.py archivo.sip
```

El informe JSON identifica `legacy-java`, `VER8`, `VER7`,
`VER6` y otras versiones con marcador; para VER8 valida el tag GCM
y estructura Java. Para VER7/VER6 **no ejecuta hipótesis de descifrado**,
sino que muestra longitud, SHA-256 y rasgos de codificación sin imprimir
texto de configuración ni credenciales.

- `hex_text_candidate` o `base64_text_candidate` indica únicamente
  que los bytes parecen pertenecer a ese alfabeto. No significa que sea
  realmente la siguiente capa.
- La herramienta no modifica el archivo ni informa `parse_supported=true`
  en variantes de cifrado desconocidas.
- El test `tests/test_socksip_version_inspection.py` cubre detección,
  compatibilidad anterior, autenticación VER8 e integridad negativa.

## 5. Contrato para futuras versiones VER6/VER7

Mantener `sockip.py` y `SipPort.kt` intactos hasta disponer de un
decodificador **independiente, con fixtures positivos reales** para
cada variante; no habilitar ni anunciar un VER7/VER6 por semejanza.

La futura implementación debería incorporar detección por *magic bytes*
+ un motor independiente por variante, límite de memoria, salida Java
datos-solo, fallos tipados, paridad bot/Android y documentación que
identifique los builds verificados.

**Estado actual:** VER8 integrado; VER7/VER6 únicamente
caracterización estructural. Compatible con el Release firmado previo,
sin afirmar que el APK ya decodifica esos formatos.
