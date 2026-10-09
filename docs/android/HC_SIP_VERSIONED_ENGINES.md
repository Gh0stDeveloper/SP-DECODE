# HC y SIP — arquitectura de variantes (2026-10-09)

## Fuentes y compatibilidad

Código aportado por el propietario: `HttpCustom.py` (nuevo **HCCFG**) y
`sipnew.py` (nuevo **VER8**). El código se incorporó **sin sustituir** los
decodificadores existentes y sin convertir una prueba sintética en una
certificación de versiones comerciales.

| Sufijo | Variante previa | Variante nueva | Bot | Android |
|---|---|---|---|---|
| `.hc` | ChaCha20/outer-XOR/RST y formato histórico de `HTTPCUSTOM.py` | HCCFG schemas 1/2/5/7; n1/n2/n7/n8; XChaCha20-Poly1305, HKDF y perfiles HPC1 | Referencia `_hc_hccfg.py` detrás de `HTTPCUSTOM.py` | `HcPort.kt` preservado + `HcHccfgPort.kt` |
| `.sip` | Base64, AES-128-ECB/PKCS#7 y Java Serialization | VER8 con AES-GCM (12 bytes de nonce y 16 de tag) después de la capa ECB | `sockip.py` | `SipPort.kt` + `SockipObjectReader.kt` |

El registro `decoders.json` conserva las **mismas 59 extensiones**: no se
duplica la extensión según su versión interna. Los motores antiguos se
mantienen en sus rutas originales. `VER7` continúa reportando que no hay
un decodificador verificado de esa variante; VER8 **no implica soporte VER7**.

## Protocolo HC

El motor HCCFG nuevo distingue el sobre estándar autenticado con AAD
`HCX1|xyz.easypro.httpcustom|1` del sobre V3 de flujo.
Lee `a=HCCFG`, la versión de esquema `b`, el calendario `e`,
la clave de 32 bytes `g` y los metadatos `f`/`n`.
Deriva la clave de sección mediante el transcript + HKDF-SHA256;
para `n7/n8` emplea HMAC adicional. La protección `h=1`
requiere Argon2id y contraseña. `n2/n8` requiere HWID explícito
y slots autenticados. Las secciones principales y perfiles se autentican
antes de interpretar JSON o los 11 campos HPC1, incluidos opciones,
host, puerto, credenciales, payload y metadatos.

**Limitaciones actuales:** el ejecutor de archivos de Telegram es
no interactivo: nunca debe invocar `input()`. En los perfiles que
necesitan contraseña/HWID, devuelve un error explícito, no un resultado
supuestamente descifrado. El puerto Android acepta estos parámetros en su
API, pero la UI no tiene todavía un formulario para solicitarlos. Los
formatos sin estas restricciones se procesan automáticamente. El sobre
V3 y el reenvoltorio HPR1 conservan la compatibilidad del script aportado;
se exige al menos la autenticación válida de la sección cifrada antes
de extraer información y **faltan vectores independientes** para
certificar dichos caminos.

## Protocolo SIP

El mismo AES-ECB original se usa solo para obtener el contenedor:
- Si comienza con la cabecera de serialización Java
  `AC ED 00 05`, se conserva la ruta clásica.
- Si contiene `VER8`, se separan los siguientes 12 bytes como
  nonce AES-GCM, se autentica `ciphertext || tag16` con la clave
  de 32 bytes **literal del archivo aportado**, y **solo después**
  se interpreta la serialización Java con límites de tamaño,
  objetos, arrays y profundidad.
- Un tag inválido o un Java stream inválido se rechaza; nunca
  se pasa al decodificador antiguo como si fuese éxito.
- Si contiene `VER7`, sigue siendo una variante no implementada.

La clave AES-GCM literal del código aportado es
`cambia_esto_por_tu_llave_de_32_b` (32 bytes ASCII). **El propietario
confirmó explícitamente el 2026-10-09 que esta clave es funcional** en
la versión `VER8` de SocksIP y no es un marcador de sustitución.
Se conserva exactamente en Python y Kotlin; el nombre aparentemente
provisional no autoriza a modificarla, derivarla ni reemplazarla.

**Evidencia diferenciada:** esta confirmación del propietario establece
la funcionalidad observada de la clave. La batería CI existente usa
vectores generados sintéticamente con la misma clave; esos tests
certifican la coherencia de ambas implementaciones, pero no sustituyen
una prueba de paridad registrada de un exportador comercial real.

## Pruebas y estado

- `tests/test_hc_sip_new_variants.py`: vectores sintéticos nuevos,
  retrocompatibilidad y rechazo de manipulación.
- `tests/golden/hc_sip_new_variants.py`: datos de prueba deterministas,
  ejemplo.org, claves/contraseñas exclusivamente ficticias.
- `scripts/android_hc_sip_fixture_export.py`: prepara los archivos
  sintéticos para las pruebas instrumentadas API35.
- `HcSipVersionedInstrumentedTest.kt`: verifica las variantes
  antiguas/nuevas y falla ante etiquetas de autenticación alteradas.

**Estado de certificación de terceros: NO VERIFICADO.**
Faltan archivos reales autorizados por el propietario y versiones exactas
de las aplicaciones exportadoras, y repetir pruebas en ARM64/páginas de
16 KiB cuando proceda. No se incorpora un golden comercial inventado.

## Plantilla de integración para futuras extensiones

1. Conservar el archivo original, su algoritmo y rutas de error para
   poder comparar la implementación.
2. Inventariar *magic bytes*, serialización, derivación de clave,
   autenticación, versiones y protección por contraseña/HWID.
3. Hacer **detección estructural** dentro de la extensión registrada
   y no sustitución ciega del motor anterior.
4. Añadir un adaptador Python **no interactivo** para el bot.
5. Portar a Android solo primitivas verificables, con límites estrictos
   de tamaño, profundidad y tiempo, sin subprocess ni red.
6. Construir tests positivos sintéticos y negativos (tag corrupto,
   datos truncados, versión desconocida), y comprobar que todas las
   versiones antiguas siguen funcionando.
7. Ejecutar Linux + emulador Android y comprobar firma/release
   por separado. Clasificar muestras comerciales como pendientes
   hasta disponer de pruebas reales autorizadas.
