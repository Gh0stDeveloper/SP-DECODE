# LinkLayer VPN (.lnk) VER6 — integración Android 1.0.3

## Origen de la implementación

Decodificador de referencia `decoders/Python/linklayer.py` generado y probado
por Codex sobre un archivo auténtico facilitado por el propietario: LinkLayer
VPN 3.11.2 (93), formato VER6. La muestra real **no se publica**.

El puerto `android/.../parity/LinkLayerPort.kt` implementa el mismo método
en Kotlin y Bouncy Castle ligero, sin Python ni servicio externo:

```text
VER6 + Blowfish-CFB (clave 8 bytes al final)
 -> clave AES 32 bytes derivada del material extraído
 -> AES-CFB
 -> contenedor Salsa20 + reordenamiento
 -> 3 segmentos, seleccionar el segmento central
 -> CAST5-CFB + bandera de orden
 -> PBKDF2-HMAC-SHA1 (1500 iteraciones) para XOR inicial
 -> reconstrucción de clave/ciphertext
 -> AES-CFB
 -> lector Go gob de solo datos (NativeConfig)
 -> JSON: 60 campos hoja con bool, int y strings, incluso ceros omitidos
```

El formato **no contiene MAC criptográfico**. La validez del esquema Go gob
y los 60 campos es una comprobación estructural, **no autenticación**.
No se aceptan contenedores truncados, versiones distintas o tipos Go gob
fuera del esquema LinkLayer 3.11.2. El límite de 8 MiB aplica **solo a
archivos `.lnk`**; el resto continúa limitado a 1 MiB en importación Android.

## Integración

- El bot recibe `.lnk` mediante `decoders.json` y el Python de la rama
  `analysis/linklayer-ver6` que se copió sin alterar el algoritmo.
- Android usa `AndroidOfflineDecoderRouter` y una entrada nueva en el
  catálogo generado. Inventario total **60 sufijos**.
- El corpus congelado previo de 59 extensiones y 60 pruebas sintéticas
  permanece sin cambios. Las pruebas LinkLayer se ejecutan **aparte**.
- Las cadenas de la app están en ES, EN, PT-BR y AR; la salida Go no se
  traduce ni se ocultan silenciosamente campos del resultado original.
- La alerta `Novedades de SP-DECODE` aparece tras el splash solo si
  `last_seen_whats_new_version < versionCode`. Al cerrarla se guarda
  el código en preferencias, sin mostrarla en cada apertura.
- Versión candidata `1.0.3`, código 14; Release estable sigue NO-GO.

## Pruebas

- Python: `tests/test_linklayer_ver6.py` (10 pruebas originales, contrato CLI,
  esquema íntegro, entradas inválidas y revisión del ejecutor del bot).
- Generador: `scripts/android_linklayer_fixture_export.py` crea dos
  contenedores sintéticos con orden CAST alternativo, JSON esperado obtenido
  directamente del Python y dos negativos.
- Android API35: `LinkLayerVer6InstrumentedTest.kt` compara todos los 60
  campos contra JSON Python y comprueba errores y ausencia de fallback.
- UX: `WhatsNewVersionInstrumentedTest.kt` comprueba que el aviso se muestra
  una vez por versión y no reaparece al recrear la Activity.

**Evidencia aún pendiente:** ejecutar paridad Kotlin con el archivo real del
propietario en un dispositivo autorizado y revisar rendimiento ARM64/16 KiB.
Los fixtures generados por el mismo código no equivalen a validación externa.
Se requiere fallo explícito en variantes de LinkLayer diferentes a VER6.

## Distribución

CI Linux y Android deben pasar en el commit definitivo. La pre-release
firmada debe utilizar exactamente la keystore permanente de GitHub Secrets
y conservar las anteriores en Releases. La puerta estable NO-GO no cambia.
