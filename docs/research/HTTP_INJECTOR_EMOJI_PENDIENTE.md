# HTTP Injector 6.5.0: emojis — investigación pendiente

Fecha: 2026-10-11. **No hay un alfabeto emoji, una ruta de descifrado completa ni una exportación emoji real verificados todavía.** No se entregó un script con un mapeo inventado.

La APK contiene bibliotecas de compatibilidad emoji de Android; esos nombres no son evidencia del formato de intercambio. Los DEX `assets/audience_network` son publicidad. El código de configuración está protegido en `libdatajar`, `libdexjniehi` y las clases/wrappers de `ConfigActivity`. La extracción parcial está descrita en `HTTP_INJECTOR_650_METODO.md`.

Parte de las cadenas de la aplicación se obtiene mediante un descodificador que recibe constantes `long`. El pool parcial MessagePack de la biblioteca Fort no expuso un alfabeto emoji confirmado. Reconocer una secuencia Unicode o encontrar `EmojiCompat` no permite inferir una tabla de 64/256 símbolos ni afirmar que es Base64.

Para continuar se necesita texto emoji exportado directamente de la app, sin capturas ni transcripción manual; idealmente dos exportaciones de una configuración controlada con un único campo cambiado. Conservar los bytes UTF-8 originales, variantes de presentación U+FE0F, modificadores, ZWJ y delimitadores. Extraer el método exportador/importador y verificar si opera por punto de código, unidad UTF-16 o secuencia completa; no normalizar Unicode antes de saberlo.

Una vez confirmado el alfabeto y la envoltura, implementar `decoders/Python/HTTPINJECTOR_EMOJI.py` separado, con errores de símbolo desconocido, truncamiento y delimitador. Probar vuelta a bytes y el descifrado del archivo/configuración real. Sólo reutilizar EHI si ese contenedor aparece realmente después de descodificar emojis. No afirmar compatibilidad con exportaciones de otra app ni sólo por generar y abrir un fixture propio.
