# HTTP Injector 6.5.0: cloud — investigación pendiente

Fecha: 2026-10-11. **No hay un decodificador cloud certificado ni una muestra cloud real en esta investigación.** No confundir `decoders/Python/cloudy.py` de otra aplicación con el formato cloud de HTTP Injector.

La APK `com.evozi.injector` 6.5.0/244 está protegida por SecNeo y Fort/JniLib. Se recuperaron bibliotecas ELF y metadatos parciales; los métodos virtualizados y las cadenas con constantes `long` aún no están completamente resueltos. Ver `HTTP_INJECTOR_650_METODO.md` para hashes y extracción reproducible.

Anclas recuperadas del modelo Java:

- `com/evozi/injector/model/ExportConfig`: `configKey`, `configKeyUrl`, `message`, `resultMsg`, `status`.
- `com/evozi/injector/model/ImportConfig`: `status`, `message`, `achilles`, `configData`.
- Constantes visibles: `config_key`, `config_key_url`, `config_data`, `configKey`, `configKeyUrl`.
- `ConfigActivity` y `ConfigImportActivity` contienen la ruta de exportar/importar y callbacks Retrofit; parte de la lógica llama a `com/fort/andjni/JniLib`.

Los getters del modelo son comprobables. **No se ha confirmado el esquema URI, dominio, endpoint, verbo HTTP, parámetros, derivación de claves ni la representación de `configData` de una respuesta real.** Tener un nombre de campo no demuestra que sea Base64 del archivo EHI. Tampoco demuestra que el enlace incluya todo el ciphertext: puede ser una referencia a servidor.

Para continuar: recibir un enlace cloud exportado desde la APK y, si existe, la respuesta original guardada; registrar bytes, SHA, fecha y códigos HTTP sin publicar secretos. Rastrear el callback `ImportConfig` hasta `configData`/`achilles`, distinguir envoltorio de transporte de contenedor criptográfico y verificar el JSON resultante contra un valor conocido de la configuración. Sólo después crear `decoders/Python/HTTPINJECTOR_CLOUD.py` separado. Debe conservar fallos de red/expiración como errores, no como supuestas contraseñas incorrectas, y usar `decode_ehi` únicamente si se demuestra que el payload es un EHI real.
