# SSC Custom por texto

La integración SSC ahora forma parte del motor multipart compartido documentado en `MULTIPART_TEXT_INTEGRATION.md`.

La cantidad de mensajes no está fijada: puede ser 1, 2, 3 o más. Después de cada fragmento el bot vuelve a ejecutar `SSCCUSTOM.run(...)`; cuando obtiene un resultado válido, elimina automáticamente la sesión temporal.

La configuración actual utiliza:

```json
{
  "runtime": {
    "text_session_timeout_seconds": 600,
    "text_session_max_chars": 250000
  }
}
```

Los nombres anteriores `ssc_session_timeout_seconds` y `ssc_max_text_chars` siguen siendo aceptados por compatibilidad al leer configuraciones antiguas.
