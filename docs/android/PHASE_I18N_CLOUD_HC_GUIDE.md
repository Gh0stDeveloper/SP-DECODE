# SP-DECODE Android — Nuevos idiomas y guía de ayuda

## Alcance

Esta rama agrega traducciones y contenido educativo **sin modificar** motores de descifrado, protocolos, enrutadores, autenticación, bot Python, formatos de archivo, API ni permisos. Tampoco publica una nueva versión de producción.

### Idiomas

Se conservan inglés, español, portugués de Brasil y árabe. Se agregan:

| Idioma | Selector | Recursos Android |
| --- | --- | --- |
| Persa (RTL) | `fa` — فارسی | `values-fa` |
| Francés | `fr` — Français | `values-fr` |
| Indonesio | `id` — Bahasa Indonesia | `values-in` (alias histórico de idioma Android) |
| Ruso | `ru` — Русский | `values-ru` |
| Alemán (adicional) | `de` — Deutsch | `values-de` |

Los **nueve idiomas** contienen todas las **201 cadenas** de la aplicación, incluidas importación, resultados, JSON, historial, privacidad, contraseñas locales, mensajes NPVS, Cloud y HTTP Custom. Se respetan los parámetros Android `%1$s`, `%1$d`, `%2$d`. El idioma elegido continúa guardándose con la lógica de preferencias ya existente; persa y árabe usan disposición RTL.

### Guía integrada (cinco a siete pasos)

La guía conserva el componente central y la posibilidad de repetirla desde Ajustes. Los pasos existentes no se suprimen:

1. Inicio: importar archivos.
2. Textos codificados locales.
3. Historial cifrado.
4. Formatos disponibles.
5. Ajustes y privacidad.
6. **HTTP Injector Cloud:** opción independiente de Textos. Abrir Nube en Inicio, pegar URL `ehi.link`, clave o secuencia de emojis `💉…🚀`, pulsar Importar; necesita Internet y la referencia se envía a HTTP Injector **solo tras la pulsación explícita**. Los descifradores de archivos y textos locales no se conectan.
7. **HTTP Custom (.hc) protegido:** importar como siempre. La aplicación solicita contraseña de exportación, HWID de 32 caracteres o ambos cuando el HCCFG lo requiera. No confundir HWID del archivo con un ID obtenido automáticamente del teléfono. Credenciales erróneas o archivo alterado impiden el descifrado, los archivos .hc ordinarios mantienen el descifrador previo.

Se resaltan visualmente los controles **Nube** e **Importar** que ya existían durante los pasos correspondientes; no cambia el diseño, las acciones de red ni los motores.

### Comprobaciones

- Comparación de los 201 nombres de recursos en los nueve idiomas.
- Verificación de parámetros de formato `%1$d` / `%1$s` / `%2$d` y ausencia de duplicados.
- Pruebas Android instrumentadas sobre la guía de siete pasos, selector de idiomas, localización visible, layout RTL persa, y recursos de Cloud / HC.
- Validación y compilación mediante GitHub Actions del PR; no se modifica el pipeline ni la publicación.

## Limitaciones

Las traducciones deben revisarse editorialmente con hablantes nativos antes de asumir equivalencia terminológica absoluta. La guía documenta el comportamiento de Cloud y HCCFG que ya existía; no añade nuevas capacidades ni compatibilidad con más formatos.
