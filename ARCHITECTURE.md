# Arquitectura modular de SP-DECODE

## Inicio

`main.py` solo valida el proyecto, registra los handlers mediante imports y mantiene el polling de Telegram.

## Configuración

- `config.json`: token, administradores, grupos permitidos y límites de ejecución.
- `decoders.json`: relación entre extensión, script y runtime.

## Paquete `spdecode/`

- `config.py`: carga y validación de configuración.
- `runtime.py`: instancia compartida del bot y configuración cargada.
- `access.py`: autorización de administradores y grupos.
- `registry.py`: carga y validación de `decoders.json`.
- `executor.py`: ejecución segura de Python, Node.js o PHP conservando la raíz del proyecto como directorio de trabajo.
- `utils.py`: utilidades de nombres de archivo y división de respuestas.
- `handlers/commands.py`: comandos y callbacks generales.
- `handlers/text_protocols.py`: decodificadores de protocolos enviados como texto.
- `handlers/documents.py`: recepción y ejecución de archivos.
- `handlers/fallback.py`: decodificador de texto genérico, registrado al final.

## Añadir un nuevo decodificador de archivo

1. Coloca el script en la raíz del proyecto o en una subcarpeta relativa.
2. Añade una entrada en `decoders.json`:

```json
"mi_extension": {
    "script": "mi_decoder.py",
    "runtime": "python"
}
```

Los runtimes admitidos son `python`, `node` y `php`. No es necesario modificar `main.py`.

## Compatibilidad con scripts antiguos

El ejecutor usa siempre la raíz de SP-DECODE como `cwd`, por lo que rutas relativas antiguas como `cfg/keyFile.json` o `modules/...` siguen resolviéndose igual que antes. Los decodificadores existentes no fueron movidos ni reescritos.

## Validación

Ejecuta:

```bash
python validate_project.py
```

Esto comprueba la sintaxis de los archivos Python y que todos los scripts registrados existan.

## Decodificadores Python recientes

Los decodificadores Python recientes en mayúsculas conservan `run(file_bytes)` para integración programática y además implementan una entrada CLI independiente. El bot los ejecuta como proceso externo con un argumento de archivo, equivalente a:

```bash
python decoders/Python/DARKTUNNEL.py "archivo.dark"
python decoders/Python/HTTPCUSTOM.py "archivo.hc"
python decoders/Python/HTTPINJECTOR.py "archivo.ehi"
python decoders/Python/NPVTUNNEL.py "archivo.npv4"
python decoders/Python/SSCCUSTOM.py "archivo.ssc"
```

`subprocess` recibe cada argumento por separado, por lo que nombres y rutas con espacios se transmiten correctamente sin usar `shell=True`.

## SSC Custom por texto

El procesamiento multipart de `ssc://` y Dark Tunnel vive en `spdecode/handlers/text_protocols.py` y reutiliza directamente `SSCCUSTOM.run` y `DARKTUNNEL.run` sin duplicar sus algoritmos. Las cadenas divididas se almacenan mediante `spdecode/text_sessions.py`, aisladas por usuario y chat, y se reconstruyen por `message_id`. La cantidad de partes es dinámica: se intenta descifrar después de cada fragmento hasta obtener un resultado válido.

Consulta `SSC_TEXT_INTEGRATION.md` para el flujo completo y los parámetros configurables.

## Organización de decodificadores por lenguaje

- `decoders/Python/`: decodificadores Python.
- `decoders/JavaScript/`: decodificadores Node.js/JavaScript.
- `decoders/PHP/`: decodificadores PHP.

`decoders.json` conserva las rutas internas y el nombre público de cada aplicación. El comando `/formats` solo muestra el nombre de la aplicación y la extensión; nunca expone el archivo del decodificador ni el runtime.
