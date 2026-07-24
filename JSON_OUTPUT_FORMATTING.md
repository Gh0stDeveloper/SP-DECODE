# Formato de salida JSON

El formateo de los cinco decodificadores recientes se realiza dentro de cada script:

- `decoders/Python/DARKTUNNEL.py`
- `decoders/Python/HTTPCUSTOM.py`
- `decoders/Python/HTTPINJECTOR.py`
- `decoders/Python/NPVTUNNEL.py`
- `decoders/Python/SSCCUSTOM.py`

## Regla de formato

Solo se recorren las claves del objeto JSON raíz.

```text
│[۞] key: value
```

Si `value` es otro objeto o una lista JSON, se serializa como un único valor y no se recorre de forma recursiva. No se usa `sort_keys`, por lo que se conserva el orden de inserción disponible.

Si `value` ya es una cadena que contiene JSON, se conserva como cadena y no se vuelve a ejecutar `json.loads` sobre ella. Esto permite copiar configuraciones embebidas directamente.

El bot no vuelve a parsear ni reformatear la salida de estos decodificadores.
