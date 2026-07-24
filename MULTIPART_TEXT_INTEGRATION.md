# Integración de cadenas multipart

SP-DECODE puede procesar cadenas de texto de **SSC Custom** y **Dark Tunnel** tanto si llegan completas como si Telegram o el usuario las divide en varios mensajes.

## Regla de funcionamiento

No existe una cantidad fija de fragmentos.

1. El primer mensaje abre una sesión para el usuario dentro del chat.
2. El bot intenta descifrar inmediatamente.
3. Si el resultado aún no es válido, conserva la sesión.
4. Cada nuevo fragmento se agrega en orden de `message_id` y vuelve a intentarse el descifrado.
5. Cuando el decodificador devuelve un resultado válido, la sesión se elimina automáticamente.

Por lo tanto, el mismo flujo funciona para 1, 2, 3 o más mensajes.

## Aislamiento

Solo puede existir una sesión multipart activa por combinación `chat_id + user_id`. Iniciar una nueva cadena reemplaza la anterior para evitar mezclar fragmentos de protocolos distintos.

## Decodificadores reutilizados

Los algoritmos criptográficos no se duplican:

- SSC usa `SSCCUSTOM.run(...)`.
- Dark Tunnel usa `DARKTUNNEL.run(...)`.

Los archivos `decoders/Python/SSCCUSTOM.py` y `decoders/Python/DARKTUNNEL.py` no necesitan modificaciones para procesar texto.

## Dark Tunnel

El detector reconoce esquemas cuyo nombre contiene `dark`, además de `dtunnel://` y `dt://`, por ejemplo:

- `dark://...`
- `darktunnel://...`
- `mydarkconfig://...`
- `dtunnel://...`

El contenido restante debe ser compatible con el formato que ya procesa `decoders/Python/DARKTUNNEL.py`.
