# SP-DECODE

Bot modular de Telegram para decodificar configuraciones mediante scripts Python, Node.js y PHP. Esta entrega es acumulativa: conserva los métodos anteriores e integra TLS Tunnel, e-V2Ray, Maya Tunnel, XUI Tunnel, HTTP Injector Lite y la variante Java de SocksIP Tunnel.

## Preparación

Requisitos recomendados:

- Python 3.11 o posterior.
- Node.js 20 o posterior.
- PHP 8.1 o posterior.

Instalación:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
npm ci
cp config.example.json config.json
```

Edita `config.json` y configura el token, los administradores y los grupos permitidos. En servidores también puedes mantener el marcador del ejemplo y proporcionar el token con la variable `SPDECODE_BOT_TOKEN`.

El archivo `config.json` es local, está ignorado por Git y no se incluye en la distribución.

## Validación y pruebas

```bash
python validate_project.py
python -m unittest discover -s tests -v
```

La validación comprueba sintaxis, registro de decodificadores, archivos faltantes, integración TLS/e-V2Ray/Maya/XUI/SocksIP/HTTP Injector Lite, protección de handlers, versiones fijas y ausencia de tokens de Telegram.

## Ejecución

```bash
python main.py
```

El bot autoriza administradores desde cualquier chat y usuarios normales únicamente dentro de los grupos configurados. Los menús informativos permanecen disponibles para que sea posible consultar `/id`, mientras que todo contenido que se descifra pasa por la misma política central.

## Métodos actuales integrados

- NetMod `.nm`.
- Tunnel `.tnl`, incluidos OPL, AES-GCM y OpenTunnel.
- TLS Tunnel `.tls` y enlaces `tls://`.
- e-V2Ray `.v2`.
- Maya Tunnel `.maya`, NoobCrypt AES-256-CBC y campos internos AES-256-GCM.
- XUI Tunnel `.xui`, NoobCrypt AES-256-CBC y campos internos AES-256-GCM.
- HTTP Injector `.ehi`, mediante `HTTPINJECTOR.py`.
- HTTP Injector Lite `.ehil`, versión 5.4.0 y campos internos protegidos, mediante su decodificador independiente `HTTPINJECTORLITE.py`.
- SocksIP Tunnel `.sip`, para exportaciones Base64/AES-ECB con serialización Java.
- Los decodificadores heredados registrados en `decoders.json`.

### Compatibilidad conocida de SocksIP

La variante de serialización Java protegida con AES-ECB está implementada. El APK completo suministrado corresponde a SocksIP 15.14.4 (`com.newtoolsworks.sockstunnel`, versión interna 124). Su código Java y nativo aplica Base64, AES-128-ECB/PKCS#7 y después abre directamente una serialización Java.

Las dos muestras actuales abren correctamente esa primera capa, pero después comienzan con `VER7` y no contienen la cabecera de serialización Java. El APK 15.14.4 suministrado no contiene ninguna implementación de `VER7` y no podría importar esas muestras mediante su flujo de configuración. El decodificador detecta esta incompatibilidad y devuelve un error específico. Para reproducir `VER7` hace falta la variante de SocksIP que sí pueda importar una de las muestras, o un archivo `.sip` nuevo exportado directamente por el APK 15.14.4 recibido.

Para agregar otro formato, incorpora el script dentro de la carpeta del runtime correspondiente y registra su extensión, nombre público y runtime en `decoders.json`.
