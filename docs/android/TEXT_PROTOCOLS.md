# SP-DECODE Android — Protocolos de texto (0.3.7-alpha)

**Fuentes originales:** `spdecode/handlers/text_protocols.py`,
`spdecode/handlers/fallback.py`,
`MULTIPART_TEXT_INTEGRATION.md` y `SSC_TEXT_INTEGRATION.md`.

## Alcance de este parche

La pestaña Inicio ofrece **Decodificar texto** debajo de la importación
de archivos. Pegar un enlace conocido y tocar **Decodificar texto** ejecuta
exclusivamente lógica local; no se utilizan Telegram, Internet, Python,
Node.js, PHP ni servicios externos.

Rutas de texto:

| Entrada | Decodificador Android | Estado de este parche |
|---|---|---|
| `tls://` | `TlsReferencePort` existente | Integrado |
| `ssc://` | `SscPort` existente | Integrado; partes sucesivas |
| `dark://`, `darktunnel://`, `dtunnel://`, `dt://`, nombres con `dark` | `DarkPort` existente | Integrado; partes sucesivas |
| `vmess://` | Base64 + JSON del bot | Integrado |
| `nm-dns/ssr/vmess/vless/trojan/ssh/xray-json://` | AES-ECB NetMod del bot | Integrado |
| Cadena NetMod Base64 sin prefijo | Fallback NetMod AES-ECB del bot | Integrado; solo JSON válido |
| `ar-dns/vless/vmess/trojan/ssr/socks/trojan-go/ssh://` | AES-ECB + parámetros URL + perfil JSON | Integrado |
| `pb-ssh/vless/vmess/trojan/socks/ss://` | AES-CBC XrayPB del bot | Integrado |
| `howdy://` y `N7pr://` | Base64 + AES-CBC individual de host/SNI | Integrado |
| `zivpn://` | AES-CBC + etiquetas XML del bot | Integrado |
| `v2box://?locked=...` | Base64 + parámetros de URI | Integrado |
| `/decssh host@user:password` | Transformación histórica del bot | Integrado |

**No confundir rutas textuales con extensiones de archivo**: los puertos
de archivo `.nm`, `.pb`, `.ziv` tienen sus propios contenedores,
distintos de enlaces `nm-`, `pb-` y `zivpn://`.
El motor de cada protocolo textual fue revisado por separado, sin probar
claves de otros formatos.

## Texto multipart

1. Pegar `ssc://<fragmento_hex>` o
   `darktunnel://<fragmento_base64>`; pulsar **Decodificar texto**.
2. Si no se obtiene resultado válido, el fragmento se conserva en una
   sesión temporal y el formulario indica cuántas partes lleva.
3. Pegar la siguiente parte **sin repetir el prefijo** y tocar de nuevo
   Decodificar. Se reintenta al añadir cada fragmento.
4. Pulsar **Descartar partes** para reiniciar o comenzar una cadena nueva
   con otro enlace reconocido.
5. Sesión temporal: máximo 250 000 caracteres, 10 min de inactividad.
   No se persiste en historial ni en Bundle.

## Privacidad y persistencia

- Únicamente **resultados decodificados correctamente** se guardan en
  `SecureDecodeHistory` AES-GCM/Keystore mediante `HistoryRepository`.
- Resultado JSON principal; acciones de copiar/exportar y favoritos existentes.
- Los fragmentos incompletos se conservan solo en memoria, nunca en
  DataStore, Room, `savedInstanceState` o registros de depuración.
- Enlaces no reconocidos, variantes corruptas y descifrados nulos no deben
  producir resultados falsamente positivos.
- Se mantienen los límites, la cancelación y el estado de progreso.
- Los certificados de firma recién configurados por el propietario se
  validarán por el workflow manual, no se consideran verificados solo por
  existir en GitHub Secrets.

## Pruebas para la fase de producción

- CI Linux y Android API 35 (fixtures sintéticos, pruebas negativas y
  estabilidad de las funciones de archivos existentes).
- Pruebas manuales en dispositivo de las variantes reales de **texto**,
  especialmente multipart y cambios de formato de las aplicaciones.
- Ejecutar la firma V1/V2/V3 con `kind=candidate`, no publicarla como
  estable hasta verificar instalación, actualización y seguridad en `main`.

Este registro no certifica por sí solo todas las versiones de cada proveedor;
verificar las entradas reales y documentar cualquier variante incompatible.
