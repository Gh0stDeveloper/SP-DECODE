# Seguridad, privacidad y calidad — SP-DECODE Android

## Modelo de amenazas

**Activos:** originales importados, perfiles descifrados, servidores/contraseñas/tokens, historial, configuraciones, claves de algoritmo, clave de firma y clipboard. **Escenarios:** archivo corrupto/hostil causa OOM o DoS; proveedor SAF desconecta; intent externo malicioso; logs con secretos; backup no cifrado; extracción de APK; fuga por clipboard/compartir; librería agrega INTERNET; mensajes «Error» impresos como si fueran éxito.

**Fuera de garantía:** protección absoluta contra teléfono root/comprometido, observación física, apps externas que reciben datos compartidos y ocultar secretos estáticos compilados contra ingeniería inversa.

## Seguridad obligatoria (P0)

1. Sin permiso INTERNET ni ACCESS_NETWORK_STATE, analytics, anuncios o requests remotos. Comprobar manifest combinado y tests modo avión; nada de fallback al bot/VPS.
2. SAF ContentResolver sin rutas reales asumidas, sin permisos globales de almacenamiento. Limitar tamaño real leyendo streams, no confiar en metadata del proveedor.
3. Nombre saneado, sufijos por longitud, no shell, no ejecución de scripts ajenos, no evaluación dinámica de configuración.
4. Límites de entrada/salida, ratio descompresión, profundidad JSON, duración y trabajos paralelos; limpieza cache en finally; interrupción segura.
5. Room: cifrar payload descifrado por registro con AES-GCM y Android Keystore; metadata mínima. No indexar secretos en claro. Tests DB migration/corrupción.
6. Desactivar backup del historial o reglas estrictas para backup y transferencia de dispositivo; verificar en dispositivos reales.
7. Ocultar contraseñas por defecto. Confirmación al copiar/compartir/exportar secretos; versión censurada por defecto. Si rawText puede contener secretos no estructurados, avisar que su redacción no es garantizada.
8. Logs/crash locales con solo códigos y duración, nunca valores/bytes originales. No crash reporting remoto.
9. Portapapeles puede ser leído o conservarse fuera de la app; advertir de ese límite. Ocultar revelación al volver del background.
10. Claves criptográficas hardcodeadas de formatos públicos **no son secretos almacenables**: APK y repositorio se pueden analizar. No introducir credenciales personales de servicios.

## Localización y seguridad de la salida

Los recursos es/en/pt-BR/ar solo traducen UI, estados y accesibilidad. **No traducir, normalizar ni modificar `rawText`, etiquetas/claves originales o datos de archivos decodificados** al cambiar idioma o visualizar RTL. La presentación árabe debe aislar el texto técnico LTR sin alterar la cadena almacenada ni exportada. Las máscaras/redacciones de secretos son una operación de privacidad distinta, con confirmación, y nunca reemplazan la copia inalterada de salida original. Ver [LOCALIZATION.md](LOCALIZATION.md).

## Validación de resultado

- DecoderResult.success no se infiere de stdout no vacío ni returncode 0. Los legacy pueden imprimir errores por stdout. Validar estructura, campos esperados, errores, límites y paridad.
- Nombres de campos con flags public/sensitive/secret. Al renderizar nested JSON y raw text, aplicar política conservadora.
- Status: registered / porting / experimental / verified / disabled, separado del éxito/error de archivo individual.

## Matriz de pruebas exigida

| Suite | Casos |
|---|---|
| Kotlin unit | reconocimiento extensiones (incluyendo .sksrv.png, .fɴ, mayúsculas), normalización, status, redacción |
| Python unit | AES/ChaCha20/Base64, perfiles buenos/corruptos, fixtures sintéticos |
| Golden parity | misma muestra en script Linux existente y adapter Android; comparar bytes/campos |
| Contract | DecodeRequest/Result, timeout, fallo dependency, cancelación, warnings |
| Android intent/SAF | Content URI local, permiso revocado, MIME genérico, VIEW/SEND/MULTIPLE, duplicados |
| UI + i18n | 4 locales es/en/pt-BR/ar con recursos completos, LTR/RTL golden, 320/360/393dp, font 200%, TalkBack, selector sistema/manual offline y cadenas técnicas sin cambios |
| Storage | historial cifrado, migración, retención, reabrir sin URI fuente, limpiar datos |
| Security | logcat con sentinelas, no INTERNET manifest, red con modo avión, backup, corruptos/zip bombs |
| Compatibility | arm64 físico y x86_64 emulador, minSdk previsto 24, dispositivos 16 KB cuando correspondan |
| Build/release | reproducibilidad razonable, firma, checksum, SBOM/licencias, revalidación bot |

**Fixtures:** solo configuraciones sintéticas/autorizadas sin credenciales reales; guardar hash, formato, versión, script y salida esperada, OS/ABI, resultado CI y fecha. La bandera verified requiere caso positivo, negativo, paridad y ejecución Android.

## Umbrales iniciales y medición

Límite global preliminar 16 MiB/archivo, 8 MiB de texto de salida y timeout por decoder (calibrar por benchmarks). No son garantías definitivas: A.2 y C.4 deben medir perfiles grandes y ajustar. Ningún trabajo pesado en el main thread. Pantallas de error no revelan trazas sin censura.

## CI y entrega

Mantener .github/workflows/validate.yml actual (bot). Agregar Android lint/unit, pruebas instrumentadas, ABI smoke, golden decoder, scan seguridad/manifest, verificación de licencias, build debug/release. Release firmado con claves de GitHub Secrets, nunca almacenadas en Git ni impresas. Si falta prueba hardware necesaria, estado «pendiente», no «success».

**Gates para publicar:** 0 requests de red; 0 permisos de red; 0 secretos centinela en logs; 0 crashes corpus corrupto; 100% pruebas verdes para cada formato anunciado verificado; capturas UI revisadas; APK firmada instalable desde cero sin Termux/Node/PHP externos; changelog que indique claramente estados y límites.

## Referencias

- Android permissions/SAF: https://developer.android.com/guide/topics/providers/document-provider
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- Chaquopy: https://chaquo.com/chaquopy/doc/current/android.html

