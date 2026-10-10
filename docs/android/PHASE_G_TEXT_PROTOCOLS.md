# SP-DECODE Android — Fase G: descifrado de textos y protocolos

**Rama:** `feat/android-phase-g-text-protocols`  
**Destino:** `feat/android-decoder-parity-239`, nunca `main` durante el desarrollo.

## Alcance y precedencia

El catálogo **de archivos** de las fases A–F permanece en 239/239 motores. La fase G añade un **catálogo independiente de textos**. Se coteja con:

- `spdecode/handlers/text_protocols.py`: TLS, SSC y Dark (portados previamente), VMess, NetMod, ARMod, XrayPB, Howdy/N7pr, ZIVPN, V2Box locked URL, /decssh y RENZ.
- `spdecode/handlers/extra_text_protocols.py`: ampliaciones NetMod/ARMod/Howdy, FlexNet, NPVS y VPVS, V2Box export, Kivu, SlipNet Base64, VMess y Creeb.
- `spdecode/handlers/config_batch_texts.py`: HAPP RSA, XOR, Falcon Tunnel, NPVT/dns/npvs1, SlipNet cifrado, WyrLite/WyrVPN/IntVPN, JuanScript, EUT, HTTP Tweak, IZPH.
- `decoders/Python/renz.py` y `decoders/Python/text_legacy_protocols.py`/`text_structured_protocols.py` como referencias independientes de algoritmo y representación.

La nueva ruta `TextPhaseGPort.kt` diferencia fuentes por protocolo antes de llamar al motor original. Compartir un motor criptográfico no convierte los formatos en iguales: `slipnet://` es texto Base64 plano, `slipnet-enc://` es AES-GCM, `npvs1:` es un esquema legado de valor y `npvs://`/ `vpvs://` son contenedores NPVS v5 autenticados.

## Sublotes

| Lote | Protocolo y motor | Comportamiento |
|---|---|---|
| G.1 | NetMod, ARMod, XrayPB, Howdy/N7pr/Mark, ZIVPN y VMess | Correcciones del motor **de texto**, tres claves fuente de NetMod, PB VMess con Base64 interno, metadata completa de Howdy y nuevas variantes de prefijo |
| G.2 | 23 esquemas RENZ/7NET + 10 XOR | Perfiles y cifrados por esquema, sin redirección a claves de otra familia; JSON con aplicación, protocolo y todos los campos de configuración |
| G.3 | FlexNet (FLXCFG en Base64), NPVS v5, V2Box export, Kivu, Creeb y SlipNet claro | Enlaces estructurados y extracción de perfiles Creeb con original conservado; las operaciones Base64 no se presentan como cifrado |
| G.4 | Falcon, NPVT/dns/npvs1, WyrLite, WyrVPN, IntVPN, JuanScript/Mobi, EUT, IZPH, HTTP Tweak y SlipNet cifrado | Adaptadores por prefijo al motor exacto; no se confunden las representaciones textuales y las extensiones de archivos |

## Limitaciones de seguridad y certificación

- **HAPP RSA:** `happ://crypt[2-4]/` está detectado, pero requiere las claves privadas del usuario que el bot recibe a través de `SPDECODE_HAPP_KEYS_JSON`. La aplicación Android **no incorpora claves RSA privadas ni simula un descifrado**. Se mantiene bloqueado hasta disponer de un flujo local y seguro de importación explícita. Es una limitación de credenciales, no una sustitución por una clave inventada.
- **V2Box export protegido:** si el paquete requiere contraseña de usuario, muestra `passwordRequired` y no extrae contenido sin ella.
- **Multipart SSC y Dark:** el formulario Android continúa consumiendo una entrada ensamblada localmente; las sesiones Telegram no implican comunicación con el bot ni alteran el motor.
- Longitud máxima de texto pegado: 250 000 caracteres, límite de resultado: 1 MiB. El tamaño inferior al máximo histórico de algunos bots previene cargas de memoria y es un límite explícito de la interfaz.
- Todo procesamiento es offline, sin endpoints de descifrado, telemetría de credenciales ni claves obtenidas por red. La certificación con exportaciones reales actuales sigue pendiente de la fase H.

## Pruebas automáticas

`scripts/android_g_text_fixtures.py` genera datos artificiales **cifrados desde Python**, incluyendo 23 alias RENZ, 10 XOR, variantes de motores de lotes y textos Base64/JSON sin cifrar, con resultado de referencia por esquema. `tests/test_android_g_text_parity.py` valida fuente y registro; `PhaseGTextInstrumentedTest.kt` comprueba el mismo resultado íntegro en Android API35, además de entradas inválidas y HAPP no configurado.

```sh
PYTHONPATH=. python -m unittest tests.test_android_g_text_parity -v
PYTHONPATH=. python scripts/android_g_text_fixtures.py --fixtures android/app/src/androidTest/assets/parity/g-text-fixtures.json
cd android && gradle --no-daemon :app:connectedDebugAndroidTest
```

**Cierre:** Python, compilación Gradle y emulador Android API35 completos en SUCCESS; mantener todos los tests A–F. No publicar APK estable ni fusionar `main`. El número 239 indica rutas de archivo nativas, no protocolos de texto certificados.
