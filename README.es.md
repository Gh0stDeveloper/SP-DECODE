<div align="center">

# SP-DECODE

**Decodificador Android sin conexión · Bot modular de Telegram**

[APK estable](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.4) · [Vista previa firmada](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.5-rc.1) · [README completo (EN)](README.md) · [Canal Telegram](https://t.me/GhostDeve)

</div>

> [!WARNING]
> **Compatibilidad por versiones:** SP-DECODE registra 60 extensiones, pero las pruebas sintéticas no garantizan todas las variantes exportadas por aplicaciones reales. Hay formatos que todavía necesitan muestras y regresiones. Nunca publiques credenciales, configuraciones privadas ni servidores reales en un issue público.

## Dos componentes independientes

| Componente | Qué hace | Requisitos |
|---|---|---|
| **Aplicación Android** | Importa archivos, decodifica textos compatibles, muestra todos los campos y permite copiar y exportar resultados localmente | Android 7.0+, sin conexión, cuenta ni servidor |
| **Bot de Telegram** | Recibe archivos y enlaces y usa scripts originales de Python, JavaScript/Node.js y PHP en tu propia instalación | VPS o Termux, Internet y token de BotFather |

## Descargar la aplicación Android

- **v1.0.4 estable:** [descarga en GitHub Releases](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.4). Publicación autorizada por el propietario; no certifica cada variante real.
- **v1.0.5-rc.1 de prueba:** [APK de producción firmada](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.5-rc.1). Mejora Dark Tunnel y protocolos `nm-ssh://` y `ar-ssh://`. Sigue en **NO-GO estable** hasta completar comparaciones de archivos reales.

Ambas publicaciones incluyen `SHA256SUMS.txt` y `SIGNATURE_VERIFICATION.txt`. No se emplea una firma temporal para el artefacto publicado.

La APK integra interfaz AMOLED, historial local, importación por lotes, resultados ordenados con datos anidados y traducciones de la **interfaz** a español, inglés, portugués brasileño y árabe (RTL). Los valores decodificados no se traducen.

Consulta la [guía técnica de Android](docs/android/README.md), [estado de compatibilidad](docs/android/REAL_DECODER_PARITY_TRIAGE.md) y [notas de publicación](docs/android/RELEASE_RUNBOOK.md).

## Instalar el bot de Telegram

Los instaladores automatizan las dependencias y la configuración del token y grupos.

**Termux:**
~~~bash
git clone https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
bash installers/install-termux.sh
~~~

**Linux VPS:**
~~~bash
git clone https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
bash installers/install-vps.sh
~~~

Requisitos manuales: Python 3.11+, Node.js 20+, PHP 8.1+. El token se guarda en `config.json` local o se proporciona mediante `SPDECODE_BOT_TOKEN`. Para instalación detallada, comandos, protocolos y la lista de formatos, consulta [README.md](README.md).

## Colaboración, seguridad y contacto

Reporta errores indicando versión de SP-DECODE, plataforma, extensión/protocolo, aplicación exportadora y pasos reproducibles, **siempre con datos anonimizados**. Sigue [CONTRIBUTING.md](CONTRIBUTING.md) y [SECURITY.md](SECURITY.md).

- [Desarrollador: Ghost Developer](https://github.com/Gh0stDeveloper)
- [Telegram personal: @Gh0stDeveloper](https://t.me/Gh0stDeveloper)
- [Canal: @GhostDeve](https://t.me/GhostDeve)
- [Comunidad: @CodeBreakersHub](https://t.me/CodeBreakersHub)

**Licencia:** actualmente no hay una licencia general publicada. La visibilidad del código no implica permiso de redistribución.
