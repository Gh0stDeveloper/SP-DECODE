# Registro de decisiones arquitectónicas (ADR)

**Fecha:** 2026-10-08. «Firme» = alcance aceptado por usuario; «condicional» = se decide con spike real.

| ADR | Decisión | Estado | Justificación |
|---|---|---|---|
| 001 | 100% offline, sin login, sin Telegram, sin servidor | Firme | producto independiente |
| 002 | Kotlin + Jetpack Compose | Firme | UI nativa premium |
| 003 | Android en subdirectorio android/ del monorepo | Firme | conservar bot y compartir registro |
| 004 | Registro Android generado desde decoders.json | Firme | evitar divergencias de extensiones |
| 005 | Motor por adapters y salida tipada | Firme | UI desacoplada |
| 006 | Chaquopy como primer prototipo Python | Condicional | validar ruedas arm64 / 16 KB y límites |
| 007 | Port JS/PHP a Kotlin/Python | Preferido | evitar 3 runtimes externos |
| 008 | SAF / ACTION_VIEW / SEND | Firme | acceso granular sin storage total |
| 009 | Room + cifrado payload vía Keystore AES-GCM | Firme | historial privado |
| 010 | Tema AMOLED / light, estilo iOS-like sin abandonar Android | Firme | fidelidad visual aprobada |
| 011 | Bottom nav 4 destinos: Inicio, Historial, Formatos, Ajustes | Firme | navegación compacta |
| 012 | Estado por formato con fixtures | Firme | 59 registros != 59 probados |
| 013 | CI/firmado/release gates estrictos | Firme | seguridad de usuarios |
| 014 | minSdk 24 / arm64-v8a inicial | Condicional | restricción actual Chaquopy, pendiente validar |
| 015 | Español/inglés y strings externas | Firme | internacionalización |
| 016 | No ejecutar scripts descargados de internet | Firme | privacidad y seguridad |
| 017 | SVG + DESIGN_SYSTEM son fuente visual obligatoria | Firme | continuidad entre chats |

**Modificación:** PR con análisis impacto, evidencia, actualización de docs+SVG+estado y decisión explícita de dueño de producto. Alternativas a investigar si falla Chaquopy: porte nativo de primitivas y funciones, nunca backend online. No confiar en ofuscación APK para ocultar claves embebidas.

