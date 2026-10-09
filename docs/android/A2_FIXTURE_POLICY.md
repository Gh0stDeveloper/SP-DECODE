# Fase A.2 — Política de muestras y pruebas golden

## Principio de seguridad

Todos los archivos y resultados usados para validar descifradores deben ser **sintéticos** o estar **explícitamente autorizados** para el proyecto. No subir a GitHub configuraciones que pertenezcan a terceros, credenciales SSH/HTTP reales, claves personales, tokens, contraseñas o servidores privados. La mera posesión de un archivo no demuestra autorización para publicarlo.

Si no existe una muestra segura de un formato, se marca **fixture_missing** y el formato continúa **not_verified**. No inventar datos para simular una prueba aprobada.

## Niveles de evidencia (separados)

| Nivel | Descripción | Permite declarar |
|---|---|---|
| L0 | Existe una entrada decoders.json y ruta de script | registrado |
| L1 | Fuente parseada y auditada estáticamente, dependencias/recursos inventariados | auditado estático |
| L2 | Fixture autorizado + referencia bot Linux real, incluyendo casos negativos y versionado del formato | referencia golden Linux |
| L3 | Bridge Android local produce paridad exacta de contenido/orden respecto al golden; sin red | experimental/paridad según casos |
| L4 | Suite arm64 física y emulador, múltiples versiones de formato, estrés, errores y CI | verificado Android para versiones cubiertas |

Los cuatro idiomas de la **interfaz** (es, en, pt-BR, ar) no modifican el contenido. Comparar hash byte a byte del \`rawText\` exportado en los cuatro locales; en UI árabe, la dirección LTR es solo presentación y no se inserta Unicode extra en datos.

## Catálogo de golden fixtures — estructura propuesta

La carpeta futura \`android/test-fixtures\` (no creada todavía) alojará exclusivamente muestras autorizadas con nombres estables y documentación de procedencia. Los samples pueden ser construidos localmente durante test (como TLS y EV2RAY en \`tests/test_current_decoders.py\`) sin necesidad de subir archivos que contengan secretos reales.

Cada registro de \`manifest.json\` deberá incorporar:

| Campo | Tipo | Propósito |
|---|---|---|
| fixtureId | string | identificador estable no personal |
| suffix | string | extensión verificada (.tls, .htb, etc.) |
| decoderScript | path | script de referencia del registro |
| exporterAppName / exporterVersion | string | versión exacta de app generadora si se conoce |
| sourceKind | synthetic / authorized | base legal/técnica de uso |
| sanitized | boolean | no hay secretos reales |
| inputPath o generator | path o función | origen reproducible |
| sha256 | sha256 | integridad de bytes de entrada |
| expectedStatus | success / invalid_input / unsupported | distinguir éxito de error |
| expectedRawUtf8Sha256 | sha256 si aplica | comparación exacta del resultado crudo |
| expectedStructuredFields | objeto si aplica | datos con el orden correcto |
| referenceRuntime / referenceCommit | string | entorno y commit Linux del golden |
| androidTestEvidence | entradas versionadas | SDK, ABI, hardware, job, fecha |
| knownLimitations | lista | versiones no soportadas/variantes |

**Nota:** No se debe guardar un expected output secreto real en GitHub. Si el fixture autorizado necesita una contraseña, usar un valor sintético sin poder de autenticación (ej. \`dummy-secret\`) y justificarlo.

## Conjunto mínimo por sufijo

1. **Caso positivo**: un archivo con éxito sustantivo y salida esperada exacta.
2. **Caso negativo corrupto**: archivo truncado, cabecera inválida, padding incorrecto o tag AEAD modificado según el algoritmo.
3. **Versión divergente**: formato más nuevo o incompatible, con error explícito, nunca salida inventada.
4. **Edge**: UTF-8/Unicode, filename con espacios, sufijo compuesto y tamaño máximo sensato.
5. **Paridad Linux/Android**: payload original, renderizado de campos/orden, error semántico, exportación raw.
6. **Privacidad**: no clave sensible en logcat, JSON redacción explícita y sin Internet en el paquete.

Un mismo script usado por varios sufijos requiere al menos pruebas de detección/importación por **cada sufijo**, aunque se reutilice golden del algoritmo si ambos inputs son realmente idénticos.

## Fixtures ya presentes (pruebas unitarias del bot)

- \`tests/test_current_decoders.py::CurrentDecoderTests.test_tls_current_aes_gcm_container\` fabrica un perfil TLS con datos sintéticos y comprueba campos específicos en salida.
- \`tests/test_current_decoders.py::CurrentDecoderTests.test_ev2ray_current_profile_layers\` fabrica un perfil e-V2Ray simple y comprueba parte de la salida.
- **Limitación:** esos dos tests usan aserciones parciales (\`assertIn\`), no comparan el \`rawText\` completo ni corren en Android; no elevan un sufijo a \`verified\`.

## Plan de adquisición de fixtures que falta

| Orden | Sufijos | Necesidad |
|---|---|---|
| 1 | .tls, .v2 | extender dos fixtures existentes a goldens exactos; casos de fallo |
| 2 | .ehi, .ehil, .hc | nuevos contenedores, versiones y wheels nativos |
| 3 | .ht, .htb, .npv4, .npvt | alias y variantes, blobs/transformaciones |
| 4 | .ssc, .dark | multipart, msgpack y entrada texto vs archivo |
| 5 | .hat, .rez, .rezl, .tvt, .sks | port Node con vectores criptográficos |
| 6 | .sksplus, .jez, .hrt | PHP/OpenSSL y padding |
| 7 | todos los restantes | fixtures positivos/negativos por sufijo y versión |

Este orden es prioridad técnica, no promesa de soporte. Cada muestra debe tener evidencia de origen y versión antes de pasar a D/E.

## Implementación actual del corpus (A.2.3)

Ya existe el corpus **reproducible en memoria y exportable** en `tests/golden`, con [documentación detallada](A23_GOLDEN_CORPUS.md). Cuenta con **60 casos sintéticos completos para 59/59 sufijos** (TLS, e-V2Ray dos variantes, HTTP Injector Lite, SSC Custom, Dark Tunnel, HTTP Tweak .ht/.htb y HTTP Custom), manifest para los 59 sufijos, entradas negativas, SHA-256 congelados y pruebas exactas de salida Linux/CLI. El último sufijo `.ssh` dispone ya de un fixture ficticio Blowfish-CBC y salida golden determinista solo en modo de prueba. **Esta cobertura no representa compatibilidad de exportadores ni Android.** Para exportar inputs físicos de prueba: `PYTHONPATH=. python tests/golden/a23_export.py --output-dir out/a23/samples`.

Esto **no representa cinco formatos certificados Android**: sigue `androidVerifiedSuffixes=0`. No hay demostración de compatibilidad con versiones actuales de apps emisoras.

## Criterios para cerrar el análisis A.2

- [x] 59/59 registros revisados y asociados a 48/48 rutas existentes.
- [x] Escáner estático para 48 scripts con outputs automatizados y revisión de hallazgos críticos.
- [x] Política de muestras, matriz y baseline de riesgos.
- [ ] Fixtures positivos/negativos autorizados para los formatos aún no cubiertos.
- [ ] Auditoría de los adaptadores y dependencia transitiva por formato con muestras reales/sintéticas.
- [ ] Portabilidad API/ABI confirmada para candidatos (C.4), sin declarar Android verified prematuramente.

No bloquear el inicio de B.1 por ausencia de todos los fixtures: se pueden ejecutar en paralelo B.1 y A.2.3; sí bloquear «compatibilidad total» y release mientras falten los gates.
