# Informe de validación manual comunicado por el propietario

**Fecha:** 2026-10-09  
**Origen:** confirmación explícita del propietario/desarrollador de SP-DECODE en el proyecto.

El propietario informó que ha realizado manualmente las siguientes comprobaciones
y que los resultados observados fueron correctos:

- Importación por lotes: resultados de éxito y error correctamente señalados.
- Archivos reales y variantes utilizadas en sus pruebas.
- Funcionamiento en ARM64.
- Compatibilidad con páginas de memoria de 16 KiB según sus verificaciones.
- Auditoría final realizada y aprobada por el propietario.

## Alcance de esta atestación

**Estado de usuario: APROBADO / USER-VERIFIED.**

Este documento es un registro fiel de su declaración, **no es** un log ADB,
identificación de modelos de dispositivos, inventario de versiones de
exportadores, matriz de hashes de archivos ni informe independiente de
seguridad. La confirmación no autoriza inventar modelos, tamaños de página
medidos, versiones de aplicaciones, una cobertura de 59/59 en condiciones
reales o pruebas de actualización de firma.

La decisión de release de producción permanece separada: configurar
GitHub Secrets, firmar un candidato con la clave definitiva y verificar
instalación/actualización con ese mismo certificado y CI de `main` antes
de cambiar `release/android-readiness.json` a `GO`.


## Ampliación de aceptación del propietario — SP-DECODE 1.0.3 (2026-10-09)

El propietario aportó capturas de pruebas manuales en Android y confirmó
expresamente que los archivos reales de **LinkLayer VPN (.lnk) VER6** y
**HTTP Custom (.hc)** se decodifican y que los demás archivos incluidos en
sus pruebas se comportan correctamente. En ambas capturas se observan campos
de configuración en JSON, incluyendo campos anidados y valores reales.
Las capturas aportadas al chat contienen datos de configuración y **no
deben copiarse a este repositorio público** ni a logs de CI.

El propietario también reiteró que, bajo su criterio de QA, las pruebas
de Android, archivos reales, lotes, ARM64 y páginas de 16 KiB están
**aprobadas** y solicitó distribuir una primera versión de producción.
Se registra explícitamente su aceptación y su decisión de distribución.

**Límite de trazabilidad:** la evidencia visible permite constatar que
en su dispositivo se mostraron resultados de los dos formatos; no permite
probar por sí sola un conjunto exhaustivo de exportadores, accesibilidad
en otros modelos, métricas de rendimiento ni una instalación/actualización
firmada observada con ADB. Los checks de CI del SHA exacto de `main` y la
firma permanente tienen evidencia pública independiente a través de
GitHub Actions. No declarar completada una prueba que no está documentada.

## Versión 1.0.4 — modificación única de créditos

Para la siguiente actualización se cambia exclusivamente la atribución
de resultados a **SP-DECODE** y se incluyen los créditos de
**Ghost Developer** y los enlaces oficiales de grupo/canal **solo en la
copia/exportación ordenada**. JSON original, decodificadores y fuentes
de datos permanecen intactos. El propietario acepta la funcionalidad
previa y solicita que este parche se distribuya con la keystore
permanente de producción.
