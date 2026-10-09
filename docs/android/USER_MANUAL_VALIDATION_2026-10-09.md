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
