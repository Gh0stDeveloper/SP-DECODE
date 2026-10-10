# SP-DECODE Android — Fase H | Auditoría de salida a producción

**Fecha:** 2026-10-10  
**Versión candidata:** 1.0.6 (versionCode 17).  
**Rama de auditoría:** `feat/android-phase-h-production-audit`.  
**Decisión inicial:** **NO-GO para publicación pública estable y para nueva prerelease**. La autorización del propietario está condicionada a que *todo salga bien*; no sustituye evidencias nuevas faltantes.

## H.1 — Cobertura y paridad de motores

| Grupo | Rutas nativas implementadas | Fuente primaria de prueba |
|---|---:|---|
| Legacy | 61 | Los decodificadores históricos de Python/Node/PHP y suite A.2 |
| B — Genéricos | 81 | Vectores AES/DES de `android_b_generic_profiles.py` |
| C — Ultra/Sandok | 41 | Argon2id + AES-GCM `android_c_ultra_profiles.py` |
| D — RENZ | 16 | `android_d_renz_profiles.py` |
| E — Especiales | 27 | `android_e_special_fixtures.py` |
| F — Independientes | 13 | `android_f_independent_fixtures.py` |
| G — Texto | Catálogo **separado** de enlaces | `android_g_text_fixtures.py` |
| **Total archivos** | **239** | Pruebas Python ↔ Kotlin en API35 |

**239/239 significa rutas implementadas, NO 239/239 exportadores reales certificados.** El catálogo conserva el contador de versiones reales certificadas en cero. Los informes antiguos de usuario para .lnk y .hc son válidos dentro de su alcance original, pero no constituyen ensayos de los 178 motores nuevos ni de sus distintas versiones externas.

## H.2 — Seguridad y privacidad

**Controles automáticos en código y APK de Android:**
- Sin permisos `INTERNET`, `ACCESS_NETWORK_STATE`, almacenamiento total ni `QUERY_ALL_PACKAGES`.
- `android:allowBackup=false`, `android:fullBackupContent=false`, y `android:usesCleartextTraffic=false`.
- Almacén de historial con Android Keystore/AES-GCM; el informe H no inspecciona contraseñas reales.
- Motores de texto y archivo distintos; no probar claves de descifradores ajenos como sustitución. HAPP necesita claves RSA privadas proporcionadas de manera segura por el usuario.
- Límite de bytes y resultados; comportamiento de errores y formato invalido cubierto por pruebas instrumentadas.
- No se añade una keystore ni ningún secreto al repositorio público.

**No equivalen a auditoría externa:** estos controles prueban el código fuente y el paquete instalado en el emulador. La seguridad de proveedores de documentos SAF, el rendimiento en dispositivos físicos, vulnerabilidades de dependencias y los casos extremos de exportadores todavía requieren ensayos complementarios.

## H.3 — Compatibilidad Android y publicación

- Android API 35 x86_64 con tests instrumentados y regresión de fases A–G.
- Versión Android 1.0.6, `versionCode=17` — posterior a la APK pública v1.0.5 `versionCode=16`.
- Nombre de paquete `com.ghostdeveloper.spdecode`, mantenido para futuras actualizaciones.
- Workflow de firma ya configurado para usar **únicamente** `SPDECODE_SIGNING_*` en GitHub Secrets. Firma de producción V1/V2/V3, validación por `apksigner`, `zipalign -P 16`, checksum SHA-256 y asociación a SHA exacto de `main`.
- El workflow de firma se dispara automáticamente **después** de un CI `main` exitoso y genera el APK firmado como artefacto de GitHub Actions.
- La creación de una GitHub Release está protegida **por separado** por `scripts/android_release_gate.py`. Para la 1.0.6 está bloqueada hasta completar el control condicional; no se usará `OWNER-GO` de una versión anterior ni una aprobación de preview de otra versión.

## H.4 — Evidencia real todavía pendiente

1. **Versiones exportadoras auténticas**: para cada variante relevante, muestra consentida y controlada fuera del repositorio público, marca, versión, sufijo, SHA-256, resultado del script original y del motor Android comparados campo por campo. No publicar secretos, endpoints de usuarios ni payloads reales.
2. **Enlaces de texto reales:** contraste con el protocolo original, no con el motor de archivos por parecido de nombre; incluye multipart, fallos de cifrado y esquemas desconocidos.
3. **ARM64 físico:** informe de instalación y descifrado de la APK nueva con modelo y versión Android; no reciclar automáticamente pruebas de 1.0.4/1.0.5.
4. **Página de memoria 16 KiB:** verificación física donde corresponda; la alineación ZIP de CI por sí sola no demuestra el entorno real.
5. **Accesibilidad/rendimiento:** TalkBack, tamaño de fuente 200%, interfaz pequeña, cargas grandes, cancelaciones, estabilidad y consumo de memoria.
6. **Identidad de actualización:** instalación limpia + actualización **desde la APK firmada anterior** y persistencia de historial, sin migración destructiva, con el mismo certificado; V1/V2/V3 validados en APK concreta del nuevo SHA.

Hasta disponer de estas pruebas, **el hecho de que el CI pase no desbloquea una Release estable**. La firma con keystore real se ejecuta como precondición necesaria para las pruebas de actualización, sin que ello implique autorización de distribución pública.

## H.5 — Automatización de auditoría

`scripts/android_h_production_audit.py` produce un JSON **sin secretos** con:
- Catálogo nativo de 239, fuente de cada sufijo y separación de estados experimentales/certificados.
- Permisos offline del manifest fuente y configuración de firma y procedencia del SHA.
- Validación de versión 1.0.6/17 y bloqueo de publicación inesperada.
- Lista de requisitos pendientes para el cierre; `sourceGate=PASS` no implica `productionGate=GO`.

Comandos:
```sh
PYTHONPATH=. python scripts/android_h_production_audit.py --version 1.0.6 --code 17 --report /tmp/spdecode-h/audit.json
PYTHONPATH=. python -m unittest tests.test_android_h_production_audit -v
# Debe fallar mientras no haya evidencia: salida distinta de cero
PYTHONPATH=. python scripts/android_h_production_audit.py --version 1.0.6 --code 17 --require-production
```

## H.6 — Decisión final

Al cerrar H **solo los checks que realmente concluyan en SUCCESS podrán marcarse verificados**. El dueño podrá aprobar una distribución estable posterior cuando el informe de esta versión esté completo; las aprobaciones anteriores son versionadas y no se transfieren. No se inventarán métricas de dispositivos, capturas, firmas ni exportaciones. El APK de prueba firmado permanentemente no debe etiquetarse como una versión estable si la auditoría señala NO-GO.
