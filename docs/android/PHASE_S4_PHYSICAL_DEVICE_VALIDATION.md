# SP-DECODE — S.4.2: evidencia de Android Keystore en teléfonos físicos

## Estado de evidencia

La suite de GitHub Actions del PR #77 certifica un **emulador Android API 35**,
no un teléfono real. Las pruebas instrumentadas incorporadas se pueden ejecutar
en equipos físicos, pero **no se considerarán realizadas** hasta registrar
modelo, fabricante, versión de Android, configuración de bloqueo y resultado
efectivo por equipo. La ejecución y el acta de resultados corresponden al
propietario o a un operador con acceso ADB al equipo real.

**No publicar una APK firmada ni atribuir capacidades hardware-backed a
Android Keystore sin evidencia de ese equipo.**

## Seguridad operativa

1. Nunca desinstalar una SP-DECODE de producción con credenciales personales
   para instalar la variante debug: esto eliminaría los registros privados y
   no permite restaurarlos. Utilizar un teléfono de pruebas o un perfil
   independiente destinado a pruebas, sin datos personales.
2. No ejecutar `pm clear`, `adb uninstall`, `keystore delete` sobre el
   alias de producción ni reiniciar/restablecer el teléfono para simular pérdida
   de claves.
3. Los casos destructivos usan exclusivamente el namespace de pruebas
   `private-credentials-s4-tests/<id>` y el alias
   `spdecode.private-credentials.test.<id>`, habilitados únicamente en builds
   `DEBUG`. El alias de producción `spdecode.private-credentials.v1`
   permanece intacto. Cada prueba ejecuta `clearAll()` solo sobre el
   namespace aislado, también ante errores.
4. La clave del vault se genera con AES-GCM 256 sin
   `setUserAuthenticationRequired(true)`. Bloquear la pantalla normalmente
   no invalida la clave. Cambiar o retirar el bloqueo puede variar por
   dispositivo/ROM; no prometer invalidación ni resistencia al malware
   ejecutado en un equipo comprometido.

## Pruebas automatizadas no destructivas (equipo físico)

**Prerequisitos:** un dispositivo USB con depuración habilitada; Java 17,
Android SDK, Gradle 8.11.1, `adb`; dependencias del repositorio y assets
sintéticos de pruebas generados. SP-DECODE **debug** ya instalada en el
equipo dedicado. No se reemplazará automáticamente ninguna APK de producción.

```bash
adb devices -l
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
cd ..
bash scripts/android_s4_physical_smoke.sh SERIAL_DEL_DISPOSITIVO
```

El script verifica que el dispositivo está autorizado y que la aplicación
instalada admite `run-as` (debuggable), instala **solo** la APK de pruebas y
ejecuta `DevicePrivateCredentialLifecycleInstrumentedTest`. Rechaza
resultados sin `OK (N tests)` y `INSTRUMENTATION_CODE: -1`.

Verifica automáticamente:
- persistencia tras crear una nueva instancia del almacén, cifrado de
  contenido, alias Keystore no exportable y directorio `noBackup`;
- eliminación selectiva: una clave borrada deja de abrirse y otra continúa;
- pérdida simulada **solo del alias de pruebas**, registros antiguos ilegibles
  retenidos, nueva clave que no descifra datos antiguos y borrado individual
  explícito de los registros huérfanos;
- corrupción autenticada AES-GCM: rechazo sin fabricar resultados.

Estas pruebas NO fuerzan un reinicio real, no prueban una restauración real y
no ejecutan la interacción manual de Compose. El éxito no equivale a una
certificación de hardware seguro.

## Pruebas UI manuales en teléfonos (obligatorias)

Usar contraseñas y archivos **sintéticos**; no guardar secretos productivos.

| ID | Prueba | Resultado aceptable |
| --- | --- | --- |
| P1 | Ajustes: crear dos credenciales sintéticas, cerrar y reabrir app | Solo se ven los nombres, ambas siguen presentes |
| P2 | Importar un HCCFG `.hc` sintético protegido; seleccionar credencial correcta | Descifra el contenido completo, sin mostrar ni persistir la contraseña del vault |
| P3 | Seleccionar credencial equivocada | Falla el descifrado, sin otro intento ni historial de éxito falso |
| P4 | Cancelar diálogo de selección | No descifra, no almacena un nuevo resultado y no se reutiliza la clave |
| P5 | Eliminar una credencial desde Ajustes y repetir el intento | Desaparece; no vuelve a seleccionarse; la segunda aún funciona |
| P6 | Importar `.hc` histórico y otros formatos | Resultados idénticos a la ruta previa, sin solicitud de clave privada |
| P7 | Bloquear/desbloquear pantalla y volver a la app | La credencial válida sigue accesible tras desbloquear; no se expone en pantalla de recientes |
| P8 | Reiniciar proceso/aplicación y después el teléfono | El vault sigue funcionando si Android Keystore conserva su alias |
| P9 | Probar archivos HCCFG protegidos con HWID | Se rechazan sin suplantar o generar HWID; caso no soportado de S.4 |
| P10 | Comprobar tras intentos fallidos, rotación y apertura desde otro Intent | No hay autoselección de claves, ni cruces de archivos, ni secretos en logcat |
| P11 | Si la plataforma invalida legítimamente una clave en un equipo de pruebas | El registro pasa a ilegible, permanece hasta borrado expreso; sin recuperación inventada |

Para P2/P3 puede generarse el archivo sintético con
`PYTHONPATH=. python scripts/android_hc_sip_fixture_export.py
--output-dir /ruta/temporal`. Importar
`variant-hc-hccfg-password.hc` y registrar la clave de prueba del generador
`S4_SYNTHETIC_PASSWORD`. No subir a GitHub datos privados ni capturas con
resultados sensibles.

**P11 no autoriza borrar credenciales reales ni modificar el sistema**:
el test automatizado recrea la condición usando un alias independiente.

## Matriz de aceptación

Probar, si se dispone de ellos, al menos dos fabricantes y distintas versiones
de Android (idealmente un equipo anterior a API 35 y otro API 35/36).
En todos registrar:

| Campo | Evidencia requerida |
| --- | --- |
| Modelo / fabricante / Android / API | Especificar valores reales |
| Bloqueo (PIN/biometría/ninguno) | Configuración real, sin publicar PIN |
| Hardware-backed / StrongBox | Solo cuando `KeyInfo` o `dumpsys` lo certifique; opcional |
| Instrumentación S.4.2 | PASS/FAIL y fecha + salida sin secretos |
| P1-P11 | PASS/FAIL/NO APLICABLE con incidencia reproducible |
| Compilación / SHA APK | Identificador de binario instalado |
| Responsable | Persona que ejecutó físicamente las pruebas |

**Estado inicial: PENDIENTE DE EJECUCIÓN EN EQUIPO FÍSICO.**
Una ejecución satisfactoria del emulador no puede marcar esta matriz como PASS.

## Cierre de S.4.2

En CI exigir `validate`, `assembleDebug`, `assembleRelease` con R8,
auditorías S.1-S.4 y la instrumentación API35 en SUCCESS. La fusión al
repositorio puede hacerse tras superar CI; la **aceptación en dispositivos
físicos** permanece explícitamente pendiente hasta aportar los registros de
P1-P11. La publicación de una nueva APK de producción es independiente y
requiere autorización posterior.
