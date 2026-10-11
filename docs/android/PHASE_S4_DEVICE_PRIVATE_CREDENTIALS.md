# Fase S.4 — Aprovisionamiento local de credenciales privadas

## Objetivo y alcance

SP-DECODE funciona **100 % sin Internet**. No es posible ocultar una
contraseña universal de descifrado en una APK pública: la clave de apertura
de los recursos `SPV1` se puede recuperar mediante ingeniería inversa y las
claves de compatibilidad de protocolos existentes ya están publicadas en
el repositorio. Ninguna de esas claves debe tratarse como credencial privada
del servicio o del usuario.

La Fase S.4 crea, de forma separada, un almacén **optativo** para secretos
que el propietario introduzca directamente en su teléfono. No se empaquetan
con la APK, no los proporciona CI, no hay servidor de aprovisionamiento ni
permiso `INTERNET`, y no hay cambios silenciosos a motores de descifrado.

## Implementación

- **DevicePrivateCredentialVault** almacena cada credencial con un UUID
  aleatorio en `noBackupFilesDir/private-credentials`. No guarda secretos ni
  etiquetas en Room, SharedPreferences, DataStore, código Kotlin, assets o
  eventos de diagnóstico.
- **Clave no exportable Android Keystore**, algoritmo AES-256-GCM. Se
  configura `setRandomizedEncryptionRequired(true)` y cada nuevo registro
  recibe un nonce independiente de 12 bytes y una etiqueta autenticada.
  La identidad del registro se enlaza mediante AAD
  `spdecode:s4:private-credential:{uuid}`: copiar ciphertext a otro UUID
  no permite recuperarlo bajo esa identidad.
- **Formato binario `S4K1`**: cabecera, nonce, ciphertext autenticado de
  longitud controlada; el texto legible solo existe transitoriamente en
  memoria durante la operación. Escritura atómica con `AtomicFile`.
- **Interfaz Ajustes → Claves privadas de este dispositivo**:
  añadir/nombrar/borrar una credencial. El editor de secretos oculta el texto,
  utiliza un diálogo con `SecureFlagPolicy.SecureOn` para impedir capturas
  normales de la ventana y no ofrece copiar/compartir/mostrar el secreto
  después de guardarlo. Traducciones ES/EN/PT-BR/AR.
- Los lectores internos futuros pueden llamar `use(id) { bytes -> ... }`
  para operaciones explícitamente autorizadas. Los bytes temporales de
  la copia del secreto se sobrescriben con ceros al salir del callback,
  incluso si este lanza una excepción. También se sobrescriben los búferes
  plaintext de lectura y escritura en lo posible.
- Borrado por usuario independiente del historial cifrado. La limpieza del
  historial NO elimina las credenciales privadas. Existe `clearAll()`
  destructivo de uso explícito, que elimina también el alias Keystore.
- Si un archivo está corrupto o el alias Keystore se pierde, la lista muestra
  el número de registros ilegibles **sin borrarlos automáticamente**.
- Los nuevos campos de la interfaz no se incluyen en copias de seguridad ni
  en estado persistente de Compose. Los secretos no se adjuntan a
  diagnósticos, logs, accesos directos, Intent o APK.

## Qué NO hace todavía

El almacén **no se conecta automáticamente a ningún descifrador existente**:
los formatos con claves públicas siguen usando sus claves históricas y
conservan todos sus resultados actuales. Conectar una contraseña del usuario
a un formato exige conocer su protocolo exacto y una acción de selección/
autorización, así como pruebas de paridad de archivos reales; nunca se
sustituirá una clave de compatibilidad pública por una clave privada
arbitraria. Tampoco se implementa sincronización, recuperación en la nube
ni recuperación después de reinstalar la aplicación.

Android Keystore puede estar respaldado por hardware/TEE/StrongBox según el
modelo de teléfono, pero **no está garantizado**. El propietario de un
dispositivo comprometido o con privilegios elevados puede observar secretos
mientras se usan en memoria, aunque no pueda exportar el material de la clave
de Android Keystore directamente. Un campo de contraseña de Compose se
representa temporalmente como `String` administrado por el runtime; se
limpia del estado de la UI en cuanto se envía, pero no existe garantía
absoluta de borrado de todos los objetos JVM anteriores.

## Validación y gates

- `DevicePrivateCredentialVaultInstrumentedTest.kt`: guardar/leer/borrar,
  prueba de no exposición del secreto como texto dentro del archivo,
  bytes limpiados tras el callback, corrupción AES-GCM, intercambio de UUID
  y límites de entrada.
- `scripts/android_s4_provisioning_audit.py`: verifica invariantes del
  proveedor/manifest/interfaz/firmado y rechaza `.s4k`, JKS, PKCS12 y otros
  archivos privados si aparecen dentro de la APK debug, R8 o firmada.
- `tests/test_android_s4_provisioning_audit.py`: pruebas del escáner de
  archivos privados sobre APK sintética.
- Las suites existentes de S.1/S.2/S.3, 239 formatos y emulador API35 siguen
  siendo obligatorias; S.4 no añade ni elimina motores de descifrado.
- CI no publica una APK estable por sí solo: sigue siendo necesaria la
  política de firma de producción y las pruebas físicas del propietario.

## Próximos pasos de seguridad

1. Si un formato realmente necesita una contraseña externa, definir el
   esquema de identificación y selección manual por archivo, sin reutilizar
   automáticamente credenciales entre formatos.
2. Probar restauración de instalación, bloqueo de pantalla, eliminación de
   credenciales y pérdida de clave en dispositivos físicos.
3. Auditar las rutas de autorización de claves opcionales al avanzar a
   S.5; no introducir un backend obligatorio.
