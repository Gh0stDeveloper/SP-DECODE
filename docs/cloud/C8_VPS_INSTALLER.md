# C8 — SP-DECODE Cloud: instalación VPS, actualizador y compilador APK/AAB

**Rama:** `feat/cloud-c8-vps-installer-updater`, basada en C7 (#93). Es software para instalar en tu VPS: **no se ha conectado ni desplegado en una VPS real**. C8 no cambia el bot Python ni las pantallas Android.

## 1. Instalar SP-DECODE Cloud en Oracle / AWS / DuckDNS

Necesitas Ubuntu/Debian 64 bits, un hostname (por ejemplo, DuckDNS) cuyo DNS A apunte al VPS y puertos **80/443 TCP** abiertos tanto en UFW como en Oracle NSG/security lists o AWS Security Group. Docker y Nginx quedan instalados automáticamente. Si el repositorio es privado, prepara acceso de lectura mediante clave SSH de despliegue; nunca pongas un token PAT en el comando.

```bash
sudo apt-get update && sudo apt-get install -y git
git clone --branch feat/cloud-c8-vps-installer-updater \
  https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
sudo bash cloud/infra/vps/install.sh \
  --domain tuusuario.duckdns.org \
  --email tucorreo@ejemplo.com
```

El script solicita automáticamente certificado HTTPS Let's Encrypt con webroot de Nginx, instala renovación/reload, clona la rama controlada a `/opt/spdecode/repo`, genera secretos del servidor en `/etc/spdecode/cloud.env` con permisos root 0600 y despliega Docker Compose: Next.js, worker privado Python/Node/PHP y Redis en red interna. **API y administrador permanecen desactivados por defecto**, y `CLOUD_FORCE_MAINTENANCE=true`.

La administración remota se bloquea en Nginx por defecto (solo localhost); puedes agregar `--admin-cidr DIRECCION_IP_PUBLICA/32` al instalador para autorizar exclusivamente tu IP. No pongas 0.0.0.0/0 salvo que añadas protección independiente como VPN/MFA. El script no registra DuckDNS ni abre automáticamente el NSG/firewall de Oracle.

En VPS pequeños ten presente que **la instalación de contenedores y la compilación Android son operaciones distintas**. Se recomiendan 2–4 GiB de RAM para el primer build de Docker, más espacio de disco de al menos 20 GiB si piensas compilar localmente. Una instancia económica no garantiza atender 200–300 operaciones de descifrado simultáneas: C7/C8 requieren benchmark y límites por sesión. En Oracle ARM64 se puede alojar el servidor pero el SDK/NDK de compilación Android suministrado aquí requiere x86_64; compila Android con GitHub Actions en ese caso.

## 2. Actualizador integral

```bash
sudo spdecode status
sudo spdecode logs web
sudo spdecode logs api
sudo spdecode logs panel
sudo spdecode logs worker

sudo spdecode update api
sudo spdecode update web
sudo spdecode update panel
sudo spdecode update worker
sudo spdecode update all
sudo spdecode update all feat/cloud-c8-vps-installer-updater

sudo spdecode backup
sudo spdecode rollback
sudo spdecode restart all
```

API, web y panel **comparten una misma aplicación Next.js**, así que los tres comandos despliegan conjuntamente la imagen web. En cambio el worker de descifrado sí es un contenedor separado y puede actualizarse sin reconstruir el frontend. El actualizador bloquea operaciones concurrentes con flock, exige repositorio limpio, hace git fetch del ref seleccionado y guarda el SHA previo, reconstruye el componente y comprueba el endpoint de salud. Si falla, intenta restaurar el código anterior y reconstruir contenedores. No realiza migraciones ni garantiza cero downtime; una actualización irreversible del estado persistente requiere restauración manual del backup.

Los archivos principales están en `/etc/spdecode/cloud.env` y `/etc/spdecode/install.conf` (root 0600), nunca se publican ni se añaden al Git. El comando `spdecode backup` crea copias sensibles root-only en `/opt/spdecode/backups`; conserva una copia cifrada externa.

## 3. Panel y credenciales privadas

```bash
sudo spdecode config admin-password
sudo chmod 600 /root/service-account.json
sudo spdecode config google-service-account /root/service-account.json
sudo spdecode config set CLOUD_GOOGLE_PLAY_PACKAGE com.ghostdeveloper.spdecode

# Tras configuración y validación manual del acceso de administrador:
sudo spdecode config set CLOUD_ADMIN_ENABLED true
sudo spdecode restart web

# Mantenimiento de emergencia impuesto en servidor:
sudo spdecode config set CLOUD_FORCE_MAINTENANCE true
sudo spdecode restart web
```

El password administrativo se lee sin eco y se almacena como hash scrypt. El JSON de Google se conserva en variables privadas del servidor, no en Kotlin/C++ ni en JavaScript del navegador. Todos los proveedores de importación permanecen deshabilitados por defecto hasta suministrar credenciales autorizadas. Play Integrity exige validación de versión, paquete, licencia, dispositivos y Google Play Console: un servidor instalado no certifica esas verificaciones.

## 4. Compilar APK y AAB firmados para pruebas de Play Console

**AAB** significa Android App Bundle: es el archivo de carga recomendado para Google Play Console; el APK permite pruebas e instalación directa. Un AAB no se instala directamente como APK y debe firmarse con tu clave de subida registrada. La clave de firma de la aplicación de Google Play puede ser diferente de la clave de subida.

En VPS **x86_64** con al menos 12 GiB libres adicionales:

```bash
sudo spdecode android setup
```

Instala OpenJDK 17, Android SDK Command-Line Tools con SHA-256 verificado, API 35, NDK 27.2.12479018, CMake 3.22.1, Build Tools 35 y Gradle 8.11.1 verificado. Descarga de dependencias y compilación pueden consumir muchos recursos.

Si la aplicación ya tiene una clave de subida registrada, utiliza **la misma clave existente** (no crees otra):

```bash
sudo chmod 600 /root/upload-key.p12
sudo spdecode android signing configure /root/upload-key.p12 mi_alias
```

Solo para una aplicación nueva **sin clave registrada**, o con la autorización de Google para cambiar tu upload key:

```bash
sudo spdecode android signing generate spdecode_upload
```

Esto solicita una contraseña que no se muestra. Guarda la clave en `/etc/spdecode/keys/upload-key.p12` y las contraseñas en `/etc/spdecode/signing.env`; respáldalas cifradas fuera del servidor. Nunca generes otra clave en cada actualización.

Para compilar una nueva versión de prueba usando un `versionCode` mayor al del código fuente (y que también debe superar el máximo usado en Play Console):

```bash
sudo spdecode android build \
  --version-name 1.2.0 --version-code 26 --testing-only

# Actualizar código y compilar un nuevo paquete de prueba:
sudo spdecode update app feat/cloud-c8-vps-installer-updater \
  --version-name 1.2.0 --version-code 26 --testing-only

sudo spdecode android artifacts
```

El compilador crea un Git worktree temporal, modifica `versionName`/`versionCode` solo en esa copia, incorpora tu dominio HTTPS compilado en `libspdecode.so`, ejecuta `:app:assembleRelease :app:bundleRelease` y verifica la firma APK con apksigner, alineación 16 KiB, firma AAB con jarsigner, escaneo C5 del APK y hashes SHA-256. Guarda los paquetes y manifiesto en `/opt/spdecode/artifacts/vVERSION-CODE/`. No sobreescribe versiones firmadas existentes.

**NO se suben archivos automáticamente a Play Console**, **NO se publica una nueva versión pública** y **NO se fusiona con main**: el gate C7 continúa bloqueando producción hasta comprobar el servicio y Play Integrity reales. El AAB de este comando es un **artefacto de pruebas**, que puedes evaluar en un canal autorizado y cerrado una vez configurado Play Console. El script no asegura que un usuario pueda descifrar sin VPS ni Play Integrity real.

## 5. Archivos, seguridad y límites

- `/opt/spdecode/repo` — checkout de código gestionado.
- `/opt/spdecode/artifacts` — APK/AAB firmados y SHA-256; acceso root-only.
- `/opt/spdecode/previous.sha` — SHA para rollback.
- `/etc/spdecode/cloud.env` — secretos de API, Redis y administrador.
- `/etc/spdecode/signing.env` y `/etc/spdecode/keys/upload-key.p12` — claves de firma, root-only.
- `/etc/nginx/sites-available/spdecode.conf` — proxy HTTPS con allowlist para admin.
- `/var/www/spdecode-acme` — desafíos Let's Encrypt.
- `cloud/infra/vps/tests/test_installer.py` — pruebas offline; GitHub Actions valida sintaxis, dominio y Compose.

Quienes tienen acceso root o al socket Docker pueden leer las variables del contenedor; restringe SSH/Docker y usa un gestor de secretos si el proyecto crece. Nginx solo expone la web local de Next.js, nunca Redis ni worker por un puerto directo. Para producción faltan: Play Integrity real, muestras autorizadas, privacidad, carga en VPS, monitorización, recuperación y revisión final C8. Las verificaciones CI no sustituyen una instalación en una VPS real.
