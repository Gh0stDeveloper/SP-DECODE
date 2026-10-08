<div align="center">

# SP-DECODE

**Modular Telegram configuration decoder powered by Python, Node.js and PHP.**

A structured, extensible decoder platform for processing supported configuration files and text protocols through a centralized Telegram bot.

<p>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/Node.js-20%2B-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js 20+" />
  <img src="https://img.shields.io/badge/PHP-8.1%2B-777BB4?style=for-the-badge&logo=php&logoColor=white" alt="PHP 8.1+" />
  <img src="https://img.shields.io/badge/Telegram-Bot-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram Bot" />
</p>

<p>
  <a href="https://github.com/Gh0stDeveloper"><img src="https://img.shields.io/badge/GitHub-Gh0stDeveloper-181717?style=flat-square&logo=github" alt="GitHub" /></a>
  <a href="https://t.me/GhostDeve"><img src="https://img.shields.io/badge/Telegram-Channel-26A5E4?style=flat-square&logo=telegram&logoColor=white" alt="Telegram channel" /></a>
  <a href="https://t.me/CodeBreakersHub"><img src="https://img.shields.io/badge/Telegram-Community-26A5E4?style=flat-square&logo=telegram&logoColor=white" alt="Telegram community" /></a>
</p>

</div>

> [!WARNING]
> **Maintenance notice:** not every legacy decoder has been fully revalidated against the latest versions of the applications it targets. Some formats may fail or behave differently depending on the exporting app version. If you find a broken decoder, please report it in the [Telegram community](https://t.me/CodeBreakersHub), the [Telegram channel](https://t.me/GhostDeve), or directly to [@Gh0stDeveloper](https://t.me/Gh0stDeveloper).

---

## SP-DECODE Android — Offline application (planned)

> [!NOTE]
> The Android APK is **planned and not yet available**. This is an independent, fully offline Android app with **no Telegram account, no login, no backend and no Internet permission**. The existing Telegram bot continues unchanged.

- [Official Android documentation and design references](docs/android/README.md)
- [Visual identity, UI tokens and SVG mockups](docs/android/DESIGN_SYSTEM.md)
- [Offline UI localization (Spanish, English, Brazilian Portuguese, Arabic RTL) — decoder output never translated](docs/android/LOCALIZATION.md)
- [Architecture](docs/android/ARCHITECTURE.md) · [Decoder compatibility matrix](docs/android/DECODER_MATRIX.md)
- [Phased roadmap](docs/android/ROADMAP.md) · [Cross-chat handoff](docs/android/HANDOFF.md)
- [Decoder A.2 source audit (48 scripts)](docs/android/DECODER_AUDIT.md) · [Golden fixture policy](docs/android/A2_FIXTURE_POLICY.md)
- [A.2.3 synthetic golden corpus — forty-nine cases, forty-eight file suffixes](docs/android/A23_GOLDEN_CORPUS.md)

The Android proposal preserves the premium AMOLED visual design: shield header, centered import panel, structured result cards, copy/export buttons and bottom navigation.

---

## Overview

SP-DECODE is a modular Telegram bot designed to process and decode configuration formats used by multiple tunneling, proxy and VPN-related applications.

The project separates configuration, authorization, decoder registration, runtime execution and Telegram handlers into independent modules. File decoders are registered through `decoders.json` and may run through **Python**, **Node.js** or **PHP**, allowing new formats to be added without turning the main bot entry point into a monolithic script.

### Core features

- **59 registered file extensions/suffixes**.
- Python, Node.js and PHP decoder runtimes.
- Centralized decoder registry through `decoders.json`.
- Telegram file processing with automatic format detection.
- Text protocol decoding for supported URI/configuration schemes.
- Multipart reconstruction for large SSC Custom and Dark Tunnel payloads.
- Centralized authorization for administrators and allowed groups.
- Configurable file-size, decoder timeout and text-session limits.
- Temporary input/output cleanup after processing.
- Validation tooling and automated unit tests.
- Local configuration with optional environment-variable token injection.

---

## Technology stack

<div align="center">
  <a href="https://www.python.org/"><img src="https://cdn.simpleicons.org/python/3776AB" width="44" height="44" alt="Python" /></a>&nbsp;&nbsp;
  <a href="https://nodejs.org/"><img src="https://cdn.simpleicons.org/nodedotjs/339933" width="44" height="44" alt="Node.js" /></a>&nbsp;&nbsp;
  <a href="https://www.php.net/"><img src="https://cdn.simpleicons.org/php/777BB4" width="44" height="44" alt="PHP" /></a>&nbsp;&nbsp;
  <a href="https://telegram.org/"><img src="https://cdn.simpleicons.org/telegram/26A5E4" width="44" height="44" alt="Telegram" /></a>&nbsp;&nbsp;
  <a href="https://github.com/"><img src="https://cdn.simpleicons.org/github/181717" width="44" height="44" alt="GitHub" /></a>
</div>

### Main libraries

| Component | Purpose |
|---|---|
| [pyTelegramBotAPI](https://github.com/eternnoir/pyTelegramBotAPI) | Telegram Bot API integration |
| [PyCryptodome](https://www.pycryptodome.org/) | Cryptographic primitives used by supported decoders |
| [argon2-cffi](https://github.com/hynek/argon2-cffi) | Argon2 support |
| [MessagePack](https://msgpack.org/) | Binary serialization support |
| [Requests](https://requests.readthedocs.io/) | HTTP client functionality |
| [base64-js](https://github.com/beatgammit/base64-js) | Base64 support for Node.js decoders |

---

## Supported file formats

The following extensions are currently registered in `decoders.json`. Detection supports both regular and compound suffixes, including `.sksrv.png`.

| Application / format | Supported extension(s) | Runtime |
|---|---|---|
| HA Tunnel Plus | `.hat` | Node.js |
| X-Socks | `.xscks` | Python |
| PHC Tunnel | `.phc` | Python |
| HTTP Injector Lite | `.ehil` | Python |
| MinaProNet | `.mina` | Python |
| ASH Tunnel | `.at` | Python |
| Gold Tunnel | `.gold` | Python |
| NetMod | `.nm` | Python |
| NPV Tunnel v4 | `.npv4`, `.npvt` | Python |
| HTTP Tweak | `.ht`, `.htb` | Python |
| Tunnel | `.tnl` | Python |
| TLS Tunnel | `.tls` | Python |
| e-V2Ray | `.v2` | Python |
| ZIVPN | `.ziv` | Python |
| XrayPB | `.pb` | Python |
| Rez Tunnel | `.rez` | Node.js |
| SocksIP | `.sks` | Node.js |
| Stark VPN | `.stk` | Node.js |
| PCX Tunnel | `.pcx` | Python |
| SSH Injector | `.ssh` | Python |
| Net Tunnel | `.nt` | Python |
| VPN Lite | `.vpnlite` | Python |
| SUT Tunnel | `.sut` | Python |
| Maya Tunnel | `.maya` | Python |
| XUI Tunnel | `.xui` | Python |
| SocksIP Tunnel | `.sip` | Python |
| FN Tunnel | `.fɴ` | Python |
| MIJ Tunnel | `.mij` | Python |
| MTL Tunnel | `.mtl` | Python |
| FN Network | `.fnnetwork` | Python |
| MRC Tunnel | `.mrc` | Python |
| SKS Server | `.sksrv`, `.sksrv.png` | Python |
| V2Ray Injector | `.v2i` | Python |
| AGN Injector | `.agn` | Python |
| JVI Tunnel | `.jvi` | Python |
| JVC Tunnel | `.jvc` | Python |
| ARMOD | `.aro` | Python |
| Cloudy Inject | `.cloudy` | Python |
| ePro Tunnel | `.epro` | Node.js |
| Cloudy | `.cly` | Python |
| XTProy | `.xtp` | Python |
| Royal Tunnel | `.roy` | Python |
| WeTunnel | `.ipt` | Python |
| Rez Tunnel Lite | `.rezl` | Node.js |
| TV Tunnel | `.tvt` | Node.js |
| UWU Tunnel | `.uwu` | Python |
| NPV Tunnel v2 | `.npv2` | Node.js |
| Dark Tunnel | `.dark` | Python |
| OUSS Tunnel | `.ost` | Python |
| SBR Injector | `.sbr` | Python |
| SocksIP Plus | `.sksplus` | PHP |
| JEZ Tunnel | `.jez` | PHP |
| HRT Tunnel | `.hrt` | PHP |
| HTTP Custom | `.hc` | Python |
| HTTP Injector | `.ehi` | Python |
| SSC Custom | `.ssc` | Python |

> The registry currently contains **59 distinct supported suffixes**. Some applications intentionally map more than one extension to the same decoder.

---

## Supported text protocols

SP-DECODE can also process supported configuration strings directly from Telegram messages.

| Family | Supported schemes / prefixes |
|---|---|
| SSC Custom | `ssc://...` with automatic multipart reconstruction |
| TLS Tunnel | `tls://...` |
| Dark Tunnel | `dark://...`, `darktunnel://...` and compatible Dark Tunnel schemes |
| NetMod | `nm-vmess://`, `nm-vless://`, `nm-dns://`, `nm-trojan://`, `nm-ssh://`, `nm-ssr://`, `nm-xray-json://` |
| ARMOD | `ar-dns://`, `ar-vless://`, `ar-vmess://`, `ar-trojan://`, `ar-ssr://`, `ar-socks://`, `ar-trojan-go://`, `ar-ssh://` |
| Howdy | `howdy://`, `N7pr://` |
| XrayPB | `pb-vmess://`, `pb-ss://`, `pb-socks://`, `pb-vless://`, `pb-trojan://`, `pb-ssh://` |
| Other supported handlers | `vmess://`, `zivpn://`, `v2box://locked=...` |

Multipart text sessions are currently implemented for **SSC Custom** and **Dark Tunnel**. The bot retries decoding after each received fragment and automatically closes the session once a valid result is produced.

---

## Project architecture

```text
SP-DECODE/
├── main.py
├── decoders.json
├── config.example.json
├── requirements.txt
├── package.json
├── validate_project.py
├── decoders/
│   ├── Python/
│   ├── JavaScript/
│   └── PHP/
├── installers/
│   ├── configure.py
│   ├── install-termux.sh
│   └── install-vps.sh
├── scripts/
│   ├── spdecode-termux.sh
│   └── spdecode-vps.sh
├── spdecode/
│   ├── access.py
│   ├── config.py
│   ├── executor.py
│   ├── registry.py
│   ├── runtime.py
│   ├── text_sessions.py
│   ├── utils.py
│   └── handlers/
│       ├── commands.py
│       ├── documents.py
│       ├── text_protocols.py
│       └── fallback.py
└── tests/
```

### Runtime flow

```text
Telegram
   │
   ▼
Authorization
   │
   ├── File ──► Extension detection ──► decoders.json ──► Python / Node.js / PHP
   │
   └── Text ──► Protocol handler ──► Optional multipart session ──► Decoder
   │
   ▼
Formatted Telegram response + result file
```

---

## Requirements

Recommended runtime versions:

- **Python 3.11+**
- **Node.js 20+**
- **PHP 8.1+**
- A Telegram bot token created through [@BotFather](https://t.me/BotFather)

---

## Automated installers

SP-DECODE includes dedicated installers for **Termux** and **Linux VPS** environments. They install the required runtimes, Python dependencies, Node.js packages, create the local configuration, ask for the Telegram bot token, configure administrators/groups and start the bot automatically.

> **Why Node.js is installed:** JavaScript decoders require an actual Node.js runtime. The repository intentionally does not ship `node_modules`; the installer detects/installs Node.js when needed and runs `npm ci`.

### Termux

From a cloned repository:

```bash
bash installers/install-termux.sh
```

Or install directly from GitHub:

```bash
pkg install -y curl
curl -fsSL https://raw.githubusercontent.com/Gh0stDeveloper/SP-DECODE/main/installers/install-termux.sh -o install-spdecode.sh
bash install-spdecode.sh
```

The Termux installer:

- installs Python, PHP, Node.js, Git and native build dependencies;
- creates an isolated Python virtual environment;
- installs PyCryptodome, pyTelegramBotAPI, Argon2, MessagePack and Requests;
- installs Node.js decoder dependencies with `npm ci`;
- runs the validator and unit tests;
- launches an interactive setup for the Telegram token and access policy;
- creates the `spdecode` management command;
- starts the bot automatically in the background.

Available commands:

```bash
spdecode status
spdecode start
spdecode stop
spdecode restart
spdecode logs
spdecode config
spdecode update
spdecode validate
```

For reliable long-running operation on Android, disable battery optimization for Termux.

### VPS / Linux server

Supported installers currently target Debian/Ubuntu and Fedora/RHEL-compatible systems using `apt`, `dnf` or `yum`.

From a cloned repository:

```bash
bash installers/install-vps.sh
```

Or install directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/Gh0stDeveloper/SP-DECODE/main/installers/install-vps.sh -o /tmp/install-spdecode.sh
bash /tmp/install-spdecode.sh
```

Do **not** run the entire VPS installer with `sudo`; it requests elevated permissions only when system packages or the `systemd` service need them.

The VPS installer creates and enables a persistent `systemd` service named `spdecode`, starts it immediately and installs the same `spdecode` management command globally.

### Interactive access configuration

During installation, the setup wizard securely asks for:

1. the Telegram bot token;
2. administrator Telegram user IDs;
3. either:
   - specific allowed group IDs, or
   - **all groups/supergroups** where the bot is present.

The **all groups** option does not make private chats public. Private protected actions still require an administrator ID.

The generated `config.json` remains local, is ignored by Git and is written with restrictive file permissions where supported.

---

## Manual installation

### 1. Clone the repository

```bash
git clone https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
```

### 2. Create a Python virtual environment

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
npm ci
```

PHP decoders use the local PHP runtime and do not currently require Composer packages.

### 4. Create the local configuration

```bash
cp config.example.json config.json
```

On Windows PowerShell:

```powershell
Copy-Item config.example.json config.json
```

Edit `config.json` and configure:

- Telegram bot token.
- Administrator user IDs.
- Access mode: selected groups or all groups/supergroups.
- Allowed Telegram group IDs when selected-group mode is used.
- Runtime limits and temporary directories.

For server deployments, the bot token may instead be supplied through:

```bash
export SPDECODE_BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
```

> `config.json` is intentionally ignored by Git and must remain local.

---

## Running SP-DECODE

```bash
python main.py
```

At startup, SP-DECODE validates the decoder registry and checks that every registered decoder script exists before beginning Telegram long polling.

Administrators may use protected decoding features from any chat. Regular users are authorized inside explicitly configured groups, or inside every group/supergroup when `access.allow_all_groups` is enabled.

---

## Telegram commands

| Command | Description |
|---|---|
| `/start` | Open the main menu |
| `/help` | Show usage instructions |
| `/formats` | List all registered file formats |
| `/texts` | List supported text protocols |
| `/session` | Show the active multipart text session |
| `/ssc` | Show the current SSC session |
| `/dark` | Show the current Dark Tunnel session |
| `/cancel` | Cancel the pending multipart session |
| `/id` | Show user and chat IDs |
| `/ping` | Check whether the bot is responding |
| `/status` | Show internal status for administrators |
| `/about` | Show project information |

---

## Validation and tests

Run the project validator:

```bash
python validate_project.py
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

The validation layer checks project syntax, decoder registration, missing decoder files, protected handlers, pinned dependencies and accidental Telegram token exposure.

---

## Adding a new decoder

1. Add the decoder implementation to the appropriate runtime directory:
   - `decoders/Python/`
   - `decoders/JavaScript/`
   - `decoders/PHP/`
2. Register its extension, public name, script path and runtime in `decoders.json`.
3. Make sure the decoder accepts the file path expected by the executor.
4. Run `python validate_project.py`.
5. Run the full unit-test suite.

Example registry entry:

```json
{
  "example": {
    "script": "decoders/Python/example.py",
    "runtime": "python",
    "name": "Example Tunnel"
  }
}
```

---

## Security

SP-DECODE is designed so operational credentials remain outside version control.

- Never commit `config.json`, `.env` files or bot tokens.
- Prefer `SPDECODE_BOT_TOKEN` for hosted/server deployments.
- Keep administrator and allowed-group IDs under your control.
- Rotate a Telegram bot token immediately if it is ever exposed.
- Deleting a secret from the latest branch does **not** remove it from previous Git history.
- Use the project only with configurations you own or are explicitly authorized to inspect.

---

## Known compatibility note: SocksIP `.sip`

The current decoder supports the Java-serialization variant protected with Base64 and AES-ECB.

Some analyzed samples open the outer encrypted layer successfully but then begin with `VER7` instead of a Java serialization header. The analyzed SocksIP 15.14.4 application (`com.newtoolsworks.sockstunnel`, internal version 124) does not contain the corresponding `VER7` implementation, so the current decoder reports this case explicitly instead of returning misleading output.

A compatible SocksIP build that can import those samples, or a fresh `.sip` export generated directly by the analyzed application, is required to reproduce that variant accurately.

---

## Credits

**SP-DECODE** is created and maintained by **Ghost Developer** (`@Gh0stDeveloper`).

The project also relies on the open-source ecosystems around Python, Node.js, PHP, Telegram and the libraries listed above. Their respective projects and maintainers retain ownership of their software and trademarks.

---

## Contact

| Channel | Link |
|---|---|
| Developer | [@Gh0stDeveloper](https://t.me/Gh0stDeveloper) |
| Telegram channel | [@GhostDeve](https://t.me/GhostDeve) |
| Community | [@CodeBreakersHub](https://t.me/CodeBreakersHub) |
| GitHub | [github.com/Gh0stDeveloper](https://github.com/Gh0stDeveloper) |
| Website | [GhostDeveloper.vercel.app](https://GhostDeveloper.vercel.app) |

---

<div align="center">

**SP-DECODE — modular decoding, centralized authorization, multiple runtimes.**

Made by [Ghost Developer](https://github.com/Gh0stDeveloper).

</div>

