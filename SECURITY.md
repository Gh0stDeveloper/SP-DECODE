# Security Policy

SP-DECODE can decode configuration files containing sensitive endpoints, tokens and credentials. **Treat decrypted output as sensitive unless explicitly synthetic.**

## Disclosure

Do **not** post exploits, private configuration files, live credentials, keys, device identifiers, tokens, or production endpoints in public GitHub issues.

If GitHub's private vulnerability reporting is enabled for this repository, use **Report a vulnerability**. Otherwise contact the project owner privately at [Telegram @Gh0stDeveloper](https://t.me/Gh0stDeveloper) to arrange an appropriate channel **before sending any sensitive sample**. Provide affected version, impact, and sanitized reproduction steps.

## Release support

- **Android v1.0.4:** published stable APK, accepted by the product owner.
- **Android v1.0.5-rc.1:** signed public testing preview; the **1.0.5 stable QA gate is NO-GO** pending real exporter samples.
- **Telegram bot:** source distribution for self-hosted operation; operators should validate pinned dependencies and updates.

This is not a promise that every historical export is supported or that all versions have undergone an independent security audit.

## Operational safeguards

- **Android:** processing is offline and local. Protect copied/exported plaintext and local files; a user viewing a decoded password should avoid sharing screenshots publicly.
- **Telegram bot:** configuration data travels over Telegram and is processed on the deployment operator's runtime. Use only trusted bot installations.
- **Bot secrets:** keep `config.json` and Telegram bot tokens out of Git; rotate exposed tokens. Use restrictive file permissions and manage access by administrators/groups.
- **APK verification:** download from [official Releases](https://github.com/Gh0stDeveloper/SP-DECODE/releases); verify the SHA-256 manifest and accompanying production signing report. Do not distribute debug or temporary-key builds as releases.
- **Decoder QA:** avoid logging plaintext secrets in tests. Synthetic samples are not proof of universal compatibility.
- **Authorized use:** decode only configurations you own or are authorized to inspect.

See [Android security and QA](docs/android/SECURITY_AND_QA.md) and [release readiness](release/android-readiness.json).
