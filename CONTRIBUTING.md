# Contributing to SP-DECODE

SP-DECODE contains two distinct components: **native offline Android** and the **self-hosted Telegram bot** (Python, Node.js and PHP). Changes should identify which component is affected and preserve existing decoders.

## Reporting an issue

1. Search existing issues and consult [Releases](https://github.com/Gh0stDeveloper/SP-DECODE/releases).
2. Identify component, SP-DECODE version, environment, file extension/text scheme and **exact exporting application version**.
3. Provide steps to reproduce, expected output, actual output and redacted diagnostic details.
4. If the original Python/Node/PHP script decodes successfully but Android fails, explicitly identify which **reference file decoder or Telegram text handler** was tested. Those are different routes.
5. Never publish passwords, tokens, SSH keys, private hosts, personal data, live configs or unredacted decoded results.

### Reproducible compatibility reports

| Field | Example (fictional) |
|---|---|
| Product | Android |
| SP-DECODE | 1.0.5-rc.1 |
| Exporter | ExampleVPN 4.2 |
| Input | `.example` / `example://` |
| Expected | Original script successfully decodes |
| Actual | Android reports unsupported variant |
| Evidence | Sanitized log and synthetic fixture |

Registered extensions and synthetic golden fixtures confirm routing or selected algorithms, **not** every encrypted variant from an external exporter. To debug a real sample, contact the maintainer privately and agree on an appropriate transfer method first. Public records should use SHA-256, redacted metadata and nonsensitive test vectors. See [real-sample parity triage](docs/android/REAL_DECODER_PARITY_TRIAGE.md).

## Development workflow

- Use a focused branch and a pull request. Document actual validation evidence and known limitations.
- Keep bot decoders in their existing runtime folders and maintain `decoders.json`.
- Preserve Android offline architecture and avoid adding runtime Telegram, Node.js or Python dependencies to the APK.
- Prefer synthetic regression cases that are generated from and compared against the original reference engine.
- For bot changes run:

~~~bash
python validate_project.py
python -m unittest discover -s tests -v
~~~

- For documentation changes run:

~~~bash
python docs/android/validate_docs.py
~~~

- For native Android changes run or inspect the CI **Android API 35** parity checks. Explain whether a test is synthetic, based on a real export, or a device-owner attestation.
- Use descriptive commits, preferably Conventional Commits such as `fix(android): correct text protocol parsing`.

## Releases and support

The [readiness manifest](release/android-readiness.json) and [release runbook](docs/android/RELEASE_RUNBOOK.md) control stable and preview publication. A permanently signed testing prerelease is **not** a stable QA approval.

Contact: [Telegram community](https://t.me/CodeBreakersHub), [channel](https://t.me/GhostDeve) or [maintainer](https://t.me/Gh0stDeveloper). Security reports follow [SECURITY.md](SECURITY.md).

**License:** there is currently no project-wide LICENSE file. Contact the maintainer about redistribution and derivative permissions.
