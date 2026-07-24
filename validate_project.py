#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def validate_python_files() -> list[str]:
    errors: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        if any(part in {"node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError as exc:
            errors.append(f"Python inválido: {path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}")
    return errors


def validate_registry() -> list[str]:
    errors: list[str] = []
    path = ROOT / "decoders.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"No se pudo leer decoders.json: {exc}"]

    decoders = data.get("decoders", {}) if isinstance(data, dict) else {}
    if not isinstance(decoders, dict) or not decoders:
        return ["decoders.json no contiene un registro válido."]

    for extension, spec in decoders.items():
        if not isinstance(spec, dict):
            errors.append(f".{extension}: configuración inválida")
            continue
        name = spec.get("name")
        script = spec.get("script")
        runtime = spec.get("runtime")
        if not isinstance(name, str) or not name.strip():
            errors.append(f".{extension}: falta el nombre público de la aplicación")
        if runtime not in {"python", "node", "php"}:
            errors.append(f".{extension}: runtime inválido {runtime!r}")
        if not script or not (ROOT / str(script)).is_file():
            errors.append(f".{extension}: no existe el script {script!r}")
        expected_folder = {"python": "Python", "node": "JavaScript", "php": "PHP"}.get(runtime)
        if expected_folder and Path(str(script)).parts[:2] != ("decoders", expected_folder):
            errors.append(
                f".{extension}: {script!r} no está dentro de decoders/{expected_folder}/"
            )
    return errors



RECENT_CLI_SCRIPTS = (
    "decoders/Python/DARKTUNNEL.py",
    "decoders/Python/HTTPCUSTOM.py",
    "decoders/Python/HTTPINJECTOR.py",
    "decoders/Python/HTTPINJECTORLITE.py",
    "decoders/Python/NPVTUNNEL.py",
    "decoders/Python/SSCCUSTOM.py",
)

CRITICAL_CLI_SCRIPTS = RECENT_CLI_SCRIPTS + (
    "decoders/Python/TLS.py",
    "decoders/Python/EV2RAY.py",
    "decoders/Python/maya.py",
    "decoders/Python/xui.py",
    "decoders/Python/sockip.py",
)


def validate_recent_cli_scripts(project_dir: Path) -> list[str]:
    errors: list[str] = []
    for script_name in CRITICAL_CLI_SCRIPTS:
        script_path = project_dir / script_name
        if not script_path.is_file():
            errors.append(f"No existe el decodificador reciente: {script_name}")
            continue
        source = script_path.read_text(encoding="utf-8")
        if 'if __name__ == "__main__":' not in source and "if __name__ == '__main__':" not in source:
            errors.append(f"{script_name} no tiene entrada CLI __main__")
        if "sys.argv" not in source and "ArgumentParser" not in source:
            errors.append(f"{script_name} no recibe el archivo por argumento")
    return errors



def validate_multipart_text_integration(project_dir: Path) -> list[str]:
    errors: list[str] = []
    text_handler = project_dir / "spdecode" / "handlers" / "text_protocols.py"
    state_module = project_dir / "spdecode" / "text_sessions.py"

    if not text_handler.is_file():
        return ["No existe spdecode/handlers/text_protocols.py"]
    if not state_module.is_file():
        return ["No existe spdecode/text_sessions.py"]

    source = text_handler.read_text(encoding="utf-8")
    required_fragments = {
        "importa el mismo método SSC": "from decoders.Python.SSCCUSTOM import run as decode_ssc_payload",
        "importa el mismo método Dark Tunnel": "from decoders.Python.DARKTUNNEL import run as decode_dark_payload",
        "detecta ssc://": '_SSC_PREFIX = "ssc://"',
        "procesa SSC directamente": 'decode_ssc_payload(session.payload.encode("utf-8"))',
        "procesa Dark Tunnel directamente": 'decode_dark_payload(session.payload.encode("utf-8"))',
        "acepta fragmentos posteriores": "append_to_session(",
        "usa sesiones genéricas": "from spdecode.text_sessions import (",
    }
    for label, fragment in required_fragments.items():
        if fragment not in source:
            errors.append(f"Integración multipart incompleta: no {label}")

    state_source = state_module.read_text(encoding="utf-8")
    if "protocol: str" not in state_source:
        errors.append("El estado multipart no separa protocolos")
    if "sorted(self.fragments)" not in state_source:
        errors.append("El estado multipart no reconstruye por message_id")
    return errors



def validate_json_output_formatting(project_dir: Path) -> list[str]:
    errors: list[str] = []
    documents_path = project_dir / "spdecode" / "handlers" / "documents.py"
    text_path = project_dir / "spdecode" / "handlers" / "text_protocols.py"

    documents_source = documents_path.read_text(encoding="utf-8") if documents_path.is_file() else ""
    text_source = text_path.read_text(encoding="utf-8") if text_path.is_file() else ""

    for script in RECENT_CLI_SCRIPTS:
        script_path = project_dir / script
        source = script_path.read_text(encoding="utf-8") if script_path.is_file() else ""
        if "def _format_top_level_json(data):" not in source:
            errors.append(f"{script} no contiene su propio formateador JSON raíz")
        if "_format_top_level_json(" not in source.replace("def _format_top_level_json(data):", ""):
            errors.append(f"{script} no usa su formateador JSON raíz en la salida")
        if "sort_keys=True" in source:
            errors.append(f"{script} reordena claves JSON y no debería hacerlo")

    if "format_decoder_json_output" in documents_source:
        errors.append("documents.py todavía reformatea resultados que ya vienen listos del decodificador")
    if "format_decoder_json_output" in text_source:
        errors.append("text_protocols.py todavía reformatea SSC/Dark fuera de los decodificadores")
    return errors



def validate_tls_integration(project_dir: Path) -> list[str]:
    errors: list[str] = []
    registry_path = project_dir / "decoders.json"
    tls_script = project_dir / "decoders" / "Python" / "TLS.py"
    text_handler = project_dir / "spdecode" / "handlers" / "text_protocols.py"

    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))["decoders"]
        spec = registry.get("tls")
    except Exception as exc:
        return [f"No se pudo validar TLS Tunnel: {exc}"]

    expected = {
        "script": "decoders/Python/TLS.py",
        "runtime": "python",
        "name": "TLS Tunnel",
    }
    if spec != expected:
        errors.append("El registro .tls no apunta correctamente a TLS Tunnel")

    source = tls_script.read_text(encoding="utf-8") if tls_script.is_file() else ""
    required_script = (
        "def decrypt_tls_payload(",
        "AES.MODE_GCM",
        "def run(file_bytes",
        'if __name__ == "__main__":',
    )
    for fragment in required_script:
        if fragment not in source:
            errors.append(f"TLS.py no contiene {fragment!r}")

    handler_source = text_handler.read_text(encoding="utf-8") if text_handler.is_file() else ""
    if "from decoders.Python.TLS import run as decode_tls_payload" not in handler_source:
        errors.append("TLS Tunnel no está conectado al handler de texto")
    if "tls://" not in handler_source:
        errors.append("El handler de texto no detecta tls://")

    return errors


def validate_ev2ray_integration(project_dir: Path) -> list[str]:
    errors: list[str] = []
    registry_path = project_dir / "decoders.json"
    decoder_path = project_dir / "decoders" / "Python" / "EV2RAY.py"

    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))["decoders"]
        spec = registry.get("v2")
    except Exception as exc:
        return [f"No se pudo validar e-V2Ray: {exc}"]

    expected = {
        "script": "decoders/Python/EV2RAY.py",
        "runtime": "python",
        "name": "e-V2Ray",
    }
    if spec != expected:
        errors.append("El registro .v2 no apunta correctamente a e-V2Ray")

    source = decoder_path.read_text(encoding="utf-8") if decoder_path.is_file() else ""
    for fragment in (
        "def _xor_periodic(",
        "def _aes_ecb_decrypt(",
        "def _try_decode_v2ray_json(",
        "def run(file_bytes",
        'if __name__ == "__main__":',
    ):
        if fragment not in source:
            errors.append(f"EV2RAY.py no contiene {fragment!r}")
    return errors


def validate_three_app_integration(project_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        registry = json.loads(
            (project_dir / "decoders.json").read_text(encoding="utf-8")
        )["decoders"]
    except Exception as exc:
        return [f"No se pudo validar Maya/XUI/SocksIP: {exc}"]

    expected = {
        "maya": {
            "script": "decoders/Python/maya.py",
            "runtime": "python",
            "name": "Maya Tunnel",
        },
        "xui": {
            "script": "decoders/Python/xui.py",
            "runtime": "python",
            "name": "XUI Tunnel",
        },
        "sip": {
            "script": "decoders/Python/sockip.py",
            "runtime": "python",
            "name": "SocksIP Tunnel",
        },
    }
    for extension, spec in expected.items():
        if registry.get(extension) != spec:
            errors.append(f"El registro .{extension} no apunta al decodificador actual")

    required = {
        "decoders/Python/_noobcrypt.py": (
            "def decrypt_profile(",
            "AES.MODE_CBC",
            "def _decrypt_aes_gcm(",
            "AES.MODE_GCM",
            "def _decode_inner_values(",
            '"maya": bytes.fromhex',
            '"xui": bytes.fromhex',
        ),
        "decoders/Python/sockip.py": (
            "class _JavaObjectReader:",
            "def decode_profile(",
            "AES.MODE_ECB",
            "UnsupportedSocksIPVersion",
        ),
    }
    for relative_path, fragments in required.items():
        path = project_dir / relative_path
        source = path.read_text(encoding="utf-8") if path.is_file() else ""
        for fragment in fragments:
            if fragment not in source:
                errors.append(f"{relative_path} no contiene {fragment!r}")
    return errors


def validate_http_injector_lite_integration(project_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        registry = json.loads(
            (project_dir / "decoders.json").read_text(encoding="utf-8")
        )["decoders"]
    except Exception as exc:
        return [f"No se pudo validar HTTP Injector Lite: {exc}"]

    expected = {
        "script": "decoders/Python/HTTPINJECTORLITE.py",
        "runtime": "python",
        "name": "HTTP Injector Lite",
    }
    if registry.get("ehil") != expected:
        errors.append("El registro .ehil no apunta a HTTPINJECTORLITE.py")

    normal_expected = {
        "script": "decoders/Python/HTTPINJECTOR.py",
        "runtime": "python",
        "name": "HTTP Injector",
    }
    if registry.get("ehi") != normal_expected:
        errors.append("El registro .ehi no apunta a HTTPINJECTOR.py")
    if registry.get("ehi", {}).get("script") == registry.get("ehil", {}).get("script"):
        errors.append(
            "HTTP Injector y HTTP Injector Lite comparten incorrectamente el mismo script"
        )

    decoder_path = project_dir / "decoders" / "Python" / "HTTPINJECTORLITE.py"
    source = decoder_path.read_text(encoding="utf-8") if decoder_path.is_file() else ""
    for fragment in (
        "class HTTPInjectorLiteConstants:",
        "class HTTPInjectorLiteDecryptor:",
        "def decode_profile(",
        "def _decode_inner_fields(",
        "HTTP Injector Lite",
    ):
        if fragment not in source:
            errors.append(f"HTTPINJECTORLITE.py no contiene {fragment!r}")

    normal_path = project_dir / "decoders" / "Python" / "HTTPINJECTOR.py"
    normal_source = normal_path.read_text(encoding="utf-8") if normal_path.is_file() else ""
    for forbidden in ("HTTP Injector Lite", ".ehil", "LITE_"):
        if forbidden in normal_source:
            errors.append(f"HTTPINJECTOR.py todavía contiene lógica Lite: {forbidden!r}")
    return errors


def _decorator_name(decorator: ast.expr) -> str:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return ""


def validate_authorization_integration(project_dir: Path) -> list[str]:
    """Exige autorización central en cada handler que descifra contenido."""
    errors: list[str] = []
    protected_files = (
        project_dir / "spdecode" / "handlers" / "documents.py",
        project_dir / "spdecode" / "handlers" / "text_protocols.py",
        project_dir / "spdecode" / "handlers" / "fallback.py",
    )

    for path in protected_files:
        if not path.is_file():
            errors.append(f"No existe el handler protegido {path.relative_to(project_dir)}")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = {_decorator_name(item) for item in node.decorator_list}
            if "message_handler" in decorators and "require_authorized" not in decorators:
                errors.append(
                    f"{path.relative_to(project_dir)}:{node.lineno}: "
                    f"el handler {node.name} no usa require_authorized"
                )
    return errors


def validate_secret_hygiene(project_dir: Path) -> list[str]:
    errors: list[str] = []
    if (project_dir / "config.json").exists():
        errors.append("config.json no debe distribuirse; usa config.example.json")
    if (project_dir / "node_modules").exists():
        errors.append("node_modules no debe distribuirse; se reconstruye con npm ci")

    telegram_token = re.compile(r"(?<![A-Za-z0-9_-])\d{8,12}:[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])")
    for path in sorted(project_dir.rglob("*")):
        if not path.is_file() or any(part in {".git", "__pycache__"} for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if telegram_token.search(source):
            errors.append(f"Posible token de Telegram incluido en {path.relative_to(project_dir)}")
    return errors


def validate_pinned_dependencies(project_dir: Path) -> list[str]:
    errors: list[str] = []
    requirements = project_dir / "requirements.txt"
    for line in requirements.read_text(encoding="utf-8").splitlines():
        dependency = line.strip()
        if dependency and not dependency.startswith("#") and "==" not in dependency:
            errors.append(f"Dependencia Python sin versión fija: {dependency}")

    package = json.loads((project_dir / "package.json").read_text(encoding="utf-8"))
    for name, version in package.get("dependencies", {}).items():
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", str(version)):
            errors.append(f"Dependencia Node.js sin versión exacta: {name}@{version}")
    return errors

def main() -> int:
    errors = [
        *validate_python_files(),
        *validate_registry(),
        *validate_recent_cli_scripts(ROOT),
        *validate_multipart_text_integration(ROOT),
        *validate_json_output_formatting(ROOT),
        *validate_tls_integration(ROOT),
        *validate_ev2ray_integration(ROOT),
        *validate_three_app_integration(ROOT),
        *validate_http_injector_lite_integration(ROOT),
        *validate_authorization_integration(ROOT),
        *validate_secret_hygiene(ROOT),
        *validate_pinned_dependencies(ROOT),
    ]
    if errors:
        print("VALIDACIÓN FALLIDA")
        for error in errors:
            print(f" - {error}")
        return 1

    count = len(json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"])
    print(
        f"VALIDACIÓN OK: Python sintácticamente correcto, {count} decodificadores registrados, "
        f"{len(CRITICAL_CLI_SCRIPTS)} decodificadores críticos con entrada CLI, "
        "TLS + e-V2Ray + Maya/XUI/SocksIP + HTTP Injector Lite integrados, "
        "permisos centralizados y secretos ausentes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
