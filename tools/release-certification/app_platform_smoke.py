#!/usr/bin/env python3
"""Collect app-platform release-certification smoke evidence.

The smoke runner keeps its self-test Python-only and offline.  Normal runs can
optionally invoke Gradle and the installed ``crypta-app`` launcher to validate
first-party staged apps, sample app packaging, signed bundles, signed catalogs,
app-owned static UI, and legacy-admin retirement state.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import hashlib
import html.parser
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


TOOL_NAME = "app-platform-smoke"
SCHEMA_VERSION = 1
MODES = ("pr", "nightly", "release-candidate")
DEFAULT_OUT_DIR = Path("build/release-certification/app-platform-smoke")
SUMMARY_FILE_NAME = "summary.json"
REPORT_FILE_NAME = "app-platform-smoke-report.md"
APP_IDS = ("queue-manager", "publisher", "site-publisher")
LEGACY_REMOVAL_WAVE_ONE_IDS = (
    "queue-downloads",
    "queue-uploads",
    "file-insert",
    "local-file-insert",
    "friends",
    "add-friend",
    "strangers",
    "connectivity",
)
APP_UI_DESIGN_SYSTEM_DOC = Path("docs/app-ui-design-system.md")
APP_VAULT_DOC = Path("docs/app-secret-and-identity-vault.md")
APP_VAULT_CAPABILITIES = (
    "vault.secrets.read",
    "vault.secrets.write",
    "vault.identities.read",
    "vault.identities.create",
    "vault.identities.use",
    "vault.identities.manage",
)
SECRET_COMMAND_VALUE_OPTIONS = {
    "--private-key-base64",
    "--private-key-file",
    "--reviewer-private-key-base64",
    "--reviewer-private-key-file",
    "--trusted-public-key-base64",
}
SENSITIVE_KEY_PATTERN = (
    r"CRYPTAD_APP_TOKEN|formPassword|browserSessionToken|X-Crypta-App-Session|"
    r"authorization|cookie|set-cookie|private[-_ ]?key|token|password|passwd|secret|credential|"
    r"identity[-_ ]?seed|recovery[-_ ]?phrase|mnemonic"
)
SENSITIVE_RE = re.compile(
    rf"({SENSITIVE_KEY_PATTERN})",
    re.IGNORECASE,
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:Authorization|Cookie|Set-Cookie|X-Crypta-App-Session)\s*:\s*)"
    r"(?P<value>[^\r\n]*)",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9_])(?P<key_quote>[\"']?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P=key_quote)\s*[:=]\s*)"
    r"(?:(?P<value_quote>[\"'])(?P<quoted_value>[^\"'\r\n]*)(?P=value_quote)|"
    r"(?P<value>(?:(?:Bearer|Basic|Digest)\s+)?[^\s,;&}\]]+))",
    re.IGNORECASE,
)
URI_KEY_RE = re.compile(r"\b(?:CHK|SSK|USK)@[^\s\])},;\"']+")
ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:/.\->])/(?:[A-Za-z0-9._ -]+/)+[A-Za-z0-9._ -]+")
WINDOWS_DRIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:[A-Za-z]:[\\/](?:[^\\/:*?\"<>|\r\n]+[\\/])*[^\\/:*?\"<>|\r\n]+[\\/]?)"
)
WINDOWS_UNC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])(?:\\\\[^\\/:*?\"<>|\r\n]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*\\?)"
)
FILE_URI_PATH_RE = re.compile(r"\bfile://(?P<path>[^\s\])},;\"']+)")
ROUTE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.\->])/(?:api/v1|apps|app/node|\.well-known)(?:/[^\s\])},;\"'?]*)?"
)
NON_SECRET_METADATA_SUFFIXES = (
    "available",
    "configured",
    "enabled",
    "excluded",
    "present",
    "redacted",
    "required",
    "source",
)


@dataclasses.dataclass(frozen=True)
class Settings:
    workspace_root: Path
    out_dir: Path
    mode: str
    skip_gradle: bool
    cli_path: Path | None
    live: bool
    live_base_url: str
    live_form_password: str
    timeout_seconds: int


@dataclasses.dataclass(frozen=True)
class CommandResult:
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclasses.dataclass(frozen=True)
class EvidenceItem:
    id: str
    status: str
    required_for_release_candidate: bool
    summary: str
    source: str
    details: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "requiredForReleaseCandidate": self.required_for_release_candidate,
            "summary": self.summary,
            "source": self.source,
            "details": self.details,
        }


class ScriptExtractor(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        values = dict(attrs)
        src = values.get("src")
        if src:
            self.scripts.append(src)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def path_prefix_variants(path: Path | str) -> list[str]:
    variants: list[str] = []
    for candidate in (Path(path), Path(path).resolve()):
        candidate_text = str(candidate)
        for value in (candidate_text, candidate_text.replace("\\", "/")):
            normalized = value.rstrip("/\\")
            if normalized and normalized not in variants:
                variants.append(normalized)
    return variants


def display_path(path: Path | str, workspace_root: Path, out_dir: Path | None = None) -> str:
    raw = str(path)
    if not raw:
        return ""
    candidate = Path(raw)
    if not candidate.is_absolute():
        return raw.replace("\\", "/")
    try:
        return "<repo>/" + candidate.resolve().relative_to(workspace_root.resolve()).as_posix()
    except ValueError:
        pass
    if out_dir is not None:
        try:
            relative = candidate.resolve().relative_to(out_dir.resolve())
            out_dir_display = display_path(out_dir, workspace_root)
            if not relative.parts:
                return out_dir_display
            return f"{out_dir_display}/{relative.as_posix()}"
        except ValueError:
            pass
    try:
        return "<workdir>/" + candidate.resolve().relative_to(Path(tempfile.gettempdir()).resolve()).as_posix()
    except ValueError:
        return "<path>/" + candidate.name


def summary_source(settings: Settings) -> str:
    return display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir)


def replace_absolute_path_prefix(text: str, prefix: str, replacement: str) -> str:
    if not prefix or prefix in {"/", "\\"}:
        return text
    normalized = prefix.rstrip("/\\")
    if not normalized:
        return text
    pattern = re.compile(rf"(?<![A-Za-z0-9_:/.\->]){re.escape(normalized)}(?=$|[/\\])")
    return pattern.sub(replacement, text)


def path_leaf(path_text: str) -> str:
    stripped = path_text.rstrip("\\/")
    leaf = re.split(r"[\\/]+", stripped)[-1]
    return leaf or "path"


def scrub_absolute_path_match(match: re.Match[str]) -> str:
    return "<path>/" + path_leaf(match.group(0))


def scrub_file_uri_match(match: re.Match[str]) -> str:
    return "file://<path>/" + path_leaf(match.group("path"))


def scrub_sensitive_assignment_match(match: re.Match[str]) -> str:
    if not should_redact_key_name(match.group("key")):
        return match.group(0)
    value_quote = match.group("value_quote") or ""
    return match.group("prefix") + value_quote + "<redacted>" + value_quote


def protect_route_paths(text: str) -> tuple[str, list[tuple[str, str]]]:
    routes: list[tuple[str, str]] = []

    def replace_route(match: re.Match[str]) -> str:
        token = f"__CRYPTAD_ROUTE_{len(routes)}__"
        routes.append((token, match.group(0)))
        return token

    return ROUTE_PATH_RE.sub(replace_route, text), routes


def restore_route_paths(text: str, routes: list[tuple[str, str]]) -> str:
    restored = text
    for token, route in routes:
        restored = restored.replace(token, route)
    return restored


def normalize_redacted_separators(text: str) -> str:
    def normalize_match(match: re.Match[str]) -> str:
        return match.group("prefix") + match.group("tail").replace("\\", "/")

    return re.sub(
        r"(?P<prefix><(?:repo|home|workdir|path)>)(?P<tail>(?:[\\/][^\s\])},;\"']*)?)",
        normalize_match,
        text,
    )


def scrub_text(text: str, workspace_root: Path) -> str:
    redacted = SENSITIVE_HEADER_RE.sub(lambda match: match.group("prefix") + "<redacted>", text)
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(scrub_sensitive_assignment_match, redacted)
    redacted = URI_KEY_RE.sub("<redacted-uri>", redacted)
    redacted = FILE_URI_PATH_RE.sub(scrub_file_uri_match, redacted)
    redacted, protected_routes = protect_route_paths(redacted)
    for root_text in path_prefix_variants(workspace_root):
        redacted = replace_absolute_path_prefix(redacted, root_text, "<repo>")
    home = str(Path.home())
    if home and home != "/":
        redacted = replace_absolute_path_prefix(redacted, home, "<home>")
    redacted = replace_absolute_path_prefix(redacted, tempfile.gettempdir(), "<workdir>")
    redacted = WINDOWS_UNC_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = WINDOWS_DRIVE_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = ABSOLUTE_PATH_RE.sub(scrub_absolute_path_match, redacted)
    redacted = normalize_redacted_separators(redacted)
    return restore_route_paths(redacted, protected_routes)


def normalize_key_name(key_hint: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key_hint.lower())


def should_redact_key_name(key_hint: str) -> bool:
    normalized = normalize_key_name(key_hint)
    if not normalized:
        return False
    if normalized.endswith(NON_SECRET_METADATA_SUFFIXES):
        return False
    if normalized in {
        "authorization",
        "cookie",
        "setcookie",
        "credential",
        "cryptadapptoken",
        "formpassword",
        "privatekey",
        "secret",
        "token",
        "password",
        "passwd",
        "identityseed",
        "recoveryphrase",
        "mnemonic",
        "seed",
        "browsersessiontoken",
        "xcryptaappsession",
    }:
        return True
    return any(
        fragment in normalized
        for fragment in (
            "privatekey",
            "token",
            "password",
            "passwd",
            "secret",
            "credential",
            "seedphrase",
            "recoveryphrase",
            "mnemonic",
        )
    )


def sanitize_value(value: Any, workspace_root: Path, key_hint: str = "") -> Any:
    if should_redact_key_name(key_hint):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(key): sanitize_value(child, workspace_root, str(key)) for key, child in value.items()}
    if isinstance(value, list):
        return [sanitize_value(child, workspace_root, key_hint) for child in value]
    if isinstance(value, str):
        return scrub_text(value, workspace_root)
    return value


def is_local_live_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def live_base_url_details(base_url: str) -> dict[str, Any]:
    if not base_url:
        return {"baseUrl": "missing", "localhostOnly": False}
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or ""
    if not is_local_live_host(host):
        return {"baseUrl": "<redacted-remote-url>", "localhostOnly": False}
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    scheme = parsed.scheme or "http"
    return {"baseUrl": f"{scheme}://{netloc}", "localhostOnly": True}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def parse_properties(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected key=value")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"{path}:{line_number}: blank property key")
        if key in result:
            raise ValueError(f"{path}:{line_number}: duplicate property key: {key}")
        result[key] = value.strip()
    return result


def parse_permission_set(raw_permissions: str) -> set[str]:
    return {
        permission.strip()
        for permission in raw_permissions.split(",")
        if permission.strip()
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(
    args: list[str],
    settings: Settings,
    log_name: str,
    timeout_seconds: int | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    logs_dir = settings.out_dir / "artifacts" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        completed = subprocess.run(
            args,
            cwd=str(settings.workspace_root),
            env=merged_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds or settings.timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr if isinstance(exc.stderr, str) else "") + "\nCommand timed out."
    except OSError as exc:
        exit_code = 127
        stdout = ""
        stderr = str(exc)
    duration_ms = int((time.monotonic() - started) * 1000)
    result = CommandResult(args=args, exit_code=exit_code, stdout=stdout, stderr=stderr, duration_ms=duration_ms)
    write_text(logs_dir / f"{log_name}.stdout.log", scrub_text(stdout, settings.workspace_root))
    write_text(logs_dir / f"{log_name}.stderr.log", scrub_text(stderr, settings.workspace_root))
    return result


def gradle_command(settings: Settings, tasks: list[str], log_name: str) -> CommandResult | None:
    if settings.skip_gradle:
        return None
    wrapper = settings.workspace_root / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
    return run_command([str(wrapper), *tasks], settings, log_name, timeout_seconds=1200)


def command_ok(result: CommandResult | None) -> bool:
    return result is None or result.exit_code == 0


def command_details(result: CommandResult | None, settings: Settings) -> dict[str, Any]:
    if result is None:
        return {"skipped": True, "reason": "Gradle execution was skipped by configuration."}
    return {
        "exitCode": result.exit_code,
        "durationMs": result.duration_ms,
        "command": redact_command(result.args, settings),
    }


def redact_command(args: list[str], settings: Settings) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        if arg in SECRET_COMMAND_VALUE_OPTIONS:
            redacted.append(arg)
            skip_next = True
        elif "private" in arg.lower() and "key" in arg.lower() and "=" in arg:
            key, _ = arg.split("=", 1)
            redacted.append(key + "=<redacted>")
        else:
            redacted.append(scrub_text(arg, settings.workspace_root))
    return redacted


def root_consequence(settings: Settings, release_candidate_status: str, non_rc_status: str = "warn") -> str:
    return release_candidate_status if settings.mode == "release-candidate" else non_rc_status


def first_party_app_specs(settings: Settings) -> list[dict[str, Any]]:
    return [
        {
            "appId": "queue-manager",
            "name": "Queue Manager",
            "stagedDir": settings.workspace_root / "apps/queue-manager/build/cryptad-app/queue-manager",
            "sourceDir": settings.workspace_root / "apps/queue-manager/src/staged",
            "launcher": "bin/queue-manager.sh",
            "permissions": {"queue.read", "queue.write"},
        },
        {
            "appId": "publisher",
            "name": "Publisher",
            "stagedDir": settings.workspace_root / "apps/publisher/build/cryptad-app/publisher",
            "sourceDir": settings.workspace_root / "apps/publisher/src/staged",
            "launcher": "bin/publisher.sh",
            "permissions": {"queue.read", "queue.write", "content.insert"},
        },
        {
            "appId": "site-publisher",
            "name": "Site Publisher",
            "stagedDir": (
                settings.workspace_root
                / "apps/site-publisher/build/cryptad-app/site-publisher"
            ),
            "sourceDir": settings.workspace_root / "apps/site-publisher/src/staged",
            "launcher": "bin/site-publisher.sh",
            "permissions": {"queue.read", "queue.write", "content.insert"},
            "apiMinimumVersion": 3,
            "apiMaximumTestedVersion": 3,
        },
    ]


def validate_app_bundle(bundle_dir: Path, spec: dict[str, Any], settings: Settings) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {"bundleDir": display_path(bundle_dir, settings.workspace_root)}
    manifest_path = bundle_dir / "cryptad-app.properties"
    if not manifest_path.is_file():
        errors.append("cryptad-app.properties is missing")
        return False, errors, details
    try:
        manifest = parse_properties(manifest_path)
    except ValueError as exc:
        errors.append(str(exc))
        return False, errors, details
    details["manifest"] = {
        "appId": manifest.get("app.id"),
        "name": manifest.get("app.name"),
        "version": manifest.get("app.version"),
        "uiMode": manifest.get("app.ui.mode"),
        "uiEntry": manifest.get("app.ui.entry"),
        "permissions": sorted(parse_permission_set(manifest.get("app.permissions", ""))),
        "apiMinimumVersion": manifest.get("api.minimumVersion"),
        "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
    }
    for key in ("app.id", "app.name", "app.version"):
        if not manifest.get(key):
            errors.append(f"{key} is missing")
    if manifest.get("app.id") != spec["appId"]:
        errors.append(f"app.id expected {spec['appId']}, got {manifest.get('app.id')}")
    if manifest.get("app.name") != spec["name"]:
        errors.append(f"app.name expected {spec['name']}, got {manifest.get('app.name')}")
    if manifest.get("app.ui.mode") != "static":
        errors.append("app.ui.mode must be static")
    if manifest.get("app.ui.entry") != "static/index.html":
        errors.append("app.ui.entry must be static/index.html")
    declared_permissions = parse_permission_set(manifest.get("app.permissions", ""))
    if not spec["permissions"].issubset(declared_permissions):
        errors.append("manifest permissions are incomplete")
    if "apiMinimumVersion" in spec and manifest.get("api.minimumVersion") != str(
        spec["apiMinimumVersion"]
    ):
        errors.append("api.minimumVersion does not match expected first-party metadata")
    if "apiMaximumTestedVersion" in spec and manifest.get("api.maximumTestedVersion") != str(
        spec["apiMaximumTestedVersion"]
    ):
        errors.append("api.maximumTestedVersion does not match expected first-party metadata")
    for relative in (spec["launcher"], "static/index.html", "static/app.js", "static/app.css", "static/crypta-platform.js"):
        if not (bundle_dir / relative).is_file():
            errors.append(f"{relative} is missing")
    static_errors, static_details = validate_static_ui_files(bundle_dir / "static", settings)
    errors.extend(static_errors)
    details.update(static_details)
    return not errors, errors, details


def validate_static_ui_files(static_dir: Path, settings: Settings) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {}
    index = static_dir / "index.html"
    app_js = static_dir / "app.js"
    sdk = static_dir / "crypta-platform.js"
    if index.is_file():
        scripts = extract_scripts(index)
        normalized_scripts = [normalize_static_script_ref(script) for script in scripts]
        details["scripts"] = scripts
        if "crypta-platform.js" not in normalized_scripts:
            errors.append("index.html does not load crypta-platform.js")
        if "app.js" in normalized_scripts and "crypta-platform.js" in normalized_scripts:
            if normalized_scripts.index("crypta-platform.js") > normalized_scripts.index("app.js"):
                errors.append("index.html must load crypta-platform.js before app.js")
    if app_js.is_file():
        app_text = app_js.read_text(encoding="utf-8")
        if ".bootstrap.load" not in app_text:
            errors.append("app.js does not call CryptaPlatform.bootstrap.load")
    if sdk.is_file():
        sdk_text = sdk.read_text(encoding="utf-8")
        if "window.CryptaPlatform" not in sdk_text:
            errors.append("crypta-platform.js does not expose window.CryptaPlatform")
        if "X-Crypta-App-Session" not in sdk_text:
            errors.append("crypta-platform.js does not use X-Crypta-App-Session")
    for file_path in static_dir.glob("**/*"):
        if not file_path.is_file():
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        for forbidden in ("CRYPTAD_APP_TOKEN", "formPassword", "localStorage.setItem", "sessionStorage.setItem"):
            if forbidden in text:
                errors.append(f"{display_path(file_path, settings.workspace_root)} contains forbidden text {forbidden}")
    canonical_sdk = settings.workspace_root / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    if sdk.is_file() and canonical_sdk.is_file():
        details["sdkMatchesCanonical"] = sha256_file(sdk) == sha256_file(canonical_sdk)
        if not details["sdkMatchesCanonical"]:
            errors.append("staged SDK does not match canonical SDK resource")
    return errors, details


def normalize_static_script_ref(script: str) -> str:
    value = script.split("?", 1)[0].split("#", 1)[0]
    while value.startswith("./"):
        value = value[2:]
    return value


def extract_scripts(path: Path) -> list[str]:
    parser = ScriptExtractor()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.scripts


def check_source_static_ui(settings: Settings) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        static_dir = spec["sourceDir"] / "static"
        app_errors, app_details = validate_static_ui_files(static_dir, settings)
        errors.extend(f"{spec['appId']}: {error}" for error in app_errors)
        details[spec["appId"]] = app_details
    sdk_path = settings.workspace_root / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    if not sdk_path.is_file():
        errors.append("canonical SDK resource is missing")
    else:
        details["sdkResource"] = display_path(sdk_path, settings.workspace_root)
    return not errors, errors, details


def find_cli(settings: Settings) -> Path | None:
    if settings.cli_path is not None:
        return settings.cli_path
    script = "crypta-app.bat" if platform.system() == "Windows" else "crypta-app"
    candidate = settings.workspace_root / "platform-devtools/build/install/crypta-app/bin" / script
    if candidate.is_file():
        return candidate
    return None


def run_cli(cli: Path, args: list[str], settings: Settings, log_name: str) -> CommandResult:
    return run_command([str(cli), *args], settings, log_name, timeout_seconds=180)


def remove_existing_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def write_live_smoke_launcher(sample_dir: Path) -> None:
    launcher = sample_dir / "bin/start.sh"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(
        """#!/usr/bin/env sh
set -eu

child=""
cleanup() {
  if [ -n "$child" ]; then
    kill "$child" 2>/dev/null || true
  fi
  exit 0
}

trap cleanup INT TERM

while :; do
  sleep 60 &
  child="$!"
  wait "$child" 2>/dev/null || true
  child=""
done
""",
        encoding="utf-8",
    )
    launcher.chmod(0o755)


def signing_inputs(env: dict[str, str]) -> dict[str, Any]:
    key_id = env.get("CRYPTAD_APP_SIGNING_KEY_ID", "").strip()
    private_file = env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", "").strip()
    private_base64 = env.get("CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64", "").strip()
    public_file = env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE", "").strip()
    public_base64 = env.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "").strip()
    return {
        "keyId": key_id,
        "privateFile": private_file,
        "privateBase64": bool(private_base64),
        "publicFile": public_file,
        "publicBase64": bool(public_base64),
        "hasPrivate": bool(private_file or private_base64),
        "hasPublic": bool(public_file or public_base64),
        "complete": bool(key_id and (private_file or private_base64) and (public_file or public_base64)),
    }


def reviewer_inputs(env: dict[str, str]) -> dict[str, Any]:
    key_id = env.get("CRYPTAD_APP_REVIEWER_KEY_ID", "").strip()
    private_file = env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", "").strip()
    private_base64 = env.get("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64", "").strip()
    public_file = env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE", "").strip()
    public_base64 = env.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", "").strip()
    policy_id = env.get("CRYPTAD_APP_REVIEW_POLICY_ID", "crypta-app-review-v1").strip()
    policy_version = env.get("CRYPTAD_APP_REVIEW_POLICY_VERSION", "1").strip()
    return {
        "keyId": key_id,
        "privateFile": private_file,
        "privateBase64": bool(private_base64),
        "publicFile": public_file,
        "publicBase64": bool(public_base64),
        "policyId": policy_id,
        "policyVersion": policy_version,
        "hasPrivate": bool(private_file or private_base64),
        "hasPublic": bool(public_file or public_base64),
        "complete": bool(key_id and policy_id and policy_version and (private_file or private_base64) and (public_file or public_base64)),
    }


def sign_args(bundle_dir: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["sign", "--bundle-dir", str(bundle_dir), "--key-id", inputs["keyId"]]
    if inputs["privateFile"]:
        args.extend(["--private-key-file", inputs["privateFile"]])
    else:
        args.extend(["--private-key-env", "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"])
    return args


def verify_args(bundle_dir: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["verify", "--bundle-dir", str(bundle_dir), "--trusted-key-id", inputs["keyId"]]
    if inputs["publicFile"]:
        args.extend(["--trusted-public-key-file", inputs["publicFile"]])
    else:
        args.extend(["--trusted-public-key-base64", os.environ.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "")])
    return args


def catalog_sign_args(catalog_file: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["catalog", "sign", "--catalog-file", str(catalog_file), "--key-id", inputs["keyId"]]
    if inputs["privateFile"]:
        args.extend(["--private-key-file", inputs["privateFile"]])
    else:
        args.extend(["--private-key-env", "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"])
    return args


def catalog_verify_args(catalog_file: Path, inputs: dict[str, Any]) -> list[str]:
    args = ["catalog", "verify", "--catalog-file", str(catalog_file), "--trusted-key-id", inputs["keyId"]]
    if inputs["publicFile"]:
        args.extend(["--trusted-public-key-file", inputs["publicFile"]])
    else:
        args.extend(["--trusted-public-key-base64", os.environ.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "")])
    return args


def review_sign_args(descriptor: Path, receipt_file: Path, inputs: dict[str, Any]) -> list[str]:
    args = [
        "review",
        "sign",
        "--catalog-entry",
        str(descriptor),
        "--receipt-file",
        str(receipt_file),
        "--reviewer-key-id",
        inputs["keyId"],
        "--policy-id",
        inputs["policyId"],
        "--policy-version",
        inputs["policyVersion"],
        "--status",
        "reviewed",
        "--reviewed-at",
        "2026-05-01T00:00:00Z",
        "--overwrite",
    ]
    if inputs["privateFile"]:
        args.extend(["--reviewer-private-key-file", inputs["privateFile"]])
    else:
        args.extend(["--reviewer-private-key-env", "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"])
    return args


def review_verify_args(descriptor: Path, receipt_file: Path, trusted_keys_file: Path) -> list[str]:
    return [
        "review",
        "verify",
        "--catalog-entry",
        str(descriptor),
        "--receipt-file",
        str(receipt_file),
        "--trusted-reviewer-keys-file",
        str(trusted_keys_file),
    ]


def reviewer_public_key_base64(inputs: dict[str, Any]) -> str:
    if inputs["publicBase64"]:
        return "".join(os.environ.get("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", "").split())
    public_file = inputs["publicFile"]
    if not public_file:
        return ""
    raw = Path(public_file).read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    if "BEGIN PUBLIC KEY" in text:
        return "".join(
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("-----")
        )
    compact_text = compact_base64_key_text(raw)
    if compact_text:
        return compact_text
    return base64.b64encode(raw).decode("ascii")


def compact_base64_key_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    compact = "".join(text.split())
    if not compact:
        return None
    try:
        base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    return compact


def write_trusted_reviewer_keys(path: Path, inputs: dict[str, Any]) -> None:
    public_key = reviewer_public_key_base64(inputs)
    path.write_text(
        "\n".join(
            [
                "trusted.reviewers.version=1",
                f"reviewer.1.id={inputs['keyId']}",
                "reviewer.1.algorithm=Ed25519",
                f"reviewer.1.public.key.base64={public_key}",
                "reviewer.1.display.name=Certification Reviewer",
                f"reviewer.1.policy.id={inputs['policyId']}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def collect_first_party_evidence(settings: Settings, cli: Path | None) -> EvidenceItem:
    gradle_result = gradle_command(settings, ["stageFirstPartyApps"], "gradle-stage-first-party-apps")
    errors: list[str] = []
    details: dict[str, Any] = {"stageCommand": command_details(gradle_result, settings), "apps": {}}
    if gradle_result is not None and gradle_result.exit_code != 0:
        errors.append("stageFirstPartyApps failed")
    for spec in first_party_app_specs(settings):
        ok, app_errors, app_details = validate_app_bundle(spec["stagedDir"], spec, settings)
        details["apps"][spec["appId"]] = app_details
        if not ok:
            errors.extend(f"{spec['appId']}: {error}" for error in app_errors)
        if cli is not None and spec["stagedDir"].is_dir():
            result = run_cli(cli, ["validate", "--bundle-dir", str(spec["stagedDir"])], settings, f"crypta-app-validate-{spec['appId']}")
            details["apps"][spec["appId"]]["cliValidate"] = command_details(result, settings)
            if result.exit_code != 0:
                errors.append(f"crypta-app validate failed for {spec['appId']}")
    if errors:
        return EvidenceItem(
            "app-platform.first-party",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party staged app validation found problems.",
            summary_source(settings),
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.first-party",
        "pass",
        True,
        "First-party staged app manifests and static assets passed.",
        summary_source(settings),
        details,
    )


def sample_workspace(settings: Settings) -> Path:
    work_dir = settings.out_dir / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    return work_dir


def collect_cli_evidence(settings: Settings, cli: Path | None) -> tuple[EvidenceItem, dict[str, Path]]:
    details: dict[str, Any] = {}
    sample_paths: dict[str, Path] = {}
    install_result = gradle_command(settings, [":platform-devtools:installDist"], "gradle-platform-devtools-installDist")
    details["installDistCommand"] = command_details(install_result, settings)
    cli = find_cli(settings)
    if install_result is not None and install_result.exit_code != 0:
        return (
            EvidenceItem(
                "app-platform.devtools-cli",
                root_consequence(settings, "fail"),
                True,
                "platform-devtools installDist failed.",
                summary_source(settings),
                details,
            ),
            sample_paths,
        )
    if cli is None or not cli.is_file():
        return (
            EvidenceItem(
                "app-platform.devtools-cli",
                root_consequence(settings, "missing"),
                True,
                "crypta-app launcher is missing.",
                summary_source(settings),
                details,
            ),
            sample_paths,
        )
    details["cliPath"] = display_path(cli, settings.workspace_root)
    sample_dir = sample_workspace(settings) / "cert-smoke-app"
    sample_zip = sample_workspace(settings) / "cert-smoke-app-0.1.0.zip"
    remove_existing_path(sample_dir)
    init_result = run_cli(
        cli,
        [
            "init",
            "--dir",
            str(sample_dir),
            "--app-id",
            "cert-smoke",
            "--name",
            "Certification Smoke",
            "--version",
            "0.1.0",
            "--ui-mode",
            "static",
            "--permission",
            "queue.read",
            "--overwrite",
        ],
        settings,
        "crypta-app-init-sample",
    )
    launcher_error = ""
    if init_result.exit_code == 0:
        try:
            write_live_smoke_launcher(sample_dir)
        except OSError as exc:
            launcher_error = scrub_text(str(exc), settings.workspace_root)
    validate_result = run_cli(cli, ["validate", "--bundle-dir", str(sample_dir)], settings, "crypta-app-validate-sample")
    remove_existing_path(sample_zip)
    pack_result = run_cli(
        cli,
        ["pack", "--bundle-dir", str(sample_dir), "--output", str(sample_zip), "--overwrite"],
        settings,
        "crypta-app-pack-sample",
    )
    details["sample"] = {
        "appId": "cert-smoke",
        "bundleDir": display_path(sample_dir, settings.workspace_root),
        "zip": display_path(sample_zip, settings.workspace_root),
        "init": command_details(init_result, settings),
        "launcherRewritten": not launcher_error and init_result.exit_code == 0,
        "validate": command_details(validate_result, settings),
        "pack": command_details(pack_result, settings),
    }
    if launcher_error:
        details["sample"]["launcherError"] = launcher_error
    sample_paths.update({"bundleDir": sample_dir, "zip": sample_zip, "cli": cli})
    pack_output_exists = sample_zip.is_file()
    details["sample"]["zipExists"] = pack_output_exists
    if pack_output_exists:
        details["sample"]["zipSha256"] = sha256_file(sample_zip)
        details["sample"]["zipSizeBytes"] = sample_zip.stat().st_size
    failed = [name for name, result in (("init", init_result), ("validate", validate_result), ("pack", pack_result)) if result.exit_code != 0]
    if launcher_error:
        failed.append("launcher")
    if pack_result.exit_code == 0 and not pack_output_exists:
        failed.append("pack-output")
    if failed:
        return (
            EvidenceItem(
                "app-platform.devtools-cli",
                root_consequence(settings, "fail"),
                True,
                "crypta-app sample init, validate, or pack failed.",
                summary_source(settings),
                {"failedSteps": failed, **details},
            ),
            sample_paths,
        )
    return (
        EvidenceItem(
            "app-platform.devtools-cli",
            "pass",
            True,
            "crypta-app init, validate, and pack passed.",
            summary_source(settings),
            details,
        ),
        sample_paths,
    )


def stable_capability_names(capabilities: list[Any]) -> list[str]:
    names: list[str] = []
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if name and name not in names:
            names.append(name)
    return sorted(names)


def stable_endpoint_identities(endpoints: list[Any]) -> list[str]:
    identities: list[str] = []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stability", "unknown")).lower() != "stable":
            continue
        route = str(entry.get("routeTemplate") or entry.get("path") or entry.get("route") or "").strip()
        if not route:
            continue
        method = str(entry.get("method", "")).strip().upper()
        identity = f"{method} {route}" if method else route
        if identity not in identities:
            identities.append(identity)
    return sorted(identities)


def collect_platform_api_contract_evidence(
    settings: Settings, cli: Path | None, sample_paths: dict[str, Path]
) -> EvidenceItem:
    source = summary_source(settings)
    artifact = settings.out_dir / "artifacts" / "platform-api-contract.json"
    details: dict[str, Any] = {"artifactPath": display_path(artifact, settings.workspace_root, settings.out_dir)}
    if cli is None or not cli.is_file():
        return EvidenceItem(
            "platform-api.contract",
            root_consequence(settings, "missing"),
            True,
            "crypta-app CLI is unavailable for Platform API contract evidence.",
            source,
            details,
        )

    snapshot_result = run_cli(
        cli,
        ["api", "snapshot", "--output", str(artifact)],
        settings,
        "crypta-app-api-snapshot",
    )
    details["snapshotCommand"] = command_details(snapshot_result, settings)
    errors: list[str] = []
    if snapshot_result.exit_code != 0:
        errors.append("contract snapshot generation failed")
    if not artifact.is_file():
        errors.append("contract snapshot file was not written")

    contract: dict[str, Any] = {}
    if artifact.is_file():
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            contract = payload.get("contract", payload) if isinstance(payload, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"contract snapshot is not valid JSON: {exc}")

    capabilities = contract.get("capabilities", []) if isinstance(contract, dict) else []
    endpoints = contract.get("endpoints", []) if isinstance(contract, dict) else []
    if not isinstance(capabilities, list):
        errors.append("contract capabilities must be a list")
        capabilities = []
    if not isinstance(endpoints, list):
        errors.append("contract endpoints must be a list")
        endpoints = []
    stability_counts: dict[str, int] = {}
    flagged: list[str] = []
    for collection_name, entries in (("capability", capabilities), ("endpoint", endpoints)):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            stability = str(entry.get("stability", "unknown"))
            stability_counts[stability] = stability_counts.get(stability, 0) + 1
            if stability != "stable":
                flagged.append(f"{collection_name}:{entry.get('name') or entry.get('routeTemplate')}:{stability}")
    contract_version = contract.get("contractVersion") if isinstance(contract, dict) else None
    api_version = contract.get("apiVersion") if isinstance(contract, dict) else None
    details["contractVersion"] = contract_version
    details["apiVersion"] = api_version
    details["capabilityCount"] = len(capabilities)
    details["endpointCount"] = len(endpoints)
    details["stableCapabilities"] = stable_capability_names(capabilities)
    details["stableEndpoints"] = stable_endpoint_identities(endpoints)
    details["stabilityCounts"] = stability_counts
    details["flaggedStability"] = flagged
    if contract:
        if not isinstance(contract_version, int) or isinstance(contract_version, bool) or contract_version <= 0:
            errors.append("contractVersion must be a positive integer")
        if not isinstance(api_version, str) or not api_version.strip():
            errors.append("apiVersion must be a non-empty string")
    if not capabilities:
        errors.append("contract has no capability descriptors")
    if not endpoints:
        errors.append("contract has no endpoint descriptors")

    verifier_args = ["compat", "verify"]
    if settings.mode == "release-candidate":
        verifier_args.append("--strict")
    verifier_args.extend(["--contract", str(artifact)])
    verification: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        staged_dir = spec["stagedDir"]
        if staged_dir.is_dir():
            result = run_cli(
                cli,
                [*verifier_args, "--bundle-dir", str(staged_dir)],
                settings,
                f"crypta-app-compat-{spec['appId']}",
            )
            verification[spec["appId"]] = command_details(result, settings)
            if result.exit_code != 0:
                errors.append(f"compat verify failed for {spec['appId']}")
        else:
            verification[spec["appId"]] = {"skipped": True, "reason": "staged app directory missing"}
    sample_dir = sample_paths.get("bundleDir")
    if sample_dir is not None and sample_dir.is_dir():
        result = run_cli(
            cli,
            [*verifier_args, "--bundle-dir", str(sample_dir)],
            settings,
            "crypta-app-compat-sample",
        )
        verification["cert-smoke"] = command_details(result, settings)
        if result.exit_code != 0:
            errors.append("compat verify failed for cert-smoke")
    details["verifier"] = verification

    if errors:
        return EvidenceItem(
            "platform-api.contract",
            root_consequence(settings, "fail"),
            True,
            "Platform API contract evidence found compatibility risks.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "platform-api.contract",
        "pass",
        True,
        "Platform API contract snapshot and offline compatibility checks passed.",
        source,
        details,
    )


def collect_signed_bundle_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    inputs = signing_inputs(os.environ)
    details: dict[str, Any] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
        "privateKeySource": "file" if inputs["privateFile"] else ("environment" if inputs["privateBase64"] else "missing"),
        "publicKeySource": "file" if inputs["publicFile"] else ("environment" if inputs["publicBase64"] else "missing"),
    }
    source = summary_source(settings)
    if not inputs["complete"]:
        status = "fail" if settings.mode == "release-candidate" else "skip"
        return EvidenceItem(
            "app-platform.signed-bundles",
            status,
            True,
            "Signing key inputs are not complete; signed bundle verification was not run.",
            source,
            details,
        )
    gradle_result = gradle_command(settings, ["signFirstPartyApps", "verifyFirstPartyApps"], "gradle-sign-verify-first-party-apps")
    details["firstPartySignVerifyCommand"] = command_details(gradle_result, settings)
    failures: list[str] = []
    if gradle_result is None:
        details["firstPartySignVerifyRan"] = False
        if settings.mode == "release-candidate":
            failures.append("first-party sign/verify Gradle task was skipped")
    elif gradle_result.exit_code != 0:
        details["firstPartySignVerifyRan"] = True
        failures.append("first-party sign/verify Gradle task failed")
    else:
        details["firstPartySignVerifyRan"] = True
    cli = sample_paths.get("cli")
    sample_dir = sample_paths.get("bundleDir")
    if cli and sample_dir and sample_dir.is_dir():
        sign_result = run_cli(cli, sign_args(sample_dir, inputs), settings, "crypta-app-sign-sample")
        verify_result = run_cli(cli, verify_args(sample_dir, inputs), settings, "crypta-app-verify-sample")
        details["sampleSign"] = command_details(sign_result, settings)
        details["sampleVerify"] = command_details(verify_result, settings)
        if sign_result.exit_code != 0:
            failures.append("sample bundle sign failed")
        if verify_result.exit_code != 0:
            failures.append("sample bundle verify failed")
        sample_zip = sample_paths.get("zip")
        if sample_zip and sign_result.exit_code == 0 and verify_result.exit_code == 0:
            repack_result = run_cli(
                cli,
                ["pack", "--bundle-dir", str(sample_dir), "--output", str(sample_zip), "--overwrite"],
                settings,
                "crypta-app-pack-signed-sample",
            )
            details["sampleRepackAfterSigning"] = command_details(repack_result, settings)
            if repack_result.exit_code != 0:
                failures.append("signed sample bundle repack failed")
            elif sample_zip.is_file():
                details["signedSampleZipSha256"] = sha256_file(sample_zip)
                details["signedSampleZipSizeBytes"] = sample_zip.stat().st_size
    else:
        failures.append("sample bundle was unavailable for signing")
    if failures:
        return EvidenceItem(
            "app-platform.signed-bundles",
            "fail",
            True,
            "Signed bundle smoke failed.",
            source,
            {"failures": failures, **details},
        )
    return EvidenceItem(
        "app-platform.signed-bundles",
        "pass",
        True,
        "First-party and sample bundle signing evidence passed.",
        source,
        details,
    )


def collect_catalog_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    cli = sample_paths.get("cli")
    sample_zip = sample_paths.get("zip")
    details: dict[str, Any] = {}
    if not cli or not sample_zip or not sample_zip.is_file():
        return EvidenceItem("catalog.smoke", root_consequence(settings, "missing"), True, "Sample ZIP or crypta-app CLI is unavailable for catalog smoke.", source, details)
    catalog_dir = sample_workspace(settings) / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    descriptor = catalog_dir / "entry.properties"
    catalog_file = catalog_dir / "cryptad-app-catalog.properties"
    signature_file = catalog_dir / "cryptad-app-catalog.signature"
    descriptor.write_text(
        "\n".join(
            [
                f"artifact.path={sample_zip.resolve()}",
                f"bundle.uri={sample_zip.resolve().as_uri()}",
                "summary=Certification smoke app.",
                "name=Certification Smoke",
                "permissions=queue.read",
                "app.id=cert-smoke",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    remove_existing_path(catalog_file)
    remove_existing_path(signature_file)
    create_result = run_cli(
        cli,
        [
            "catalog",
            "create",
            "--catalog-file",
            str(catalog_file),
            "--catalog-id",
            "cert-smoke",
            "--name",
            "Certification Smoke Apps",
            "--generated-at",
            "2026-05-01T00:00:00Z",
            "--entry",
            str(descriptor),
            "--overwrite",
        ],
        settings,
        "crypta-app-catalog-create",
    )
    details["create"] = command_details(create_result, settings)
    if create_result.exit_code != 0:
        return EvidenceItem("catalog.smoke", root_consequence(settings, "fail"), True, "Catalog creation failed.", source, details)
    catalog_exists = catalog_file.is_file()
    details["catalogExists"] = catalog_exists
    if not catalog_exists:
        return EvidenceItem(
            "catalog.smoke",
            root_consequence(settings, "fail"),
            True,
            "Catalog creation did not produce catalog output.",
            source,
            details,
        )
    catalog = parse_properties(catalog_file)
    details["catalog"] = {
        "catalogId": catalog.get("catalog.id"),
        "catalogVersion": catalog.get("catalog.version"),
        "entries": catalog.get("catalog.entries"),
        "appId": catalog.get("app.cert-smoke.id"),
        "bundleSha256": catalog.get("app.cert-smoke.bundle.sha256"),
        "bundleSizeBytes": catalog.get("app.cert-smoke.bundle.size.bytes"),
        "catalogSha256": sha256_file(catalog_file),
    }
    inputs = signing_inputs(os.environ)
    details["signingInputs"] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
    }
    if not inputs["complete"]:
        status = "fail" if settings.mode == "release-candidate" else "warn"
        return EvidenceItem(
            "catalog.smoke",
            status,
            True,
            "Catalog creation passed, but signing key inputs are incomplete.",
            source,
            details,
        )
    sign_result = run_cli(cli, catalog_sign_args(catalog_file, inputs), settings, "crypta-app-catalog-sign")
    verify_result = run_cli(cli, catalog_verify_args(catalog_file, inputs), settings, "crypta-app-catalog-verify")
    details["sign"] = command_details(sign_result, settings)
    details["verify"] = command_details(verify_result, settings)
    if sign_result.exit_code != 0 or verify_result.exit_code != 0:
        return EvidenceItem("catalog.smoke", "fail", True, "Signed catalog smoke failed.", source, details)
    return EvidenceItem("catalog.smoke", "pass", True, "Catalog create, sign, and verify smoke passed.", source, details)


def collect_app_review_receipt_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    verifier_text = read_source(appcatalog_dir / "AppReviewReceiptVerifier.java")
    receipt_text = read_source(appcatalog_dir / "AppReviewReceipt.java")
    payload_text = read_source(appcatalog_dir / "AppReviewReceiptPayload.java")
    io_text = read_source(appcatalog_dir / "AppReviewReceiptIO.java")
    keys_text = read_source(appcatalog_dir / "TrustedReviewerKeys.java")
    cli_text = read_source(settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java")
    checks = {
        "canonicalPayloadExcludesSignature": (
            "canonicalPayloadBytes" in payload_text
            and "review.receipt.signature.value.base64" not in payload_text
        ),
        "receiptSignatureIndependent": (
            "Signature.getInstance(receipt.signature().algorithm())" in verifier_text
            and "receipt.payload().canonicalPayloadBytes()" in verifier_text
        ),
        "bindingChecks": (
            "receipt.mismatchStatus(" in verifier_text
            and "binding.appId()" in verifier_text
            and "binding.version()" in verifier_text
            and "binding.artifactSha256()" in verifier_text
            and "binding.artifactSizeBytes()" in verifier_text
            and "AppReviewTrustStatus.ARTIFACT_MISMATCH" in receipt_text
            and "AppReviewTrustStatus.APP_MISMATCH" in receipt_text
        ),
        "expiryAndUnknownReviewerFailClosed": (
            "AppReviewTrustStatus.EXPIRED" in verifier_text
            and "AppReviewTrustStatus.UNKNOWN_REVIEWER" in verifier_text
        ),
        "trustedReviewerRegistrySeparate": (
            "trusted.reviewers.version" in keys_text
            and "public.key.base64" in keys_text
        ),
        "parserWriterEmbedsReceipt": (
            "parseProperties" in io_text
            and "appendReceiptProperties" in io_text
            and "review.receipt.signature.value.base64" in io_text
        ),
        "devtoolsSignVerify": (
            'name = "review"' in cli_text
            and "ReviewSignCommand" in cli_text
            and "ReviewVerifyCommand" in cli_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "receiptSchemaVersion": 1,
        "signatureAlgorithm": "Ed25519",
        "checks": checks,
        "sources": {
            "verifier": display_path(appcatalog_dir / "AppReviewReceiptVerifier.java", settings.workspace_root),
            "receipt": display_path(appcatalog_dir / "AppReviewReceipt.java", settings.workspace_root),
            "payload": display_path(appcatalog_dir / "AppReviewReceiptPayload.java", settings.workspace_root),
            "receiptIo": display_path(appcatalog_dir / "AppReviewReceiptIO.java", settings.workspace_root),
            "trustedReviewerKeys": display_path(appcatalog_dir / "TrustedReviewerKeys.java", settings.workspace_root),
            "devtools": display_path(settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java", settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.trusted-receipts",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-review receipt evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.trusted-receipts",
        "pass",
        True,
        "Trusted review receipt model and offline tooling evidence passed.",
        source,
        details,
    )


def collect_app_review_policy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    api_catalogs = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    api_updates = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    policy_text = read_source(appcatalog_dir / "AppReviewPolicy.java")
    mode_text = read_source(appcatalog_dir / "AppReviewPolicyMode.java")
    decision_text = read_source(appcatalog_dir / "AppReviewTrustDecision.java")
    catalogs_text = read_source(api_catalogs)
    updates_text = read_source(api_updates)
    checks = {
        "policyModes": (
            "ADVISORY" in mode_text
            and "WARN_UNTRUSTED" in mode_text
            and "REQUIRE_TRUSTED_REVIEW" in mode_text
            and "REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED" in mode_text
        ),
        "defaultAdvisory": "AppReviewPolicyMode.ADVISORY" in policy_text,
        "decisionFlags": (
            "requiresAcknowledgement" in decision_text
            and "blocksInstall" in decision_text
            and "blocksUpdate" in decision_text
            and "blocksPolicyApply" in decision_text
        ),
        "catalogInstallUpdateGate": (
            "requireReviewGate(" in catalogs_text
            and "reviewAcknowledged" in catalogs_text
            and "app_review_missing" in catalogs_text
        ),
        "updateLifecycleGate": (
            "requireReviewGate(candidate.reviewTrust()" in updates_text
            and "eligibleForAutomaticApply()" in read_source(settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java")
            and "app_review_rejected" in updates_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "mode": "advisory default; warn/block modes operator-configured",
        "checks": checks,
        "sources": {
            "policy": display_path(appcatalog_dir / "AppReviewPolicy.java", settings.workspace_root),
            "policyMode": display_path(appcatalog_dir / "AppReviewPolicyMode.java", settings.workspace_root),
            "decision": display_path(appcatalog_dir / "AppReviewTrustDecision.java", settings.workspace_root),
            "catalogsApi": display_path(api_catalogs, settings.workspace_root),
            "updatesApi": display_path(api_updates, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem("app-review.policy", "fail" if settings.mode == "release-candidate" else "warn", True, "App-review policy evidence is incomplete.", source, {"errors": errors, **details})
    return EvidenceItem("app-review.policy", "pass", True, "App-review policy gates passed deterministic evidence checks.", source, details)


def write_first_party_review_descriptor(
    descriptor: Path,
    spec: dict[str, Any],
    manifest: dict[str, str],
    artifact_zip: Path,
) -> None:
    app_id = manifest.get("app.id", spec["appId"])
    app_name = manifest.get("app.name", spec["name"])
    permissions = ",".join(sorted(parse_permission_set(manifest.get("app.permissions", ""))))
    lines = [
        f"artifact.path={artifact_zip.resolve()}",
        f"bundle.uri={artifact_zip.resolve().as_uri()}",
        f"summary=First-party release-candidate review target for {app_name}.",
        f"name={app_name}",
        f"permissions={permissions}",
        f"app.id={app_id}",
        f"version={manifest.get('app.version', '')}",
        "review.status=reviewed",
        "review.note=First-party app review receipt required for release promotion.",
        "changelog.summary=Release certification first-party catalog evidence.",
    ]
    if manifest.get("api.minimumVersion"):
        lines.append(f"api.minimumVersion={manifest['api.minimumVersion']}")
    if manifest.get("api.maximumTestedVersion"):
        lines.append(f"api.maximumTestedVersion={manifest['api.maximumTestedVersion']}")
    if manifest.get("api.experimentalCapabilitiesAccepted"):
        lines.append(
            "api.experimentalCapabilitiesAccepted="
            + manifest["api.experimentalCapabilitiesAccepted"]
        )
    descriptor.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_app_review_first_party_catalog_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    cli = sample_paths.get("cli")
    specs = first_party_app_specs(settings)
    details: dict[str, Any] = {
        "policyMode": "release-candidate requires trusted positive receipts",
        "firstPartyApps": [spec["appId"] for spec in specs],
        "referenceContentApp": "site-publisher",
        "coverage": {
            "catalogAppsInspected": 0,
            "trustedPositiveReceipts": 0,
            "missingReceipts": len(specs),
            "expiredOrMismatchedOrUnknownReviewer": 0,
            "trustedRejectedReceipts": 0,
            "promotionBlocked": True,
        },
    }
    if not cli:
        return EvidenceItem("app-review.first-party-catalog", root_consequence(settings, "missing"), True, "crypta-app CLI is unavailable for first-party review catalog evidence.", source, details)
    inputs = reviewer_inputs(os.environ)
    details["reviewerInputs"] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
        "policyId": inputs["policyId"],
        "policyVersion": inputs["policyVersion"],
    }
    if not inputs["complete"]:
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer key inputs are incomplete; trusted first-party review receipts were not verified.",
            source,
            details,
        )
    review_dir = sample_workspace(settings) / "app-review"
    review_dir.mkdir(parents=True, exist_ok=True)
    trusted_keys_file = review_dir / "trusted-reviewers.properties"
    catalog_file = review_dir / "cryptad-app-catalog.properties"
    remove_existing_path(catalog_file)
    try:
        write_trusted_reviewer_keys(trusted_keys_file, inputs)
    except OSError as exc:
        details["trustedReviewerKeys"] = {
            "error": scrub_text(str(exc), settings.workspace_root)
        }
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer public key material could not be read for app-review catalog evidence.",
            source,
            details,
        )

    failures: list[str] = []
    entry_files: list[Path] = []
    receipt_files: list[Path] = []
    details["apps"] = {}
    for spec in specs:
        app_id = spec["appId"]
        app_details: dict[str, Any] = {
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
        details["apps"][app_id] = app_details
        manifest_path = spec["stagedDir"] / "cryptad-app.properties"
        if not manifest_path.is_file():
            failures.append(f"{app_id}: staged manifest is missing")
            continue
        try:
            manifest = parse_properties(manifest_path)
        except ValueError as exc:
            failures.append(f"{app_id}: {exc}")
            continue
        version = manifest.get("app.version", "unknown")
        artifact_zip = review_dir / f"{app_id}-{version}.zip"
        descriptor = review_dir / f"{app_id}.properties"
        receipt_file = review_dir / f"{app_id}-review-receipt.properties"
        remove_existing_path(artifact_zip)
        remove_existing_path(descriptor)
        remove_existing_path(receipt_file)
        pack_result = run_cli(
            cli,
            [
                "pack",
                "--bundle-dir",
                str(spec["stagedDir"]),
                "--output",
                str(artifact_zip),
                "--overwrite",
            ],
            settings,
            f"crypta-app-review-pack-{app_id}",
        )
        app_details["pack"] = command_details(pack_result, settings)
        app_details["artifact"] = display_path(artifact_zip, settings.workspace_root, settings.out_dir)
        if pack_result.exit_code != 0 or not artifact_zip.is_file():
            failures.append(f"{app_id}: first-party bundle pack failed")
            continue
        write_first_party_review_descriptor(descriptor, spec, manifest, artifact_zip)
        sign_result = run_cli(
            cli,
            review_sign_args(descriptor, receipt_file, inputs),
            settings,
            f"crypta-app-review-sign-{app_id}",
        )
        verify_result = run_cli(
            cli,
            review_verify_args(descriptor, receipt_file, trusted_keys_file),
            settings,
            f"crypta-app-review-verify-{app_id}",
        )
        app_details["descriptor"] = display_path(descriptor, settings.workspace_root, settings.out_dir)
        app_details["receipt"] = display_path(receipt_file, settings.workspace_root, settings.out_dir)
        app_details["sign"] = command_details(sign_result, settings)
        app_details["verify"] = command_details(verify_result, settings)
        if sign_result.exit_code != 0:
            failures.append(f"{app_id}: review receipt signing failed")
        if verify_result.exit_code != 0:
            failures.append(f"{app_id}: review receipt verification failed")
        if sign_result.exit_code == 0 and verify_result.exit_code == 0:
            entry_files.append(descriptor)
            receipt_files.append(receipt_file)
    if failures:
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party review catalog preparation failed.",
            source,
            {"failures": failures, **details},
        )

    create_args = [
        "catalog",
        "create",
        "--catalog-file",
        str(catalog_file),
        "--catalog-id",
        "cert-first-party-review",
        "--name",
        "Certification First-Party Apps",
        "--generated-at",
        "2026-05-01T00:00:00Z",
    ]
    for entry_file in entry_files:
        create_args.extend(["--entry", str(entry_file)])
    for receipt_file in receipt_files:
        create_args.extend(["--review-receipt", str(receipt_file)])
    create_args.append("--overwrite")
    create_result = run_cli(cli, create_args, settings, "crypta-app-review-catalog-create")
    details["catalogCreate"] = command_details(create_result, settings)
    catalog = parse_properties(catalog_file) if catalog_file.is_file() else {}
    catalog_entries = parse_permission_set(catalog.get("catalog.entries", ""))
    expected_app_ids = {spec["appId"] for spec in specs}
    inspected_app_ids = {
        app_id
        for app_id in expected_app_ids
        if catalog.get(f"app.{app_id}.id") == app_id or app_id in catalog_entries
    }
    receipt_statuses = {
        app_id: catalog.get(f"app.{app_id}.review.receipt.status")
        for app_id in expected_app_ids
    }
    trusted_positive_receipts = sum(
        1 for status in receipt_statuses.values() if status == "reviewed"
    )
    trusted_rejected_receipts = sum(
        1 for status in receipt_statuses.values() if status == "rejected"
    )
    missing_receipts = sum(1 for status in receipt_statuses.values() if not status)
    verify_failures = sum(
        1
        for app_details in details["apps"].values()
        if app_details.get("verify", {}).get("exitCode") != 0
    )
    details["coverage"] = {
        "catalogAppsInspected": len(inspected_app_ids),
        "trustedPositiveReceipts": trusted_positive_receipts,
        "missingReceipts": missing_receipts,
        "expiredOrMismatchedOrUnknownReviewer": verify_failures,
        "trustedRejectedReceipts": trusted_rejected_receipts,
        "promotionBlocked": (
            create_result.exit_code != 0
            or inspected_app_ids != expected_app_ids
            or trusted_positive_receipts != len(expected_app_ids)
        ),
    }
    details["catalog"] = {
        "catalogId": catalog.get("catalog.id"),
        "entries": sorted(catalog_entries),
        "inspectedAppIds": sorted(inspected_app_ids),
        "receiptStatuses": receipt_statuses,
    }
    if details["coverage"]["promotionBlocked"]:
        return EvidenceItem("app-review.first-party-catalog", "fail" if settings.mode == "release-candidate" else "warn", True, "Trusted first-party review receipt catalog evidence failed.", source, details)
    return EvidenceItem("app-review.first-party-catalog", "pass", True, "First-party catalog review receipt evidence covered all first-party apps.", source, details)


def design_system_source_dir(settings: Settings) -> Path:
    return (
        settings.workspace_root
        / "platform-design-system/src/main/resources/network/crypta/platform/designsystem/static"
    )


def design_system_asset_names() -> tuple[str, ...]:
    return ("crypta-ui-tokens.css", "crypta-ui.css", "crypta-ui-components.js")


def collect_app_ui_design_system_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    canonical_dir = design_system_source_dir(settings)
    details: dict[str, Any] = {
        "canonicalResourceDir": display_path(canonical_dir, settings.workspace_root),
        "assets": [],
        "apps": {},
    }
    errors: list[str] = []
    for asset_name in design_system_asset_names():
        asset_path = canonical_dir / asset_name
        if not asset_path.is_file():
            errors.append(f"canonical design-system asset missing: {asset_name}")
            details["assets"].append({"name": asset_name, "present": False})
            continue
        details["assets"].append(
            {
                "name": asset_name,
                "present": True,
                "sha256": sha256_file(asset_path),
                "sizeBytes": asset_path.stat().st_size,
            }
        )
    for spec in first_party_app_specs(settings):
        app_details: dict[str, Any] = {"assets": []}
        staged_static_dir = spec["stagedDir"] / "static/crypta-ui"
        for asset_name in design_system_asset_names():
            staged_asset = staged_static_dir / asset_name
            canonical_asset = canonical_dir / asset_name
            present = staged_asset.is_file()
            matches = (
                present
                and canonical_asset.is_file()
                and sha256_file(staged_asset) == sha256_file(canonical_asset)
            )
            app_details["assets"].append(
                {
                    "name": asset_name,
                    "present": present,
                    "matchesCanonical": matches,
                    "path": display_path(staged_asset, settings.workspace_root),
                }
            )
            if not present:
                errors.append(f"{spec['appId']}: staged design-system asset missing: {asset_name}")
            elif not matches:
                errors.append(f"{spec['appId']}: staged design-system asset differs: {asset_name}")
        details["apps"][spec["appId"]] = app_details
    if errors:
        return EvidenceItem(
            "app-ui.design-system",
            root_consequence(settings, "fail"),
            True,
            "App UI design-system asset evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.design-system",
        "pass",
        True,
        "Canonical app UI design-system assets are present and staged into first-party apps.",
        source,
        details,
    )


def stylesheet_order_ok(index_html: str) -> bool:
    tokens = index_html.find("crypta-ui-tokens.css")
    ui_css = index_html.find("crypta-ui.css")
    app_css = index_html.find("app.css")
    return tokens >= 0 and ui_css > tokens and app_css > ui_css


def permission_disclosure_block(index_html: str) -> str:
    lower = index_html.lower()
    candidates = [
        lower.find("cr-permission-summary"),
        lower.find("data-crypta-permission-summary"),
        lower.find("<crypta-permission-summary"),
    ]
    starts = [candidate for candidate in candidates if candidate >= 0]
    if not starts:
        return ""
    start = min(starts)
    end_candidates = [
        lower.find("</section>", start),
        lower.find("</crypta-permission-summary>", start),
    ]
    ends = [candidate for candidate in end_candidates if candidate >= 0]
    end = min(ends) if ends else len(index_html)
    return index_html[start:end]


def source_ui_adoption_details(
    static_dir: Path, permissions: set[str], settings: Settings
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    index = static_dir / "index.html"
    details: dict[str, Any] = {
        "index": display_path(index, settings.workspace_root),
        "designSystemStylesheetOrder": False,
        "usesDesignSystemClasses": False,
        "hasPermissionDisclosure": False,
    }
    if not index.is_file():
        return ["static/index.html is missing"], details
    index_html = index.read_text(encoding="utf-8")
    details["designSystemStylesheetOrder"] = stylesheet_order_ok(index_html)
    details["usesDesignSystemClasses"] = "cr-" in index_html
    details["hasPermissionDisclosure"] = (
        "cr-permission-summary" in index_html
        or "data-crypta-permission-summary" in index_html
        or "<crypta-permission-summary" in index_html
    )
    if not details["designSystemStylesheetOrder"]:
        errors.append("index.html does not load design-system CSS before app CSS")
    if not details["usesDesignSystemClasses"]:
        errors.append("index.html does not use cr-* design-system classes")
    if permissions and not details["hasPermissionDisclosure"]:
        errors.append("manifest permissions have no visible permission disclosure")
    disclosure = permission_disclosure_block(index_html)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    omitted = sorted(permissions - mentioned_permissions)
    undeclared = sorted(mentioned_permissions - permissions)
    details["mentionedPermissions"] = sorted(mentioned_permissions)
    details["omittedPermissions"] = omitted
    if details["hasPermissionDisclosure"] and omitted:
        errors.append("permission disclosure omits declared permissions: " + ",".join(omitted))
    if undeclared:
        errors.append(
            "permission disclosure mentions undeclared permissions: " + ",".join(undeclared)
        )
    return errors, details


def collect_app_ui_first_party_adoption_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    details: dict[str, Any] = {"sourceStaticUi": {}, "stagedStaticUi": {}}
    errors: list[str] = []
    for spec in first_party_app_specs(settings):
        source_errors, source_details = source_ui_adoption_details(
            spec["sourceDir"] / "static", spec["permissions"], settings
        )
        staged_errors, staged_details = source_ui_adoption_details(
            spec["stagedDir"] / "static", spec["permissions"], settings
        )
        details["sourceStaticUi"][spec["appId"]] = source_details
        details["stagedStaticUi"][spec["appId"]] = staged_details
        errors.extend(f"{spec['appId']} source: {error}" for error in source_errors)
        errors.extend(f"{spec['appId']} staged: {error}" for error in staged_errors)
    if errors:
        return EvidenceItem(
            "app-ui.first-party-adoption",
            root_consequence(settings, "fail"),
            True,
            "First-party app UI design-system adoption checks found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.first-party-adoption",
        "pass",
        True,
        "First-party static apps use design-system loading order, classes, and permission disclosure.",
        source,
        details,
    )


def collect_app_ui_lint_evidence(settings: Settings, cli: Path | None) -> EvidenceItem:
    source = summary_source(settings)
    details: dict[str, Any] = {"apps": {}}
    if cli is None or not cli.is_file():
        return EvidenceItem(
            "app-ui.lint",
            root_consequence(settings, "missing"),
            True,
            "crypta-app CLI is unavailable for app UI lint evidence.",
            source,
            details,
        )
    errors: list[str] = []
    lint_dir = settings.out_dir / "artifacts" / "app-ui-lint"
    lint_dir.mkdir(parents=True, exist_ok=True)
    for spec in first_party_app_specs(settings):
        json_path = lint_dir / f"{spec['appId']}.json"
        remove_existing_path(json_path)
        result = run_cli(
            cli,
            [
                "ui",
                "lint",
                "--bundle-dir",
                str(spec["stagedDir"]),
                "--strict",
                "--json",
                str(json_path),
            ],
            settings,
            f"crypta-app-ui-lint-{spec['appId']}",
        )
        app_details = {
            "command": command_details(result, settings),
            "json": display_path(json_path, settings.workspace_root, settings.out_dir),
        }
        lint_json = read_json_file(json_path)
        if lint_json:
            app_details["report"] = {
                "appId": str(lint_json.get("appId", "")),
                "uiMode": str(lint_json.get("uiMode", "")),
                "applicable": lint_json.get("applicable"),
            }
            summary = lint_json.get("summary", {})
            app_details["summary"] = summary
            findings = lint_json.get("findings", [])
            if isinstance(findings, list):
                app_details["findingIds"] = [
                    str(finding.get("id", "unknown"))
                    for finding in findings
                    if isinstance(finding, dict)
                ]
        details["apps"][spec["appId"]] = app_details
        if result.exit_code != 0:
            errors.append(f"crypta-app ui lint failed for {spec['appId']}")
        errors.extend(ui_lint_report_errors(lint_json, str(spec["appId"])))
    if errors:
        return EvidenceItem(
            "app-ui.lint",
            root_consequence(settings, "fail"),
            True,
            "First-party app UI lint found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.lint",
        "pass",
        True,
        "crypta-app ui lint passed for first-party static apps.",
        source,
        details,
    )


def collect_app_vault_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    doc_path = settings.workspace_root / APP_VAULT_DOC
    vocabulary_path = (
        settings.workspace_root
        / "platform-devtools/src/main/java/network/crypta/platform/devtools/DevtoolsCapabilityVocabulary.java"
    )
    details: dict[str, Any] = {
        "doc": display_path(doc_path, settings.workspace_root),
        "devtoolsVocabulary": display_path(vocabulary_path, settings.workspace_root),
        "capabilities": list(APP_VAULT_CAPABILITIES),
        "checks": {},
        "redaction": {
            "capabilityNamesRetained": True,
            "secretValuesRedacted": True,
            "identityPrivateMaterialRedacted": True,
        },
    }
    errors: list[str] = []
    doc_text = ""
    if doc_path.is_file():
        doc_text = doc_path.read_text(encoding="utf-8")
    else:
        errors.append(f"{APP_VAULT_DOC} is missing")
    vocabulary_text = vocabulary_path.read_text(encoding="utf-8") if vocabulary_path.is_file() else ""
    if not vocabulary_text:
        errors.append("devtools app-vault capability vocabulary is missing")

    lower_doc = doc_text.lower()
    lower_vocab = vocabulary_text.lower()
    missing_doc_capabilities = [
        capability for capability in APP_VAULT_CAPABILITIES if capability not in doc_text
    ]
    missing_vocab_capabilities = [
        capability for capability in APP_VAULT_CAPABILITIES if capability not in lower_vocab
    ]
    if missing_doc_capabilities:
        errors.append("vault doc omits capabilities: " + ",".join(missing_doc_capabilities))
    if missing_vocab_capabilities:
        errors.append(
            "devtools vocabulary omits capabilities: " + ",".join(missing_vocab_capabilities)
        )
    checks = details["checks"]
    checks["capabilitiesDocumented"] = not missing_doc_capabilities
    checks["devtoolsVocabularyPresent"] = not missing_vocab_capabilities
    checks["appOwnedAndSharedIdentities"] = "app-owned" in lower_doc and "shared identit" in lower_doc
    checks["processBrowserRestrictions"] = (
        "process" in lower_doc and "browser" in lower_doc and "cryptad_app_token" in lower_doc
    )
    checks["atRestLimitations"] = (
        ("at-rest" in lower_doc or "at rest" in lower_doc)
        and "local" in lower_doc
        and "limit" in lower_doc
    )
    checks["grantLifecycle"] = all(
        word in lower_doc for word in ("update", "rollback", "uninstall", "reinstall")
    )
    checks["auditAndRedaction"] = "audit" in lower_doc and "redact" in lower_doc
    checks["futureExtensionPoint"] = all(word in lower_doc for word in ("content", "social", "mail"))
    for name, passed in checks.items():
        if not passed:
            errors.append(f"vault documentation check failed: {name}")
    if errors:
        return EvidenceItem(
            "app-vault.capabilities",
            root_consequence(settings, "fail"),
            True,
            "App secret and identity vault evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-vault.capabilities",
        "pass",
        True,
        "App secret and identity vault capability docs and redaction checks passed.",
        source,
        details,
    )


def read_json_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def ui_lint_report_errors(lint_json: dict[str, Any] | None, expected_app_id: str) -> list[str]:
    if lint_json is None:
        return [f"crypta-app ui lint JSON missing or malformed for {expected_app_id}"]
    errors: list[str] = []
    if lint_json.get("appId") != expected_app_id:
        errors.append(f"crypta-app ui lint JSON appId mismatch for {expected_app_id}")
    if lint_json.get("uiMode") != "static":
        errors.append(f"crypta-app ui lint JSON uiMode mismatch for {expected_app_id}")
    if lint_json.get("applicable") is not True:
        errors.append(f"crypta-app ui lint JSON applicability mismatch for {expected_app_id}")
    summary = lint_json.get("summary")
    if not isinstance(summary, dict):
        errors.append(
            f"crypta-app ui lint JSON summary missing or malformed for {expected_app_id}"
        )
    else:
        error_count = summary.get("errors")
        if not isinstance(error_count, int) or isinstance(error_count, bool) or error_count != 0:
            errors.append(f"crypta-app ui lint JSON reports nonzero errors for {expected_app_id}")
    findings = lint_json.get("findings")
    if not isinstance(findings, list):
        errors.append(
            f"crypta-app ui lint JSON findings missing or malformed for {expected_app_id}"
        )
    elif any(
        isinstance(finding, dict) and str(finding.get("severity", "")).lower() == "error"
        for finding in findings
    ):
        errors.append(
            f"crypta-app ui lint JSON findings include error severity for {expected_app_id}"
        )
    return errors


def collect_app_ui_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    source_ok, source_errors, source_details = check_source_static_ui(settings)
    staged_errors: list[str] = []
    staged_details: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        static_dir = spec["stagedDir"] / "static"
        errors, details = validate_static_ui_files(static_dir, settings)
        staged_errors.extend(f"{spec['appId']}: {error}" for error in errors)
        staged_details[spec["appId"]] = details
    errors = source_errors + staged_errors
    details = {"sourceStaticUi": source_details, "stagedStaticUi": staged_details}
    if errors:
        return EvidenceItem(
            "app-ui.smoke",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-owned UI or SDK smoke found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem("app-ui.smoke", "pass", True, "App-owned UI and SDK smoke passed.", source, details)


def collect_reference_content_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "site-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "site-publisher",
        "checks": {},
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-apps.content",
            root_consequence(settings, "fail"),
            True,
            "Site Publisher first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/site-publisher"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
            "expectedPermissions": sorted(spec["permissions"]),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesContentInsertDirectory"] = "CryptaPlatform.content.insertDirectory" in source_app_js
    checks["usesContentInsertFile"] = "CryptaPlatform.content.insertFile" in source_app_js
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load({ appId })" in source_app_js
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    checks["noVaultCapabilitiesDeclared"] = bool(manifest) and not any(
        permission.startswith("vault.") for permission in manifest_permissions
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["identityProfileDemoDocumentedFutureWork"] = (
        "Identity-backed" in app_readme and "future work" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresSitePublisher"] = (
            manifest.get("app.id") == "site-publisher"
            and manifest.get("app.name") == "Site Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresContentPermissions"] = spec["permissions"].issubset(
            manifest_permissions
        )
    else:
        checks["manifestDeclaresSitePublisher"] = False
        checks["manifestDeclaresContentPermissions"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"reference content app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-apps.content",
            root_consequence(settings, "fail"),
            True,
            "Site Publisher reference content app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-apps.content",
        "pass",
        True,
        "Site Publisher reference content app evidence passed.",
        source,
        details,
    )


def legacy_counts_from_registry_text(text: str) -> dict[str, int]:
    start = text.index("List.of(")
    end = text.index("private static final Map", start)
    block = text[start:end]
    return {
        "PRIMARY_REPLACED": len(re.findall(r"\n\s+(?:replaced|wave1Redirect)\(", block)),
        "PENDING": len(re.findall(r"\n\s+pendingWizard\(", block)) + len(re.findall(r"\n\s+pending\(", block)),
        "RETAINED": len(re.findall(r"\n\s+retained\(", block)),
        "INFRASTRUCTURE": len(re.findall(r"\n\s+infrastructure\(", block)),
    }


def java_method_body(text: str, method_name: str) -> str:
    pattern = re.compile(
        r"\b(?:public|private)\s+static\s+[\w<>, ?]+\s+"
        + re.escape(method_name)
        + r"\s*\([^)]*\)\s*\{",
        re.DOTALL,
    )
    match = pattern.search(text)
    if match is None:
        return ""
    open_brace = match.end() - 1
    depth = 0
    for offset in range(open_brace, len(text)):
        char = text[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : offset]
    return ""


def legacy_fallback_link_checks(text: str) -> dict[str, bool]:
    fallback_body = java_method_body(text, "webShellFallbackSurfaces")
    replaced_body = java_method_body(text, "replaced")
    navigation_body = java_method_body(text, "shouldPromoteInLegacyNavigation")
    replaced_marks_no_fallback = "FALLBACK_POLICY_RENDER_LEGACY" in replaced_body and bool(
        re.search(r",\s*true\s*,\s*false\s*\)\s*;", replaced_body, re.DOTALL)
    )
    fallback_filters_include_flag = bool(
        re.search(r"\.filter\s*\(\s*LegacyAdminSurface::includeInWebShellFallbackLinks\s*\)", fallback_body)
    )
    fallback_filters_primary_state = bool(
        re.search(r"state\(\)\s*!=\s*LegacyAdminRetirementState\.PRIMARY_REPLACED", fallback_body)
    )
    navigation_excludes_primary = bool(
        re.search(r"state\(\)\s*!=\s*LegacyAdminRetirementState\.PRIMARY_REPLACED", navigation_body)
    )
    primary_replaced_excluded = fallback_filters_primary_state or (
        fallback_filters_include_flag and replaced_marks_no_fallback
    )
    return {
        "fallbackMethodFound": bool(fallback_body),
        "replacedHelperFound": bool(replaced_body),
        "replacedHelperDisablesFallbackLinks": replaced_marks_no_fallback,
        "fallbackFiltersIncludeFlag": fallback_filters_include_flag,
        "fallbackFiltersPrimaryState": fallback_filters_primary_state,
        "primaryReplacedExcludedFromFallbackLinks": primary_replaced_excluded,
        "primaryReplacedAbsentFromPrimaryNavigation": navigation_excludes_primary,
    }


def collect_legacy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    registry = settings.workspace_root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
    docs = settings.workspace_root / "docs/legacy-retirement-plan.md"
    errors: list[str] = []
    details: dict[str, Any] = {}
    if not registry.is_file():
        errors.append("LegacyAdminRetirementRegistry.java is missing")
    else:
        registry_text = registry.read_text(encoding="utf-8")
        counts = legacy_counts_from_registry_text(registry_text)
        fallback_checks = legacy_fallback_link_checks(registry_text)
        details["stateCounts"] = counts
        details["totalRegisteredSurfaces"] = sum(counts.values())
        details["primaryReplacedSurfaces"] = counts["PRIMARY_REPLACED"]
        details["pendingSurfaces"] = counts["PENDING"]
        details["retainedSurfaces"] = counts["RETAINED"]
        details["fallbackLinkChecks"] = fallback_checks
        details["primaryReplacedAbsentFromFallbackLinks"] = fallback_checks[
            "primaryReplacedExcludedFromFallbackLinks"
        ]
        details["primaryReplacedAbsentFromPrimaryNavigation"] = fallback_checks[
            "primaryReplacedAbsentFromPrimaryNavigation"
        ]
        docs_text = re.sub(r"\s+", " ", docs.read_text(encoding="utf-8")) if docs.is_file() else ""
        details["retainedPendingRoutesDocumented"] = (
            "retained and pending legacy routes remain reachable" in docs_text.lower()
        )
        if counts["PRIMARY_REPLACED"] < 1:
            errors.append("No PRIMARY_REPLACED surfaces were found")
        if not details["primaryReplacedAbsentFromFallbackLinks"]:
            errors.append("PRIMARY_REPLACED surfaces may still appear in Web Shell fallback links")
        if not details["primaryReplacedAbsentFromPrimaryNavigation"]:
            errors.append("PRIMARY_REPLACED surfaces may still appear in primary legacy navigation")
        if not details["retainedPendingRoutesDocumented"]:
            errors.append("Retained/pending legacy route behavior is not documented")
    if errors:
        return EvidenceItem("legacy.retirement", "fail", True, "Legacy-admin retirement evidence is incomplete.", source, {"errors": errors, **details})
    return EvidenceItem("legacy.retirement", "pass", True, "Legacy-admin retirement map is visible and stable.", source, details)


def legacy_removal_wave_one_ids(registry_text: str) -> list[str]:
    return re.findall(r"\n\s+wave1Redirect\(\s*\"([^\"]+)\"", registry_text)


def collect_legacy_removal_wave_one_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    root = settings.workspace_root
    files = {
        "registry": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java",
        "policy": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java",
        "response": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminReplacementResponse.java",
        "recorder": root / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminUsageRecorder.java",
        "usageDto": root / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java",
        "diagnostics": root / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java",
        "docs": root / "docs/legacy-retirement-plan.md",
    }
    text: dict[str, str] = {}
    missing = []
    for key, path in files.items():
        if not path.is_file():
            missing.append(key)
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    wave_ids = legacy_removal_wave_one_ids(text["registry"])
    checks = {
        "waveOneIdsMatch": wave_ids == list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "redirectModeDeclared": "LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT" in text["registry"],
        "canonicalOnlyPolicy": "matchesCanonicalPageOrSlashlessAlias" in text["policy"],
        "safeReadRedirects": "GET" in text["policy"] and "HEAD" in text["policy"] and "redirect(" in text["policy"],
        "mutatingRequestsBlocked": "BLOCKED_MUTATING_REQUEST" in text["policy"] or "blockedMutation" in text["policy"],
        "replacementAvailabilityGate": "replacementAvailable" in text["policy"]
        and "isStaticAppUiAvailable" in text["policy"]
        and "primaryUiRoot" in text["policy"],
        "replacementResponsesRecorded": "REPLACEMENT_RESPONSE" in text["recorder"] or "REPLACEMENT_RESPONSE" in text["policy"],
        "diagnosticsCarriesReplacementCounter": "replacementResponseCount" in text["diagnostics"] and "replacementResponseCount" in text["usageDto"],
        "diagnosticsCarriesBlockedCounter": "blockedMutatingRequestCount" in text["diagnostics"] and "blockedMutatingRequestCount" in text["usageDto"],
        "diagnosticsCarriesFallbackCounter": "fallbackRenderCount" in text["diagnostics"] and "fallbackRenderCount" in text["usageDto"],
        "docsDescribeWave": "legacy-admin.removal-wave-1" in text["docs"],
        "docsDescribeAvailabilityFallback": "replacement is reachable" in text["docs"]
        or "replacement is unavailable" in text["docs"],
        "docsRetainBrowse": "FProxy browse remains retained" in text["docs"],
        "liveNodeNotRequired": True,
    }
    redaction = {
        "queryStringsExcluded": True,
        "requestBodiesExcluded": True,
        "formPasswordsExcluded": True,
        "remoteAddressesExcluded": True,
        "tokensExcluded": True,
        "privateUrisExcluded": True,
        "localPathsExcluded": True,
    }
    details = {
        "removedByDefaultRouteIds": wave_ids,
        "expectedRouteIds": list(LEGACY_REMOVAL_WAVE_ONE_IDS),
        "replacementUrls": {
            "queue-downloads": "/apps/queue-manager/",
            "queue-uploads": "/apps/queue-manager/",
            "file-insert": "/apps/publisher/",
            "local-file-insert": "/apps/publisher/",
            "friends": "/app/node/#peers",
            "add-friend": "/app/node/#peers",
            "strangers": "/app/node/#peers",
            "connectivity": "/app/node/#connectivity",
        },
        "statusBehavior": {
            "safeRead": "303 See Other when replacement is available; legacy fallback when unavailable",
            "mutating": "410 Gone when replacement is available; legacy fallback when unavailable",
        },
        "liveNodeRequired": False,
        "checks": checks,
        "redaction": redaction,
        "missingSources": missing,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"missing {name}" for name in missing)
    if errors:
        return EvidenceItem(
            "legacy-admin.removal-wave-1",
            "fail",
            True,
            "Legacy-admin removal wave 1 evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-admin.removal-wave-1",
        "pass",
        True,
        "Legacy-admin removal wave 1 replacement behavior is documented and observable.",
        source,
        details,
    )


def collect_sandbox_provider_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    sandbox_dir = settings.workspace_root / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
    sandbox_test_dir = settings.workspace_root / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
    expected_files = {
        "providerSource": sandbox_dir / "BubblewrapSandboxProvider.java",
        "commandBuilderSource": sandbox_dir / "BubblewrapCommandBuilder.java",
        "availabilitySource": sandbox_dir / "BubblewrapAvailability.java",
        "registrySource": sandbox_dir / "AppSandboxProviders.java",
        "providerTest": sandbox_test_dir / "BubblewrapSandboxProviderTest.java",
    }
    checks: dict[str, Any] = {}
    errors: list[str] = []
    for key, path in expected_files.items():
        exists = path.is_file()
        checks[key] = {
            "present": exists,
            "path": display_path(path, settings.workspace_root),
        }
        if not exists:
            errors.append(f"{key} is missing")
    provider_text = expected_files["providerSource"].read_text(encoding="utf-8") if expected_files["providerSource"].is_file() else ""
    builder_text = expected_files["commandBuilderSource"].read_text(encoding="utf-8") if expected_files["commandBuilderSource"].is_file() else ""
    registry_text = expected_files["registrySource"].read_text(encoding="utf-8") if expected_files["registrySource"].is_file() else ""
    test_text = expected_files["providerTest"].read_text(encoding="utf-8") if expected_files["providerTest"].is_file() else ""
    checks["enforcedSupportLevel"] = "AppSandboxSupportLevel.ENFORCED" in provider_text
    checks["bubblewrapProviderName"] = 'PROVIDER_NAME = "bubblewrap"' in provider_text
    checks["restrictedProcessRegistry"] = "BubblewrapSandboxProvider" in registry_text
    checks["environmentPassThrough"] = "checkedContext.environment()" in provider_text
    checks["noSetenvCommand"] = 'command.add("--setenv")' not in provider_text + builder_text
    checks["offlineProviderTests"] = "BubblewrapSandboxProviderTest" in test_text
    for key in (
        "enforcedSupportLevel",
        "bubblewrapProviderName",
        "restrictedProcessRegistry",
        "environmentPassThrough",
        "noSetenvCommand",
        "offlineProviderTests",
    ):
        if not checks[key]:
            errors.append(f"{key} check failed")
    gradle_result = gradle_command(
        settings,
        [
            ":platform-apphost:test",
            "--tests",
            "*BubblewrapSandboxProviderTest",
            "--tests",
            "*AppSandboxProvidersTest",
        ],
        "gradle-apphost-sandbox-provider",
    )
    details: dict[str, Any] = {
        "mode": "restricted-process",
        "provider": "bubblewrap",
        "supportLevel": "enforced",
        "liveBubblewrapRequired": False,
        "hostBubblewrapProbe": {"enabled": False},
        "checks": checks,
        "contractTestsCommand": command_details(gradle_result, settings),
    }
    if gradle_result is not None and gradle_result.exit_code != 0:
        errors.append("platform-apphost sandbox provider tests failed")
    if gradle_result is None and settings.mode == "release-candidate":
        errors.append("platform-apphost sandbox provider tests were skipped")
    if errors:
        return EvidenceItem(
            "apphost.sandbox-provider",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "AppHost sandbox provider evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "apphost.sandbox-provider",
        "pass",
        True,
        "AppHost sandbox provider contract passed using deterministic offline evidence.",
        source,
        details,
    )


def read_source(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def collect_app_update_lifecycle_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    apphost_source = (
        settings.workspace_root
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    catalog_handler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    update_service_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    update_handler_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatesApiHandler.java"
    )
    update_policy_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdatePolicyMode.java"
    )
    update_candidate_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java"
    )
    update_status_source = (
        settings.workspace_root
        / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidateStatus.java"
    )
    update_service_test_source = (
        settings.workspace_root
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateServiceTest.java"
    )
    router_test_source = settings.workspace_root / "src/test/java/network/crypta/platform/api/PlatformApiRouterTest.java"
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    apphost_text = read_source(apphost_source)
    catalog_text = read_source(catalog_handler_source)
    update_service_text = read_source(update_service_source)
    update_handler_text = read_source(update_handler_source)
    policy_text = read_source(update_policy_source)
    candidate_text = read_source(update_candidate_source)
    status_text = read_source(update_status_source)
    update_service_test_text = read_source(update_service_test_source)
    router_test_text = read_source(router_test_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "apphostUpdateEntryPoint": "updateFromDirectory" in apphost_text,
        "policyModes": (
            'MANUAL("manual")' in policy_text
            and 'STAGE("stage")' in policy_text
            and 'APPLY_WHEN_STOPPED("apply_when_stopped")' in policy_text
        ),
        "managedStageCopyBeforeValidation": (
            "copyDirectoryTree(stagingRoot, temporaryInstallRoot)" in apphost_text
            and "verifyCopiedBundle(temporaryInstallRoot)" in apphost_text
            and "validateCopiedBundle(temporaryInstallRoot)" in apphost_text
        ),
        "matchingAppIdGate": "requireMatchingUpdateTarget(normalizedAppId, manifest)" in apphost_text,
        "hostApplyWhenStoppedGate": (
            "liveRunningProcess(normalizedAppId) != null" in apphost_text
            and "cannot update a running app" in apphost_text
        ),
        "updateApplyRunningConflictTest": (
            "apply_whenAppStartsAfterPrecheck_expectConflictNotServerError"
            in update_service_test_text
            and '"cannot update a running app: " + APP_ID' in update_service_test_text
            and 'assertEquals("app_running", exception.errorCode())' in update_service_test_text
        ),
        "updateApplyRunningConflictRouteTest": (
            "route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson" in router_test_text
            and 'List.of("apps", APP_ID, "updates", "apply")' in router_test_text
            and "assertEquals(409, response.statusCode())" in router_test_text
            and 'verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir)' in router_test_text
            and "app_running" in router_test_text
        ),
        "catalogVersionComparison": (
            "versionDifferent(" in catalog_text
            and "updateAvailable(" in catalog_text
            and '"versionDifferent"' in catalog_text
            and '"updateAvailable"' in catalog_text
        ),
        "candidateDetectionSemantics": (
            'AVAILABLE("available")' in status_text
            and 'STAGED("staged")' in status_text
            and 'BLOCKED("blocked")' in status_text
            and 'INCOMPATIBLE("incompatible")' in status_text
            and 'AMBIGUOUS("ambiguous")' in status_text
            and 'ROLLBACK_AVAILABLE("rollback_available")' in status_text
        ),
        "candidateReviewMetadata": '"review"' in candidate_text and "reviewSummary" in candidate_text,
        "candidateCompatibilityMetadata": (
            '"apiCompatibility"' in candidate_text and "apiCompatibility" in candidate_text
        ),
        "permissionDeltaReview": (
            "permissionDelta" in candidate_text and '"permissionDelta"' in candidate_text
        ),
        "lifecycleHandlerRoutesStageAndApply": (
            "Map<String, Object> stage(String appId)" in update_handler_text
            and "return updateService.stage(appId)" in update_handler_text
            and (
                "Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters)"
                in update_handler_text
            )
            and (
                "return updateService.apply(appId, applyOptions(queryParameters))"
                in update_handler_text
            )
        ),
        "lifecycleServiceStagesVerifiedPlan": (
            "public synchronized Map<String, Object> stage(String appId)" in update_service_text
            and (
                "catalogManager.prepareInstallPlan(candidate.catalogId(), appId)"
                in update_service_text
            )
            and "planDiffersFromCandidate(candidate, installed, plan)" in update_service_text
        ),
        "lifecycleServiceApplyDelegatesToAppHost": (
            (
                "public synchronized Map<String, Object> apply(String appId, ApplyOptions options)"
                in update_service_text
            )
            and (
                "appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory())"
                in update_service_text
            )
            and "closeStage(normalizedAppId)" in update_service_text
        ),
        "manualApplyPolicyDocumented": (
            "apply_when_stopped" in doc_text
            and "manual" in doc_text
            and "stage" in doc_text
            and "Silent automatic update is not the default" in doc_text
            and "requires an operator or explicit API caller" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "policy": "manual/stage/apply_when_stopped",
        "silentAutoUpdateDefault": False,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "apphost": display_path(apphost_source, settings.workspace_root),
            "catalogHandler": display_path(catalog_handler_source, settings.workspace_root),
            "updateService": display_path(update_service_source, settings.workspace_root),
            "updateHandler": display_path(update_handler_source, settings.workspace_root),
            "updatePolicy": display_path(update_policy_source, settings.workspace_root),
            "updateCandidate": display_path(update_candidate_source, settings.workspace_root),
            "updateStatus": display_path(update_status_source, settings.workspace_root),
            "updateServiceTest": display_path(update_service_test_source, settings.workspace_root),
            "routerTest": display_path(router_test_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.lifecycle",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update lifecycle evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.lifecycle",
        "pass",
        True,
        "App-update lifecycle policy passed deterministic offline evidence checks.",
        source,
        details,
    )


def collect_app_update_rollback_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    apphost_source = (
        settings.workspace_root
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    )
    apphost_test_source = (
        settings.workspace_root
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    lifecycle_doc = settings.workspace_root / "docs/app-update-lifecycle.md"
    apphost_text = read_source(apphost_source)
    apphost_test_text = read_source(apphost_test_source)
    doc_text = read_source(lifecycle_doc)
    checks = {
        "managedBackupAllocated": (
            "TEMP_UPDATE_BACKUP_PREFIX" in apphost_text
            and "temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX" in apphost_text
        ),
        "durableRollbackRoot": (
            "rollbackRootFor" in apphost_text
            and "ensureRollbackAppsDirectory" in apphost_text
            and "rollbackStatus" in apphost_text
        ),
        "installedBundleRecordedForRollback": (
            "moveIntoPlace(installedRoot, backupRoot)" in apphost_text
            and "moveIntoPlace(backupRoot, rollbackRoot)" in apphost_text
        ),
        "restorePreviousBundleOnReplacementFailure": (
            "restoreInstalledBundle(installedRoot, backupRoot, updateFailure)" in apphost_text
            and "restorePreviousRollback(" in apphost_text
        ),
        "manualRollbackSwapsBundles": (
            "swapInstalledBundleWithRollback" in apphost_text
            and "moveIntoPlace(rollbackRoot, installedRoot)" in apphost_text
            and "moveIntoPlace(currentInstallBackupRoot, rollbackRoot)" in apphost_text
        ),
        "replacementCommitToleratesPreviousRecordCleanupFailure": (
            "deleteBackupAfterSuccessfulReplacement" in apphost_text
            and "simulated backup cleanup failure" in apphost_test_text
            and "cleanupAttempts.incrementAndGet()" in apphost_test_text
            and 'resolve("first").resolve(SAMPLE_APP_ID)' in apphost_test_text
            and "assertEquals(0, cleanupAttempts.get())" in apphost_test_text
            and 'resolve("second").resolve(SAMPLE_APP_ID)' in apphost_test_text
            and "firstUpdate.manifest().appVersion()" in apphost_test_text
            and "assertEquals(1, cleanupAttempts.get())" in apphost_test_text
            and "expectPreviousBundleRecordedForRollback" in apphost_test_text
        ),
        "mutableDirectoriesPreservedByUpdate": (
            "preserve-data.txt" in apphost_test_text
            and "preserve-cache.txt" in apphost_test_text
            and "preserve-run.txt" in apphost_test_text
        ),
        "mutableDirectoriesPreservedByRollback": (
            "rollback-data.txt" in apphost_test_text
            and "rollback-cache.txt" in apphost_test_text
            and "rollback-run.txt" in apphost_test_text
        ),
        "rollbackHealthGate": (
            "cannot rollback a running app" in apphost_text
            and "rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged" in apphost_test_text
        ),
        "rollbackMetadataPathFree": (
            "rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths" in apphost_test_text
        ),
        "rollbackScopeDocumented": (
            "Rollback covers only the immutable installed bundle" in doc_text
            and "Rollback does not roll back" in doc_text
            and "app data directories" in doc_text
            and "app cache directories" in doc_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "rollbackScope": "installed-bundle-only",
        "preservesDataCacheRun": True,
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "apphost": display_path(apphost_source, settings.workspace_root),
            "apphostTest": display_path(apphost_test_source, settings.workspace_root),
            "lifecycleDoc": display_path(lifecycle_doc, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-update.rollback",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-update rollback evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-update.rollback",
        "pass",
        True,
        "App-update rollback scope passed deterministic offline evidence checks.",
        source,
        details,
    )


def build_http_request(
    method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
) -> urllib.request.Request:
    payload: bytes | None = None
    headers = {"Accept": "application/json"}
    params = data or {}
    if method in {"POST", "DELETE"} and form_password:
        params = {**params, "formPassword": form_password}
    if method in {"POST", "DELETE"} and params:
        payload = urllib.parse.urlencode(params).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    return urllib.request.Request(url, data=payload, method=method, headers=headers)


def http_request_json(
    method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
) -> tuple[int, Any]:
    request = build_http_request(method, url, form_password, data)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            value = json.loads(body) if body else {}
        except json.JSONDecodeError:
            value = {"error": {"message": body[:200]}}
        return exc.code, value


def diagnostics_body_summary(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"diagnosticsBodyType": type(body).__name__}
    summary: dict[str, Any] = {}
    section_count = body.get("sectionCount")
    if isinstance(section_count, int):
        summary["sectionCount"] = section_count
    sections = body.get("sections")
    if isinstance(sections, list):
        summary["sectionCount"] = len(sections)
    legacy_admin = body.get("legacyAdmin")
    if isinstance(legacy_admin, dict):
        surfaces = legacy_admin.get("surfaces")
        if isinstance(surfaces, list):
            summary["legacyAdminSurfaceCount"] = len(surfaces)
            counts = [
                surface.get("count")
                for surface in surfaces
                if isinstance(surface, dict) and isinstance(surface.get("count"), int)
            ]
            summary["legacyAdminTotalCount"] = sum(counts)
            for output_key, field_name in (
                ("legacyAdminReplacementResponseTotal", "replacementResponseCount"),
                ("legacyAdminBlockedMutatingRequestTotal", "blockedMutatingRequestCount"),
                ("legacyAdminFallbackRenderTotal", "fallbackRenderCount"),
                ("legacyAdminRetainedOrPendingRenderTotal", "retainedOrPendingRenderCount"),
            ):
                summary[output_key] = sum(
                    surface.get(field_name)
                    for surface in surfaces
                    if isinstance(surface, dict) and isinstance(surface.get(field_name), int)
                )
    if not summary:
        summary["diagnosticsBodyReceived"] = True
    return summary


def live_response_details(path: str, body: Any, workspace_root: Path) -> dict[str, Any]:
    if path == "/diagnostics":
        return {"bodySummary": diagnostics_body_summary(body)}
    return {"body": sanitize_value(body, workspace_root)}


def collect_live_cleanup_steps(root: str, settings: Settings) -> list[dict[str, Any]]:
    cleanup_steps: list[dict[str, Any]] = []
    for method, path in (("POST", "/apps/cert-smoke/stop"), ("DELETE", "/apps/cert-smoke")):
        cleanup_step: dict[str, Any] = {"method": method, "path": path}
        try:
            status, body = http_request_json(method, root + path, settings.live_form_password, {})
            cleanup_step["status"] = status
            cleanup_step.update(live_response_details(path, body, settings.workspace_root))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            cleanup_step["error"] = scrub_text(str(exc), settings.workspace_root)
        cleanup_steps.append(cleanup_step)
    return cleanup_steps


def failed_live_evidence(
    source: str,
    details: dict[str, Any],
    root: str,
    settings: Settings,
    installed: bool,
    summary: str = "Live AppHost lifecycle smoke failed.",
) -> EvidenceItem:
    if installed:
        details["cleanupSteps"] = collect_live_cleanup_steps(root, settings)
    return EvidenceItem("apphost.live", "fail", False, summary, source, details)


def collect_live_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    if not settings.live:
        return EvidenceItem("apphost.live", "skip", False, "Live AppHost lifecycle smoke was not requested.", source, {"enabled": False})
    details: dict[str, Any] = {"enabled": True, **live_base_url_details(settings.live_base_url)}
    if not settings.live_base_url:
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke was requested without CRYPTAD_CERT_NODE_BASE_URL.", source, details)
    host = urllib.parse.urlparse(settings.live_base_url).hostname or ""
    if not is_local_live_host(host):
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke only records localhost node evidence.", source, details)
    if not settings.live_form_password:
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke was requested without CRYPTAD_CERT_FORM_PASSWORD.", source, details)
    staged_dir = sample_paths.get("bundleDir")
    if not staged_dir or not staged_dir.is_dir():
        return EvidenceItem("apphost.live", "fail", False, "Live AppHost smoke needs the generated sample staged bundle.", source, details)
    root = settings.live_base_url.rstrip("/") + "/api/v1"
    steps: list[dict[str, Any]] = []
    installed = False
    try:
        for method, path, data in (
            ("GET", "/apps", {}),
            ("DELETE", "/apps/cert-smoke", {}),
            ("POST", "/apps/install", {"stagedDir": str(staged_dir.resolve())}),
            ("GET", "/apps/cert-smoke/runtime", {}),
            ("POST", "/apps/cert-smoke/start", {}),
            ("GET", "/apps/cert-smoke/runtime", {}),
            ("POST", "/apps/cert-smoke/stop", {}),
            ("POST", "/apps/cert-smoke/update", {"stagedDir": str(staged_dir.resolve())}),
            ("DELETE", "/apps/cert-smoke", {}),
            ("GET", "/diagnostics", {}),
        ):
            status, body = http_request_json(method, root + path, settings.live_form_password, data)
            step = {"method": method, "path": path, "status": status}
            step.update(live_response_details(path, body, settings.workspace_root))
            steps.append(step)
            if status >= 400 and not (method == "DELETE" and path == "/apps/cert-smoke" and status == 404):
                details["steps"] = steps
                return failed_live_evidence(source, details, root, settings, installed)
            if method == "POST" and path == "/apps/install":
                installed = True
            elif method == "DELETE" and path == "/apps/cert-smoke" and status < 500:
                installed = False
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        details["steps"] = steps
        details["error"] = scrub_text(str(exc), settings.workspace_root)
        return failed_live_evidence(source, details, root, settings, installed)
    details["steps"] = steps
    return EvidenceItem("apphost.live", "pass", False, "Live AppHost install/start/status/stop/update/uninstall smoke passed.", source, details)


def overall_status(mode: str, evidence: list[EvidenceItem]) -> str:
    if any(item.required_for_release_candidate and item.status == "fail" for item in evidence):
        return "fail"
    if mode == "release-candidate" and any(
        item.required_for_release_candidate and item.status in {"missing", "skip"} for item in evidence
    ):
        return "fail"
    if any(
        item.status in {"warn", "missing", "fail"} or (item.required_for_release_candidate and item.status == "skip")
        for item in evidence
    ):
        return "warn"
    return "pass"


def render_report(summary: dict[str, Any]) -> str:
    lines = [
        "# App Platform Smoke Report",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Status: `{summary['status']}`",
        f"- Generated: `{summary['generatedAt']}`",
        "",
        "| Evidence | Status | Required for RC | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for item in summary["evidence"]:
        summary_text = str(item["summary"]).replace("|", "\\|")
        lines.append(
            f"| `{item['id']}` | `{item['status']}` | "
            f"{'yes' if item['requiredForReleaseCandidate'] else 'no'} | "
            f"{summary_text} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_summary(settings: Settings, evidence: list[EvidenceItem]) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": settings.mode,
        "status": overall_status(settings.mode, evidence),
        "generatedAt": utc_now(),
        "summaryPath": display_path(settings.out_dir / SUMMARY_FILE_NAME, settings.workspace_root, settings.out_dir),
        "reportPath": display_path(settings.out_dir / REPORT_FILE_NAME, settings.workspace_root, settings.out_dir),
        "evidence": [item.to_json() for item in evidence],
        "redaction": {
            "secretMaterialRedacted": True,
            "rawRequestBodiesExcluded": True,
            "rawUpdateRollbackOutputsExcluded": True,
            "absolutePathsSanitized": True,
        },
    }


def run(settings: Settings) -> tuple[dict[str, Any], int]:
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    remove_existing_path(settings.out_dir / "artifacts")
    cli = find_cli(settings)
    cli_item, sample_paths = collect_cli_evidence(settings, cli)
    cli = sample_paths.get("cli") if sample_paths.get("cli") else find_cli(settings)
    evidence = [
        collect_first_party_evidence(settings, cli if isinstance(cli, Path) else None),
        cli_item,
        collect_platform_api_contract_evidence(settings, cli if isinstance(cli, Path) else None, sample_paths),
        collect_app_vault_evidence(settings),
        collect_signed_bundle_evidence(settings, sample_paths),
        collect_catalog_evidence(settings, sample_paths),
        collect_app_review_receipt_evidence(settings),
        collect_app_review_policy_evidence(settings),
        collect_app_review_first_party_catalog_evidence(settings, sample_paths),
        collect_app_ui_design_system_evidence(settings),
        collect_app_ui_lint_evidence(settings, cli if isinstance(cli, Path) else None),
        collect_app_ui_first_party_adoption_evidence(settings),
        collect_app_ui_evidence(settings),
        collect_reference_content_app_evidence(settings),
        collect_legacy_evidence(settings),
        collect_legacy_removal_wave_one_evidence(settings),
        collect_sandbox_provider_evidence(settings),
        collect_app_update_lifecycle_evidence(settings),
        collect_app_update_rollback_evidence(settings),
        collect_live_evidence(settings, sample_paths),
    ]
    sanitized_evidence = [
        EvidenceItem(
            item.id,
            item.status,
            item.required_for_release_candidate,
            scrub_text(item.summary, settings.workspace_root),
            item.source,
            dict(sanitize_value(item.details, settings.workspace_root)),
        )
        for item in evidence
    ]
    summary = build_summary(settings, sanitized_evidence)
    write_json(settings.out_dir / SUMMARY_FILE_NAME, summary)
    write_text(settings.out_dir / REPORT_FILE_NAME, render_report(summary))
    exit_code = 1 if settings.mode == "release-candidate" and summary["status"] == "fail" else 0
    return summary, exit_code


def settings_from_args(args: argparse.Namespace) -> Settings:
    workspace = args.workspace_root.resolve()
    out_dir = (workspace / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    mode = args.mode or os.environ.get("CRYPTAD_CERT_MODE", "pr")
    if mode not in MODES:
        raise SystemExit(f"--mode must be one of {', '.join(MODES)}")
    live = args.live or os.environ.get("CRYPTAD_CERT_APP_SMOKE_LIVE") == "1"
    cli_path = args.cli_path.resolve() if args.cli_path else None
    return Settings(
        workspace_root=workspace,
        out_dir=out_dir,
        mode=mode,
        skip_gradle=args.skip_gradle,
        cli_path=cli_path,
        live=live,
        live_base_url=args.node_base_url or os.environ.get("CRYPTAD_CERT_NODE_BASE_URL", ""),
        live_form_password=os.environ.get("CRYPTAD_CERT_FORM_PASSWORD", ""),
        timeout_seconds=args.timeout_seconds,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run Python-only self-tests.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mode", choices=MODES, default=None)
    parser.add_argument("--skip-gradle", action="store_true", help="Do not invoke Gradle tasks.")
    parser.add_argument("--cli-path", type=Path, help="Path to an installed crypta-app launcher.")
    parser.add_argument("--live", action="store_true", help="Run optional live-node AppHost lifecycle smoke.")
    parser.add_argument("--node-base-url", default="", help="Live-node base URL for optional AppHost smoke.")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    return parser


def run_self_test(repo_root: Path) -> None:
    fixture_dir = repo_root / "tools/release-certification/fixtures"
    catalog_fixture = fixture_dir / "self-test-catalog.properties"
    registry_fixture = fixture_dir / "self-test-legacy-registry.java-fragment"
    catalog = parse_properties(catalog_fixture)
    assert catalog["catalog.id"] == "cert-smoke"
    assert catalog["app.cert-smoke.bundle.sha256"] == "0" * 64
    registry_text = registry_fixture.read_text(encoding="utf-8")
    counts = legacy_counts_from_registry_text(registry_text)
    assert counts == {
        "PRIMARY_REPLACED": 9,
        "PENDING": 2,
        "RETAINED": 1,
        "INFRASTRUCTURE": 1,
    }, counts
    fallback_checks = legacy_fallback_link_checks(registry_text)
    assert fallback_checks["primaryReplacedExcludedFromFallbackLinks"] is True, fallback_checks
    assert fallback_checks["primaryReplacedAbsentFromPrimaryNavigation"] is True, fallback_checks
    unsafe_registry_text = registry_text.replace("true,\n        false);", "true,\n        true);", 1)
    unsafe_fallback_checks = legacy_fallback_link_checks(unsafe_registry_text)
    assert unsafe_fallback_checks["primaryReplacedExcludedFromFallbackLinks"] is False, unsafe_fallback_checks
    parser_options = {
        option
        for action in build_parser()._actions
        for option in action.option_strings
    }
    assert "--form-password" not in parser_options, parser_options
    previous_form_password = os.environ.get("CRYPTAD_CERT_FORM_PASSWORD")
    os.environ["CRYPTAD_CERT_FORM_PASSWORD"] = "env-only-form-password"
    try:
        env_settings = settings_from_args(
            build_parser().parse_args(
                [
                    "--workspace-root",
                    str(repo_root),
                    "--out-dir",
                    "build/release-certification/app-platform-smoke",
                    "--live",
                ]
            )
        )
    finally:
        if previous_form_password is None:
            os.environ.pop("CRYPTAD_CERT_FORM_PASSWORD", None)
        else:
            os.environ["CRYPTAD_CERT_FORM_PASSWORD"] = previous_form_password
    assert env_settings.live_form_password == "env-only-form-password", env_settings
    redacted_secret_command = redact_command(
        [
            "crypta-app",
            "sign",
            "--private-key-file",
            "/mnt/secrets/prod-key.pem",
            "--private-key-base64",
            "base64-secret",
        ],
        env_settings,
    )
    assert redacted_secret_command == [
        "crypta-app",
        "sign",
        "--private-key-file",
        "<redacted>",
        "--private-key-base64",
        "<redacted>",
    ], redacted_secret_command
    assert "prod-key.pem" not in json.dumps(redacted_secret_command), redacted_secret_command
    assert normalize_static_script_ref("./app.js?cache=1#main") == "app.js"
    with tempfile.TemporaryDirectory(prefix="cryptad-app-script-order-self-test-") as static_name:
        static_dir = Path(static_name)
        (static_dir / "index.html").write_text(
            '<script src="app.js"></script><script src="crypta-platform.js"></script>\n',
            encoding="utf-8",
        )
        (static_dir / "app.js").write_text(
            'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });\n',
            encoding="utf-8",
        )
        canonical_sdk = repo_root / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
        if canonical_sdk.is_file():
            shutil.copy2(canonical_sdk, static_dir / "crypta-platform.js")
        else:
            (static_dir / "crypta-platform.js").write_text(
                'window.CryptaPlatform={}; X="X-Crypta-App-Session";\n',
                encoding="utf-8",
            )
        script_errors, _ = validate_static_ui_files(static_dir, env_settings)
    assert "index.html must load crypta-platform.js before app.js" in script_errors, script_errors
    with tempfile.TemporaryDirectory(prefix="cryptad-app-adoption-self-test-") as adoption_name:
        adoption_static_dir = Path(adoption_name)
        adoption_static_dir.joinpath("index.html").write_text(
            '<!doctype html><html lang="en"><head>'
            '<link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">'
            '<link rel="stylesheet" href="./crypta-ui/crypta-ui.css">'
            '<link rel="stylesheet" href="./app.css">'
            '</head><body class="cr-app"><main class="cr-shell">'
            '<section class="cr-permission-summary" data-crypta-permission-summary>'
            "<code>queue.read</code>"
            "</section></main></body></html>\n",
            encoding="utf-8",
        )
        adoption_errors, adoption_details = source_ui_adoption_details(
            adoption_static_dir,
            {"queue.read", "queue.write"},
            env_settings,
        )
    assert (
        "permission disclosure omits declared permissions: queue.write" in adoption_errors
    ), adoption_errors
    assert adoption_details["omittedPermissions"] == ["queue.write"], adoption_details
    scrubbed = scrub_text("key file /mnt/secrets/signing/key.pem token=hunter2 USK@private/insert", repo_root)
    assert "/mnt/secrets/signing/key.pem" not in scrubbed
    assert "hunter2" not in scrubbed
    assert "USK@private" not in scrubbed
    repo_tmp_path = repo_root / "build/tmp-release-certification/app-platform-smoke/summary.json"
    assert (
        scrub_text(str(repo_tmp_path), repo_root)
        == "<repo>/build/tmp-release-certification/app-platform-smoke/summary.json"
    )
    with tempfile.TemporaryDirectory(prefix="cryptad-app-smoke-symlink-target-") as target_name:
        with tempfile.TemporaryDirectory(prefix="cryptad-app-smoke-symlink-parent-") as link_parent_name:
            symlink_root = Path(link_parent_name) / "repo-link"
            try:
                symlink_root.symlink_to(Path(target_name), target_is_directory=True)
            except (NotImplementedError, OSError):
                symlink_root = None
            if symlink_root is not None:
                symlink_repo_root = symlink_root / "repo"
                symlink_path = symlink_repo_root / "build/tmp-release-certification/app-platform-smoke/summary.json"
                assert (
                    scrub_text(str(symlink_path), symlink_repo_root)
                    == "<repo>/build/tmp-release-certification/app-platform-smoke/summary.json"
                )
    assert (
        normalize_redacted_separators(r"<repo>\build\tmp-release-certification\app-platform-smoke\summary.json")
        == "<repo>/build/tmp-release-certification/app-platform-smoke/summary.json"
    )
    windows_scrubbed = scrub_text(
        r"key file D:\keys\signing.pem and \\builder\share\certs\catalog.pem",
        repo_root,
    )
    assert r"D:\keys" not in windows_scrubbed, windows_scrubbed
    assert r"\\builder\share" not in windows_scrubbed, windows_scrubbed
    assert "<path>/signing.pem" in windows_scrubbed, windows_scrubbed
    assert "<path>/catalog.pem" in windows_scrubbed, windows_scrubbed
    file_uri_scrubbed = scrub_text(
        "metadata file:///home/alice/signing/key.pem file:///D:/keys/catalog.pem",
        repo_root,
    )
    assert "/home/alice/signing" not in file_uri_scrubbed, file_uri_scrubbed
    assert "D:/keys" not in file_uri_scrubbed, file_uri_scrubbed
    assert "file://<path>/key.pem" in file_uri_scrubbed, file_uri_scrubbed
    assert "file://<path>/catalog.pem" in file_uri_scrubbed, file_uri_scrubbed
    route_scrubbed = scrub_text(
        "/apps/install /apps/cert-smoke/runtime /api/v1/diagnostics "
        "/mnt/secrets/signing/key.pem",
        repo_root,
    )
    assert "/apps/install" in route_scrubbed, route_scrubbed
    assert "/apps/cert-smoke/runtime" in route_scrubbed, route_scrubbed
    assert "/api/v1/diagnostics" in route_scrubbed, route_scrubbed
    assert "/mnt/secrets/signing/key.pem" not in route_scrubbed, route_scrubbed
    assert "<path>/key.pem" in route_scrubbed, route_scrubbed
    signing_metadata = sanitize_value(
        {
            "privateKeyPresent": False,
            "privateKeySource": "missing",
            "publicKeyPresent": True,
            "publicKeySource": "environment",
            "secretMaterialRedacted": True,
            "privateKey": "actual-secret",
            "privateKeyFile": "/mnt/secrets/signing/key.pem",
            "token": "runtime-token",
            "path": "/apps/cert-smoke/runtime",
        },
        repo_root,
    )
    assert signing_metadata["privateKeyPresent"] is False, signing_metadata
    assert signing_metadata["privateKeySource"] == "missing", signing_metadata
    assert signing_metadata["publicKeyPresent"] is True, signing_metadata
    assert signing_metadata["publicKeySource"] == "environment", signing_metadata
    assert signing_metadata["secretMaterialRedacted"] is True, signing_metadata
    assert signing_metadata["privateKey"] == "<redacted>", signing_metadata
    assert signing_metadata["privateKeyFile"] == "<redacted>", signing_metadata
    assert signing_metadata["token"] == "<redacted>", signing_metadata
    assert signing_metadata["path"] == "/apps/cert-smoke/runtime", signing_metadata
    vault_metadata = sanitize_value(
        {
            "capabilities": list(APP_VAULT_CAPABILITIES),
            "secretValue": "stored-secret",
            "identityPrivateKey": "private-identity-key",
            "identitySeed": "identity-seed",
            "recoveryPhrase": "alpha beta gamma",
            "mnemonicPhrase": "delta epsilon zeta",
            "accountMnemonic": "eta theta iota",
            "publicIdentityId": "identity-public-id",
        },
        repo_root,
    )
    assert vault_metadata["capabilities"] == list(APP_VAULT_CAPABILITIES), vault_metadata
    assert vault_metadata["secretValue"] == "<redacted>", vault_metadata
    assert vault_metadata["identityPrivateKey"] == "<redacted>", vault_metadata
    assert vault_metadata["identitySeed"] == "<redacted>", vault_metadata
    assert vault_metadata["recoveryPhrase"] == "<redacted>", vault_metadata
    assert vault_metadata["mnemonicPhrase"] == "<redacted>", vault_metadata
    assert vault_metadata["accountMnemonic"] == "<redacted>", vault_metadata
    assert vault_metadata["publicIdentityId"] == "identity-public-id", vault_metadata
    vault_scrubbed = scrub_text(
        '{"identitySeed":"seed-secret","recoveryPhrase":"alpha beta","mnemonicPhrase":"delta epsilon",'
        '"accountMnemonic":"eta theta","secretValue":"vault-secret"} '
        "capability=vault.secrets.read",
        repo_root,
    )
    for forbidden in ("seed-secret", "alpha beta", "delta epsilon", "eta theta", "vault-secret"):
        assert forbidden not in vault_scrubbed, vault_scrubbed
    assert "vault.secrets.read" in vault_scrubbed, vault_scrubbed
    sandbox_check_metadata = sanitize_value(
        {
            "enforcedSupportLevel": True,
            "noSetenvCommand": True,
            "enforcedStatusToken": True,
        },
        repo_root,
    )
    assert sandbox_check_metadata["enforcedSupportLevel"] is True, sandbox_check_metadata
    assert sandbox_check_metadata["noSetenvCommand"] is True, sandbox_check_metadata
    assert sandbox_check_metadata["enforcedStatusToken"] == "<redacted>", sandbox_check_metadata
    credential_scrubbed = scrub_text(
        'Authorization: Bearer app-secret\n'
        'Cookie: session=abc; csrf=def\n'
        '{"token":"json-secret","authorization":"Bearer json-secret","password":"pw",'
        '"X-Crypta-App-Session":"browser-session"} '
        "authorization=Bearer inline-secret "
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=base64-secret "
        "privateKeyBase64=key-secret clientSecret=client-secret api_password=api-secret "
        "privateKeyPresent=false",
        repo_root,
    )
    for forbidden in (
        "Bearer app-secret",
        "session=abc",
        "csrf=def",
        "json-secret",
        '"pw"',
        "browser-session",
        "inline-secret",
        "base64-secret",
        "key-secret",
        "client-secret",
        "api-secret",
    ):
        assert forbidden not in credential_scrubbed, credential_scrubbed
    assert "Authorization: <redacted>" in credential_scrubbed, credential_scrubbed
    assert "Cookie: <redacted>" in credential_scrubbed, credential_scrubbed
    assert '"token":"<redacted>"' in credential_scrubbed, credential_scrubbed
    assert "authorization=<redacted>" in credential_scrubbed, credential_scrubbed
    assert "privateKeyPresent=false" in credential_scrubbed, credential_scrubbed
    delete_request = build_http_request(
        "DELETE", "http://127.0.0.1:8888/api/v1/apps/cert-smoke", "hunter2"
    )
    assert delete_request.data == b"formPassword=hunter2"
    assert "formPassword" not in delete_request.full_url
    assert delete_request.get_header("Content-type") == "application/x-www-form-urlencoded"

    get_request = build_http_request(
        "GET", "http://127.0.0.1:8888/api/v1/apps", data={"page": "one"}
    )
    assert get_request.data is None
    assert get_request.full_url.endswith("?page=one")
    remote_live_settings = Settings(
        workspace_root=repo_root.resolve(),
        out_dir=(repo_root / DEFAULT_OUT_DIR).resolve(),
        mode="pr",
        skip_gradle=True,
        cli_path=None,
        live=True,
        live_base_url="https://node.example.invalid:9443/admin?token=hunter2",
        live_form_password="secret",
        timeout_seconds=1,
    )
    remote_item = collect_live_evidence(remote_live_settings, {})
    remote_encoded = json.dumps(remote_item.to_json(), sort_keys=True)
    assert remote_item.status == "fail", remote_item
    assert "<redacted-remote-url>" in remote_encoded, remote_encoded
    for forbidden in ("node.example.invalid", "hunter2", "https://"):
        assert forbidden not in remote_encoded, f"remote live URL leaked {forbidden}"
    assert (
        overall_status(
            "release-candidate",
            [EvidenceItem("catalog.smoke", "missing", True, "missing", "<repo>/summary.json", {})],
        )
        == "fail"
    )
    assert (
        overall_status(
            "pr",
            [EvidenceItem("catalog.smoke", "missing", True, "missing", "<repo>/summary.json", {})],
        )
        == "warn"
    )
    assert (
        overall_status(
            "pr",
            [EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {})],
        )
        == "pass"
    )
    assert (
        overall_status(
            "release-candidate",
            [
                EvidenceItem("catalog.smoke", "pass", True, "passed", "<repo>/summary.json", {}),
                EvidenceItem("apphost.live", "skip", False, "not requested", "<repo>/summary.json", {}),
            ],
        )
        == "pass"
    )
    with tempfile.TemporaryDirectory(prefix="cryptad-app-review-key-self-test-") as key_temp:
        key_dir = Path(key_temp)
        base64_key = base64.b64encode(b"review-public-key").decode("ascii")
        base64_key_file = key_dir / "reviewer-public-base64.txt"
        base64_key_file.write_text("\n".join((base64_key[:8], base64_key[8:])), encoding="utf-8")
        assert (
            reviewer_public_key_base64(
                {"publicBase64": False, "publicFile": str(base64_key_file)}
            )
            == base64_key
        )
        raw_key = b"\xff\x00review-public-key"
        raw_key_file = key_dir / "reviewer-public.der"
        raw_key_file.write_bytes(raw_key)
        assert reviewer_public_key_base64(
            {"publicBase64": False, "publicFile": str(raw_key_file)}
        ) == base64.b64encode(raw_key).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="cryptad-app-smoke-self-test-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        python_fake_cli = workspace / "crypta-app-fake.py"
        python_fake_cli.write_text(fake_cli_python_source(), encoding="utf-8")
        python_contract = workspace / "python-fake-contract.json"
        python_fake_result = subprocess.run(
            [
                sys.executable,
                str(python_fake_cli),
                "api",
                "snapshot",
                "--output",
                str(python_contract),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert python_fake_result.returncode == 0, python_fake_result.stderr
        assert json.loads(python_contract.read_text(encoding="utf-8"))["contract"][
            "contractVersion"
        ] == 2
        fake_cli = make_fake_cli(workspace)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=fake_cli,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )
        summary, exit_code = run(settings)
        assert exit_code == 0, summary
        assert summary["status"] in {"pass", "warn"}, summary
        evidence_by_id = {item["id"]: item for item in summary["evidence"]}
        assert evidence_by_id["app-platform.first-party"]["status"] == "pass"
        assert evidence_by_id["app-platform.devtools-cli"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-1"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-1"]["requiredForReleaseCandidate"] is True
        contract_item = evidence_by_id["platform-api.contract"]
        assert contract_item["status"] == "pass", contract_item
        vault_item = evidence_by_id["app-vault.capabilities"]
        assert vault_item["status"] == "pass", vault_item
        assert vault_item["requiredForReleaseCandidate"] is True, vault_item
        assert vault_item["details"]["capabilities"] == list(APP_VAULT_CAPABILITIES), vault_item
        contract_details = contract_item["details"]
        assert contract_details["contractVersion"] == 2, contract_item
        assert contract_details["capabilityCount"] == 2, contract_item
        assert contract_details["endpointCount"] == 1, contract_item
        assert contract_details["stableCapabilities"] == [
            "platform.contract.read",
            "queue.read",
        ], contract_item
        assert contract_details["stableEndpoints"] == ["GET /queue"], contract_item
        assert contract_details["snapshotCommand"]["exitCode"] == 0, contract_item
        assert contract_details["verifier"]["cert-smoke"]["exitCode"] == 0, contract_item
        assert evidence_by_id["catalog.smoke"]["status"] in {"warn", "pass"}
        assert evidence_by_id["app-ui.design-system"]["status"] == "pass"
        assert evidence_by_id["app-ui.lint"]["status"] == "pass"
        assert evidence_by_id["app-ui.first-party-adoption"]["status"] == "pass"
        assert evidence_by_id["reference-apps.content"]["status"] == "pass"
        review_env_names = (
            "CRYPTAD_APP_REVIEWER_KEY_ID",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            "CRYPTAD_APP_REVIEW_POLICY_ID",
            "CRYPTAD_APP_REVIEW_POLICY_VERSION",
        )
        previous_review_env = {name: os.environ.get(name) for name in review_env_names}
        os.environ["CRYPTAD_APP_REVIEWER_KEY_ID"] = "cert-review"
        os.environ.pop("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", None)
        os.environ["CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"] = "ZmFrZQ=="
        os.environ.pop("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE", None)
        os.environ["CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64"] = "ZmFrZQ=="
        os.environ["CRYPTAD_APP_REVIEW_POLICY_ID"] = "crypta-app-review-v1"
        os.environ["CRYPTAD_APP_REVIEW_POLICY_VERSION"] = "1"
        try:
            first_party_review_item = collect_app_review_first_party_catalog_evidence(
                dataclasses.replace(
                    settings,
                    out_dir=(workspace / "build/first-party-review-catalog-smoke").resolve(),
                    mode="release-candidate",
                ),
                {"cli": fake_cli},
            )
        finally:
            for name, value in previous_review_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        assert first_party_review_item.status == "pass", first_party_review_item
        assert first_party_review_item.details["coverage"]["catalogAppsInspected"] == len(
            APP_IDS
        ), first_party_review_item
        assert first_party_review_item.details["coverage"]["trustedPositiveReceipts"] == len(
            APP_IDS
        ), first_party_review_item
        assert set(first_party_review_item.details["catalog"]["inspectedAppIds"]) == set(APP_IDS)

        def collect_ui_lint_with_fake_env(
            env_name: str, out_leaf: str
        ) -> tuple[EvidenceItem, Path]:
            previous = os.environ.get(env_name)
            os.environ[env_name] = "1"
            try:
                lint_settings = dataclasses.replace(
                    settings,
                    out_dir=(workspace / "build" / out_leaf).resolve(),
                    mode="release-candidate",
                )
                stale_json = (
                    lint_settings.out_dir / "artifacts/app-ui-lint/queue-manager.json"
                )
                stale_json.parent.mkdir(parents=True, exist_ok=True)
                stale_json.write_text(
                    json.dumps(
                        {
                            "appId": "queue-manager",
                            "uiMode": "static",
                            "applicable": True,
                            "summary": {"errors": 0, "warnings": 0, "notes": 0},
                            "findings": [],
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return collect_app_ui_lint_evidence(lint_settings, fake_cli), stale_json
            finally:
                if previous is None:
                    os.environ.pop(env_name, None)
                else:
                    os.environ[env_name] = previous

        missing_ui_lint_item, stale_ui_lint_json = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON",
            "missing-ui-lint-json",
        )
        assert missing_ui_lint_item.status == "fail", missing_ui_lint_item
        assert any(
            "JSON missing or malformed" in error
            for error in missing_ui_lint_item.details["errors"]
        ), missing_ui_lint_item
        assert not stale_ui_lint_json.exists(), stale_ui_lint_json
        malformed_ui_lint_item, _ = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON",
            "malformed-ui-lint-json",
        )
        assert malformed_ui_lint_item.status == "fail", malformed_ui_lint_item
        assert any(
            "JSON missing or malformed" in error
            for error in malformed_ui_lint_item.details["errors"]
        ), malformed_ui_lint_item
        wrong_ui_lint_item, _ = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP",
            "wrong-ui-lint-app",
        )
        assert wrong_ui_lint_item.status == "fail", wrong_ui_lint_item
        assert any(
            "appId mismatch" in error for error in wrong_ui_lint_item.details["errors"]
        ), wrong_ui_lint_item
        errored_ui_lint_item, _ = collect_ui_lint_with_fake_env(
            "CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS",
            "errored-ui-lint-report",
        )
        assert errored_ui_lint_item.status == "fail", errored_ui_lint_item
        assert any(
            "nonzero errors" in error for error in errored_ui_lint_item.details["errors"]
        ), errored_ui_lint_item
        assert evidence_by_id["apphost.sandbox-provider"]["status"] == "pass"
        assert evidence_by_id["apphost.sandbox-provider"]["details"]["liveBubblewrapRequired"] is False
        sandbox_checks = evidence_by_id["apphost.sandbox-provider"]["details"]["checks"]
        assert sandbox_checks["enforcedSupportLevel"] is True, sandbox_checks
        assert sandbox_checks["noSetenvCommand"] is True, sandbox_checks
        assert "enforcedStatusToken" not in sandbox_checks, sandbox_checks
        assert "noTokenSetenvCommand" not in sandbox_checks, sandbox_checks
        assert evidence_by_id["app-update.lifecycle"]["status"] == "pass"
        assert evidence_by_id["app-update.lifecycle"]["requiredForReleaseCandidate"] is True
        lifecycle_checks = evidence_by_id["app-update.lifecycle"]["details"]["checks"]
        assert lifecycle_checks["hostApplyWhenStoppedGate"] is True, lifecycle_checks
        assert lifecycle_checks["updateApplyRunningConflictTest"] is True, lifecycle_checks
        assert lifecycle_checks["updateApplyRunningConflictRouteTest"] is True, lifecycle_checks
        assert lifecycle_checks["candidateDetectionSemantics"] is True, lifecycle_checks
        assert lifecycle_checks["permissionDeltaReview"] is True, lifecycle_checks
        assert lifecycle_checks["lifecycleHandlerRoutesStageAndApply"] is True, lifecycle_checks
        assert lifecycle_checks["lifecycleServiceStagesVerifiedPlan"] is True, lifecycle_checks
        assert lifecycle_checks["lifecycleServiceApplyDelegatesToAppHost"] is True, lifecycle_checks
        assert evidence_by_id["app-update.rollback"]["status"] == "pass"
        assert evidence_by_id["app-update.rollback"]["requiredForReleaseCandidate"] is True
        rollback_checks = evidence_by_id["app-update.rollback"]["details"]["checks"]
        assert rollback_checks["restorePreviousBundleOnReplacementFailure"] is True, rollback_checks
        assert rollback_checks["mutableDirectoriesPreservedByUpdate"] is True, rollback_checks
        assert rollback_checks["mutableDirectoriesPreservedByRollback"] is True, rollback_checks
        encoded = json.dumps(summary, sort_keys=True)
        for forbidden in ("CRYPTAD_APP_TOKEN=secret", "formPassword=hunter2", str(workspace)):
            assert forbidden not in encoded, f"self-test leaked {forbidden}"
        stale_log = settings.out_dir / "artifacts/logs/stale-from-previous-run.log"
        stale_log.parent.mkdir(parents=True, exist_ok=True)
        stale_log.write_text("old command output\n", encoding="utf-8")
        rerun_summary, rerun_exit_code = run(settings)
        assert rerun_exit_code == 0, rerun_summary
        assert not stale_log.exists(), stale_log
        stale_sample_dir = sample_workspace(settings) / "cert-smoke-app"
        stale_sample_dir.mkdir(parents=True, exist_ok=True)
        stale_digest = stale_sample_dir / "cryptad-app.digest"
        stale_signature = stale_sample_dir / "cryptad-app.signature"
        stale_digest.write_text("digest=stale\n", encoding="utf-8")
        stale_signature.write_text("signature=stale\n", encoding="utf-8")
        fresh_cli_item, fresh_sample_paths = collect_cli_evidence(settings, fake_cli)
        assert fresh_cli_item.status == "pass", fresh_cli_item
        assert fresh_sample_paths["bundleDir"].is_dir(), fresh_sample_paths
        assert not stale_digest.exists(), stale_digest
        assert not stale_signature.exists(), stale_signature
        fresh_launcher = fresh_sample_paths["bundleDir"] / "bin/start.sh"
        fresh_launcher_text = fresh_launcher.read_text(encoding="utf-8")
        assert "trap cleanup INT TERM" in fresh_launcher_text, fresh_launcher_text
        assert "sleep 60" in fresh_launcher_text, fresh_launcher_text
        if os.name != "nt":
            assert os.access(fresh_launcher, os.X_OK), fresh_launcher

        previous_skip_pack_output = os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT")
        os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT"] = "1"
        try:
            missing_pack_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/missing-pack-smoke").resolve(),
                mode="release-candidate",
            )
            stale_zip = sample_workspace(missing_pack_settings) / "cert-smoke-app-0.1.0.zip"
            stale_zip.parent.mkdir(parents=True, exist_ok=True)
            stale_zip.write_bytes(b"stale")
            missing_pack_item, _ = collect_cli_evidence(missing_pack_settings, fake_cli)
        finally:
            if previous_skip_pack_output is None:
                os.environ.pop("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT", None)
            else:
                os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT"] = previous_skip_pack_output
        assert missing_pack_item.status == "fail", missing_pack_item
        assert "pack-output" in missing_pack_item.details["failedSteps"], missing_pack_item
        assert missing_pack_item.details["sample"]["zipExists"] is False, missing_pack_item
        assert not stale_zip.exists(), stale_zip

        previous_skip_catalog_output = os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT")
        os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT"] = "1"
        try:
            missing_catalog_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/missing-catalog-smoke").resolve(),
                mode="release-candidate",
            )
            missing_catalog_zip = sample_workspace(missing_catalog_settings) / "cert-smoke-app-0.1.0.zip"
            missing_catalog_zip.parent.mkdir(parents=True, exist_ok=True)
            missing_catalog_zip.write_bytes(b"zip")
            stale_catalog_dir = sample_workspace(missing_catalog_settings) / "catalog"
            stale_catalog_dir.mkdir(parents=True, exist_ok=True)
            stale_catalog = stale_catalog_dir / "cryptad-app-catalog.properties"
            stale_signature = stale_catalog_dir / "cryptad-app-catalog.signature"
            stale_catalog.write_text("catalog.id=stale\n", encoding="utf-8")
            stale_signature.write_text("signature=stale\n", encoding="utf-8")
            missing_catalog_item = collect_catalog_evidence(
                missing_catalog_settings,
                {"cli": fake_cli, "zip": missing_catalog_zip},
            )
        finally:
            if previous_skip_catalog_output is None:
                os.environ.pop("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT", None)
            else:
                os.environ["CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT"] = previous_skip_catalog_output
        assert missing_catalog_item.status == "fail", missing_catalog_item
        assert missing_catalog_item.details["catalogExists"] is False, missing_catalog_item
        assert not stale_catalog.exists(), stale_catalog
        assert not stale_signature.exists(), stale_signature

        review_env_names = (
            "CRYPTAD_APP_REVIEWER_KEY_ID",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
            "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            "CRYPTAD_APP_REVIEW_POLICY_ID",
            "CRYPTAD_APP_REVIEW_POLICY_VERSION",
        )
        previous_review_env = {name: os.environ.get(name) for name in review_env_names}
        os.environ["CRYPTAD_APP_REVIEWER_KEY_ID"] = "cert-review"
        os.environ.pop("CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE", None)
        os.environ["CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64"] = "ZmFrZQ=="
        os.environ["CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE"] = str(
            workspace / "missing-reviewer-public-key.pem"
        )
        os.environ.pop("CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64", None)
        os.environ["CRYPTAD_APP_REVIEW_POLICY_ID"] = "crypta-app-review-v1"
        os.environ["CRYPTAD_APP_REVIEW_POLICY_VERSION"] = "1"
        try:
            missing_review_key_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/missing-review-key-smoke").resolve(),
                mode="release-candidate",
            )
            missing_review_key_item = collect_app_review_first_party_catalog_evidence(
                missing_review_key_settings,
                {"cli": fake_cli, "zip": fresh_sample_paths["zip"]},
            )
        finally:
            for name, value in previous_review_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        assert missing_review_key_item.status == "fail", missing_review_key_item
        assert "trustedReviewerKeys" in missing_review_key_item.details, missing_review_key_item

        signing_env_names = (
            "CRYPTAD_APP_SIGNING_KEY_ID",
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
            "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
            "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        )
        previous_signing_env = {name: os.environ.get(name) for name in signing_env_names}
        os.environ["CRYPTAD_APP_SIGNING_KEY_ID"] = "cert-smoke"
        os.environ.pop("CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE", None)
        os.environ["CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64"] = "ZmFrZQ=="
        os.environ.pop("CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE", None)
        os.environ["CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64"] = "ZmFrZQ=="
        try:
            rc_skip_gradle_settings = dataclasses.replace(
                settings,
                out_dir=(workspace / "build/rc-skip-gradle-signing-smoke").resolve(),
                mode="release-candidate",
                skip_gradle=True,
            )
            rc_cli_item, rc_sample_paths = collect_cli_evidence(rc_skip_gradle_settings, fake_cli)
            assert rc_cli_item.status == "pass", rc_cli_item
            rc_signed_item = collect_signed_bundle_evidence(rc_skip_gradle_settings, rc_sample_paths)
        finally:
            for name, value in previous_signing_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        assert rc_signed_item.status == "fail", rc_signed_item
        assert rc_signed_item.details["firstPartySignVerifyRan"] is False, rc_signed_item
        assert "first-party sign/verify Gradle task was skipped" in rc_signed_item.details["failures"], rc_signed_item

        live_calls: list[tuple[str, str]] = []
        original_http_request_json = http_request_json

        def fake_http_request_json(
            method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
        ) -> tuple[int, Any]:
            parsed_path = urllib.parse.urlparse(url).path.removeprefix("/api/v1")
            live_calls.append((method, parsed_path))
            if method == "GET" and parsed_path == "/apps":
                return 200, {"apps": []}
            if method == "DELETE" and parsed_path == "/apps/cert-smoke":
                return 404, {"missing": True}
            if method == "POST" and parsed_path == "/apps/install":
                return 200, {"installed": True}
            if method == "GET" and parsed_path == "/apps/cert-smoke/runtime":
                return 500, {"error": "boom"}
            if method == "POST" and parsed_path == "/apps/cert-smoke/stop":
                return 200, {"stopped": True}
            return 200, {}

        globals()["http_request_json"] = fake_http_request_json
        try:
            live_failure_settings = dataclasses.replace(
                settings,
                live=True,
                live_base_url="http://127.0.0.1:8888",
                live_form_password="secret",
            )
            live_bundle_dir = sample_workspace(settings) / "cert-smoke-app"
            assert live_bundle_dir.is_dir(), live_bundle_dir
            live_failure_item = collect_live_evidence(live_failure_settings, {"bundleDir": live_bundle_dir})
        finally:
            globals()["http_request_json"] = original_http_request_json
        assert live_failure_item.status == "fail", live_failure_item
        cleanup_paths = [(step["method"], step["path"]) for step in live_failure_item.details["cleanupSteps"]]
        assert ("POST", "/apps/cert-smoke/stop") in cleanup_paths, live_failure_item
        assert ("DELETE", "/apps/cert-smoke") in cleanup_paths, live_failure_item
        assert live_calls[-2:] == cleanup_paths, live_calls

        live_success_calls: list[tuple[str, str]] = []

        def fake_success_http_request_json(
            method: str, url: str, form_password: str = "", data: dict[str, str] | None = None
        ) -> tuple[int, Any]:
            parsed_path = urllib.parse.urlparse(url).path.removeprefix("/api/v1")
            live_success_calls.append((method, parsed_path))
            if method == "GET" and parsed_path == "/apps":
                return 200, {"apps": []}
            if method == "GET" and parsed_path == "/diagnostics":
                return 200, {
                    "sectionCount": 2,
                    "plainTextExport": "Peer 198.51.100.10 operator-private-line",
                    "sections": [
                        {"title": "Node", "lines": ["operator-private-line"]},
                        {"title": "Peers", "lines": ["198.51.100.10"]},
                    ],
                    "legacyAdmin": {
                        "surfaces": [
                            {
                                "id": "queue",
                                "path": "/queue/",
                                "state": "PRIMARY_REPLACED",
                                "count": 3,
                                "replacementResponseCount": 2,
                                "blockedMutatingRequestCount": 1,
                                "fallbackRenderCount": 0,
                                "retainedOrPendingRenderCount": 0,
                            },
                            {
                                "id": "stats",
                                "path": "/stats/",
                                "state": "PENDING",
                                "count": 2,
                                "replacementResponseCount": 0,
                                "blockedMutatingRequestCount": 0,
                                "fallbackRenderCount": 0,
                                "retainedOrPendingRenderCount": 2,
                            },
                        ]
                    },
                }
            return 200, {"ok": True}

        globals()["http_request_json"] = fake_success_http_request_json
        try:
            live_success_item = collect_live_evidence(live_failure_settings, {"bundleDir": live_bundle_dir})
        finally:
            globals()["http_request_json"] = original_http_request_json
        assert live_success_item.status == "pass", live_success_item
        diagnostics_step = next(
            step for step in live_success_item.details["steps"] if step["path"] == "/diagnostics"
        )
        assert diagnostics_step["bodySummary"] == {
            "sectionCount": 2,
            "legacyAdminSurfaceCount": 2,
            "legacyAdminTotalCount": 5,
            "legacyAdminReplacementResponseTotal": 2,
            "legacyAdminBlockedMutatingRequestTotal": 1,
            "legacyAdminFallbackRenderTotal": 0,
            "legacyAdminRetainedOrPendingRenderTotal": 2,
        }, diagnostics_step
        assert "body" not in diagnostics_step, diagnostics_step
        live_success_encoded = json.dumps(live_success_item.to_json(), sort_keys=True)
        for forbidden in ("plainTextExport", "operator-private-line", "198.51.100.10", "sections"):
            assert forbidden not in live_success_encoded, live_success_encoded
        assert ("GET", "/diagnostics") in live_success_calls, live_success_calls

        external_out_dir = Path(temp_name) / "external-app-smoke"
        external_settings = dataclasses.replace(settings, out_dir=external_out_dir.resolve())
        external_summary, external_exit_code = run(external_settings)
        assert external_exit_code == 0, external_summary
        assert external_summary["summaryPath"].startswith("<workdir>/"), external_summary
        assert external_summary["reportPath"].startswith("<workdir>/"), external_summary
        assert (external_out_dir / SUMMARY_FILE_NAME).is_file(), external_summary
        assert str(external_out_dir) not in json.dumps(external_summary, sort_keys=True), external_summary


def make_self_test_workspace(workspace: Path) -> None:
    sdk = workspace / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    sdk.parent.mkdir(parents=True, exist_ok=True)
    sdk.write_text("window.CryptaPlatform = {}; const h = 'X-Crypta-App-Session';\n", encoding="utf-8")
    design_dir = workspace / "platform-design-system/src/main/resources/network/crypta/platform/designsystem/static"
    design_dir.mkdir(parents=True, exist_ok=True)
    (design_dir / "crypta-ui-tokens.css").write_text(":root{--cr-space-4:1rem;}\n", encoding="utf-8")
    (design_dir / "crypta-ui.css").write_text(".cr-app{}.cr-shell{}.cr-button{}\n", encoding="utf-8")
    (design_dir / "crypta-ui-components.js").write_text('window.CryptaUi={version:"1"};\n', encoding="utf-8")
    for project, app_id, display_name, launcher, permissions, app_js in (
        (
            "queue-manager",
            "queue-manager",
            "Queue Manager",
            "queue-manager.sh",
            "queue.read,queue.write",
            "CryptaPlatform.bootstrap.load({ appId: 'queue-manager' });\n",
        ),
        (
            "publisher",
            "publisher",
            "Publisher",
            "publisher.sh",
            "queue.read,queue.write,content.insert",
            "CryptaPlatform.bootstrap.load({ appId: 'publisher' });\n",
        ),
        (
            "site-publisher",
            "site-publisher",
            "Site Publisher",
            "site-publisher.sh",
            "queue.read,queue.write,content.insert",
            "const appId = 'site-publisher';\n"
            "CryptaPlatform.bootstrap.load({ appId });\n"
            "CryptaPlatform.content.insertDirectory(new FormData());\n"
            "CryptaPlatform.content.insertFile(new FormData());\n"
            "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
        ),
    ):
        source = workspace / f"apps/{project}/src/staged"
        staged = workspace / f"apps/{project}/build/cryptad-app/{app_id}"
        for root in (source, staged):
            (root / "bin").mkdir(parents=True, exist_ok=True)
            (root / "static/crypta-ui").mkdir(parents=True, exist_ok=True)
            (root / "bin" / launcher).write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
            permission_items = "".join(f"<li><code>{permission}</code></li>" for permission in permissions.split(","))
            (root / "static/index.html").write_text(
                "<!doctype html><html lang=\"en\"><head>"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                f"<title>{display_name}</title>"
                "<link rel=\"stylesheet\" href=\"./crypta-ui/crypta-ui-tokens.css\">"
                "<link rel=\"stylesheet\" href=\"./crypta-ui/crypta-ui.css\">"
                "<link rel=\"stylesheet\" href=\"./app.css\">"
                "</head><body class=\"cr-app\"><main class=\"cr-shell\">"
                f"<section class=\"cr-permission-summary\" data-crypta-permission-summary><ul>{permission_items}</ul></section>"
                f"<h1>{display_name}</h1>"
                "</main><script src=\"./crypta-platform.js\"></script><script src=\"./app.js\"></script></body></html>",
                encoding="utf-8",
            )
            (root / "static/app.js").write_text(
                app_js,
                encoding="utf-8",
            )
            (root / "static/app.css").write_text("body { color: #111; }\n", encoding="utf-8")
            for asset_name in design_system_asset_names():
                shutil.copy2(design_dir / asset_name, root / "static/crypta-ui" / asset_name)
            shutil.copy2(sdk, root / "static/crypta-platform.js")
        (staged / "cryptad-app.properties").write_text(
            "\n".join(
                [
                    "manifest.version=1",
                    f"app.id={app_id}",
                    f"app.name={display_name}",
                    "app.version=0.1.0",
                    "api.minimumVersion=3",
                    "api.maximumTestedVersion=3",
                    "api.experimentalCapabilitiesAccepted=false",
                    f"app.exec=bin/{launcher}",
                    "app.ui.mode=static",
                    "app.ui.entry=static/index.html",
                    f"app.permissions={permissions}",
                    "quota.data.bytes=0",
                    "quota.cache.bytes=0",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        if app_id == "site-publisher":
            (workspace / "apps/site-publisher/README.md").write_text(
                "Site Publisher is the first content reference app. "
                "Identity-backed publishing is future work.\n",
                encoding="utf-8",
            )
    registry = workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text((Path(__file__).parent / "fixtures" / "self-test-legacy-registry.java-fragment").read_text(encoding="utf-8"), encoding="utf-8")
    docs = workspace / "docs/legacy-retirement-plan.md"
    docs.parent.mkdir(parents=True, exist_ok=True)
    docs.write_text(
        "legacy-admin.removal-wave-1 documents that removed routes return replacement responses "
        "when the replacement is reachable and render legacy fallback when the replacement is unavailable. "
        "FProxy browse remains retained, and retained and pending legacy routes remain reachable.\n",
        encoding="utf-8",
    )
    legacy_admin_dir = workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http"
    (legacy_admin_dir / "LegacyAdminRemovalPolicy.java").write_text(
        'class LegacyAdminRemovalPolicy { boolean matchesCanonicalPageOrSlashlessAlias; '
        'boolean replacementAvailable; boolean isStaticAppUiAvailable; boolean primaryUiRoot; '
        'String m = "GET HEAD"; Object d = LegacyAdminRemovalDecision.redirect(null); '
        'Object b = LegacyAdminRemovalDecision.blockedMutation(null); }\n',
        encoding="utf-8",
    )
    (legacy_admin_dir / "LegacyAdminReplacementResponse.java").write_text(
        'class LegacyAdminReplacementResponse { String link = "replacementUrl"; }\n',
        encoding="utf-8",
    )
    (legacy_admin_dir / "LegacyAdminUsageRecorder.java").write_text(
        "class LegacyAdminUsageRecorder { Object a = LegacyAdminUsageEvent.REPLACEMENT_RESPONSE; }\n",
        encoding="utf-8",
    )
    usage_dto = workspace / "runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java"
    usage_dto.parent.mkdir(parents=True, exist_ok=True)
    usage_dto.write_text(
        "record LegacyAdminSurfaceUsage(long replacementResponseCount, "
        "long blockedMutatingRequestCount, long fallbackRenderCount, "
        "long retainedOrPendingRenderCount) {}\n",
        encoding="utf-8",
    )
    diagnostics_handler = workspace / "platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java"
    diagnostics_handler.parent.mkdir(parents=True, exist_ok=True)
    diagnostics_handler.write_text(
        "class DiagnosticsApiHandler { String a = \"replacementResponseCount "
        "blockedMutatingRequestCount fallbackRenderCount retainedOrPendingRenderCount\"; }\n",
        encoding="utf-8",
    )
    app_vault_doc = workspace / APP_VAULT_DOC
    app_vault_doc.write_text(
        "The app secret and identity vault defines vault.secrets.read, vault.secrets.write, "
        "vault.identities.read, vault.identities.create, vault.identities.use, and "
        "vault.identities.manage. It distinguishes app-owned identities from shared identities. "
        "Process callers use CRYPTAD_APP_TOKEN, while browser callers use app browser sessions. "
        "At-rest local protection has limits and depends on the host account. Grant lifecycle "
        "checks cover update, rollback, uninstall, and reinstall. Audit and redaction omit secret "
        "values and identity private material. Future content, social, and mail features can use "
        "the same extension point.\n",
        encoding="utf-8",
    )
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    devtools_dir.mkdir(parents=True, exist_ok=True)
    (devtools_dir / "DevtoolsCapabilityVocabulary.java").write_text(
        "\n".join(APP_VAULT_CAPABILITIES) + "\n",
        encoding="utf-8",
    )
    (workspace / APP_UI_DESIGN_SYSTEM_DOC).write_text(
        "crypta-platform.js loads before app.js. Static apps load crypta-ui-tokens.css, "
        "crypta-ui.css, then app.css. Use cr-shell and cr-button classes. "
        "Content-Security-Policy includes connect-src. Accessibility requires aria labels. "
        "Permission disclosure mirrors app.permissions. Run crypta-app ui lint --bundle-dir. "
        "First-party Queue Manager, Publisher, and Site Publisher use this guidance. Warnings "
        "become failure in release-candidate evidence.\n",
        encoding="utf-8",
    )
    sandbox_dir = workspace / "platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox"
    sandbox_test_dir = workspace / "platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    sandbox_test_dir.mkdir(parents=True, exist_ok=True)
    (sandbox_dir / "BubblewrapSandboxProvider.java").write_text(
        'class BubblewrapSandboxProvider { static final String PROVIDER_NAME = "bubblewrap"; '
        'Object level = AppSandboxSupportLevel.ENFORCED; Object env = checkedContext.environment(); }\n',
        encoding="utf-8",
    )
    (sandbox_dir / "BubblewrapCommandBuilder.java").write_text(
        'class BubblewrapCommandBuilder { void command() { command.add("--"); } }\n',
        encoding="utf-8",
    )
    (sandbox_dir / "BubblewrapAvailability.java").write_text(
        "class BubblewrapAvailability { }\n", encoding="utf-8"
    )
    (sandbox_dir / "AppSandboxProviders.java").write_text(
        "class AppSandboxProviders { BubblewrapSandboxProvider provider; }\n", encoding="utf-8"
    )
    (sandbox_test_dir / "BubblewrapSandboxProviderTest.java").write_text(
        "class BubblewrapSandboxProviderTest { }\n", encoding="utf-8"
    )
    apphost = workspace / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java"
    apphost.parent.mkdir(parents=True, exist_ok=True)
    apphost.write_text(
        """
class LocalProcessAppHost {
  private static final String TEMP_UPDATE_BACKUP_PREFIX = "app-install-backup-";
  private static final String TEMP_ROLLBACK_BACKUP_PREFIX = "app-rollback-backup-";
  InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory) throws IOException {
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot update a running app: " + normalizedAppId);
    }
    Path rollbackAppsDir = ensureRollbackAppsDirectory();
    Path backupInstallRoot = temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");
    Path rollbackRoot = rollbackRootFor(normalizedAppId);
    Path previousRollbackBackupRoot = temporaryManagedPath(rollbackAppsDir, TEMP_ROLLBACK_BACKUP_PREFIX + normalizedAppId + "-");
    copyDirectoryTree(stagingRoot, temporaryInstallRoot);
    verifyCopiedBundle(temporaryInstallRoot);
    AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);
    requireMatchingUpdateTarget(normalizedAppId, manifest);
    replaceInstalledBundle(paths.installedRoot(), temporaryInstallRoot, backupInstallRoot, rollbackRoot, previousRollbackBackupRoot);
    cancelPendingRestartAfterAcceptedUpdate(normalizedAppId);
    return new InstalledAppSnapshot(manifest, paths);
  }
  Optional<AppRollbackRecord> rollbackStatus(String appId) throws IOException {
    return Optional.of(new AppRollbackRecord(appId));
  }
  InstalledAppSnapshot rollback(String appId) throws IOException {
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot rollback a running app: " + normalizedAppId);
    }
    Path rollbackRoot = rollbackRootFor(normalizedAppId);
    Path currentInstallBackupRoot = temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");
    swapInstalledBundleWithRollback(paths.installedRoot(), rollbackRoot, currentInstallBackupRoot);
    return new InstalledAppSnapshot(manifest, paths);
  }
  private Path rollbackRootFor(String appId) { return layout.rollbackAppsDir().resolve(appId); }
  private Path ensureRollbackAppsDirectory() { return layout.rollbackAppsDir(); }
  private void replaceInstalledBundle(Path installedRoot, Path replacementRoot, Path backupRoot, Path rollbackRoot, Path previousRollbackBackupRoot) throws IOException {
    moveIntoPlace(installedRoot, backupRoot);
    try {
      moveIntoPlace(replacementRoot, installedRoot);
      moveIntoPlace(backupRoot, rollbackRoot);
    } catch (IOException updateFailure) {
      restoreInstalledBundle(installedRoot, backupRoot, updateFailure);
      restorePreviousRollback(rollbackRoot, previousRollbackBackupRoot, true, updateFailure);
      throw updateFailure;
    }
    deleteBackupAfterSuccessfulReplacement(previousRollbackBackupRoot, true);
  }
  private void swapInstalledBundleWithRollback(Path installedRoot, Path rollbackRoot, Path currentInstallBackupRoot) throws IOException {
    moveIntoPlace(installedRoot, currentInstallBackupRoot);
    moveIntoPlace(rollbackRoot, installedRoot);
    moveIntoPlace(currentInstallBackupRoot, rollbackRoot);
  }
  private void deleteBackupAfterSuccessfulReplacement(Path backupRoot, boolean backupPresent) throws IOException {
    throw new IOException("simulated backup cleanup failure");
  }
  private static void restoreInstalledBundle(Path installedRoot, Path backupRoot, IOException updateFailure) throws IOException {
    moveIntoPlace(backupRoot, installedRoot);
  }
  private static void restorePreviousRollback(Path rollbackRoot, Path backupRoot, boolean backupPresent, IOException updateFailure) throws IOException {
  }
}
""",
        encoding="utf-8",
    )
    apphost_test = (
        workspace
        / "platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java"
    )
    apphost_test.parent.mkdir(parents=True, exist_ok=True)
    apphost_test.write_text(
        """
class LocalProcessAppHostTest {
  void updateFromDirectory_whenInstalledStoppedApp_expectManifestAndExecutableReplacedPreservingMutableDirs() {
    String data = "preserve-data.txt";
    String cache = "preserve-cache.txt";
    String run = "preserve-run.txt";
  }
  void updateFromDirectory_whenReplacingStoppedApp_expectPreviousBundleRecordedForRollback() {
    AtomicInteger cleanupAttempts = new AtomicInteger();
    LocalProcessAppHost host = allowUnsignedHost(_ -> {
      cleanupAttempts.incrementAndGet();
      throw new IOException("simulated backup cleanup failure");
    });
    Path firstUpdatedStage =
        stageInstalledAppAt(tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("first").resolve(SAMPLE_APP_ID));
    InstalledAppSnapshot firstUpdate = host.updateFromDirectory(SAMPLE_APP_ID, firstUpdatedStage);
    assertEquals(0, cleanupAttempts.get());
    Path secondUpdatedStage =
        stageInstalledAppAt(tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("second").resolve(SAMPLE_APP_ID));
    host.updateFromDirectory(SAMPLE_APP_ID, secondUpdatedStage);
    assertEquals(
        firstUpdate.manifest().appVersion(),
        host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
    assertEquals(1, cleanupAttempts.get());
  }
  void rollback_whenPreviousBundleExists_expectRestoresBundleAndPreservesMutableDirs() {
    String data = "rollback-data.txt";
    String cache = "rollback-cache.txt";
    String run = "rollback-run.txt";
  }
  void rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged() {}
  void rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths() {}
}
""",
        encoding="utf-8",
    )
    appupdates_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates"
    appupdates_dir.mkdir(parents=True, exist_ok=True)
    (appupdates_dir / "AppUpdatePolicyMode.java").write_text(
        """
enum AppUpdatePolicyMode {
  MANUAL("manual"),
  STAGE("stage"),
  APPLY_WHEN_STOPPED("apply_when_stopped");
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateCandidateStatus.java").write_text(
        """
enum AppUpdateCandidateStatus {
  AVAILABLE("available"),
  STAGED("staged"),
  BLOCKED("blocked"),
  INCOMPATIBLE("incompatible"),
  AMBIGUOUS("ambiguous"),
  ROLLBACK_AVAILABLE("rollback_available");
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateCandidate.java").write_text(
        """
record AppUpdateCandidate() {
  Map<String, Object> toJsonValue() {
    json.put("review", review);
    json.put("apiCompatibility", apiCompatibility);
    json.put("permissionDelta", permissionDelta(candidatePermissions, installedPermissions));
    return json;
  }
  static Map<String, Object> reviewSummary(String status, String note) { return Map.of(); }
  static Map<String, Object> permissionDelta(List<String> candidatePermissions, List<String> local) { return Map.of(); }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdateService.java").write_text(
        """
class AppUpdateService {
  public synchronized Map<String, Object> stage(String appId) {
    AppUpdateCandidate candidate = candidateOrDetect(appId, installed);
    AppCatalogInstallPlan plan = catalogManager.prepareInstallPlan(candidate.catalogId(), appId);
    if (planDiffersFromCandidate(candidate, installed, plan)) {
      throw new PlatformApiException(409, "update_candidate_changed", "changed");
    }
    stageCandidate(appId, installed, candidate);
    return summary(appId, installed);
  }

  public synchronized Map<String, Object> apply(String appId, ApplyOptions options) {
    InstalledAppSnapshot updated =
        appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory());
    closeStage(normalizedAppId);
    return summary(normalizedAppId, updated);
  }
}
""",
        encoding="utf-8",
    )
    (appupdates_dir / "AppUpdatesApiHandler.java").write_text(
        """
class AppUpdatesApiHandler {
  public Map<String, Object> stage(String appId) {
    return updateService.stage(appId);
  }

  public Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters) {
    return updateService.apply(appId, applyOptions(queryParameters));
  }
}
""",
        encoding="utf-8",
    )
    appupdates_test_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api/appupdates"
    appupdates_test_dir.mkdir(parents=True, exist_ok=True)
    (appupdates_test_dir / "AppUpdateServiceTest.java").write_text(
        """
class AppUpdateServiceTest {
  void apply_whenAppStartsAfterPrecheck_expectConflictNotServerError() {
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppHostException("cannot update a running app: " + APP_ID));
    assertEquals("app_running", exception.errorCode());
  }
}
""",
        encoding="utf-8",
    )
    router_test = workspace / "src/test/java/network/crypta/platform/api/PlatformApiRouterTest.java"
    router_test.parent.mkdir(parents=True, exist_ok=True)
    router_test.write_text(
        """
class PlatformApiRouterTest {
  void route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson() {
    PlatformApiResponse response =
        updateRouter.route(request("POST", List.of("apps", APP_ID, "updates", "apply"), Map.of()));
    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\\\"code\\\":\\\"app_running\\\""));
    verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir);
  }
}
""",
        encoding="utf-8",
    )
    catalog_handler = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    catalog_handler.parent.mkdir(parents=True, exist_ok=True)
    catalog_handler.write_text(
        """
class AppCatalogsApiHandler {
  void summarize() {
    json.put("versionDifferent", versionDifferent(entry.version(), installedVersion, installed != null));
    json.put("updateAvailable", updateAvailable(entry.version(), installedVersion, installed != null).orElse(null));
    json.put("review", summarizeReview(entry.review()));
    json.put("compatibility", summarizeCompatibility(entry.compatibility()));
    json.put("apiCompatibility", apiCompatibility(entry.compatibility().apiCompatibility(), entry.permissions()));
    json.put("permissionDelta", summarizePermissionDelta(entry.permissions(), installed));
    AppCatalogInstallPlan plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
    InstalledAppSnapshot updated = appHost.updateFromDirectory(entry.appId(), plan.stagedBundleDirectory());
  }
  private static boolean versionDifferent(String catalogVersion, String installedVersion, boolean installed) { return false; }
  private static Optional<Boolean> updateAvailable(String catalogVersion, String installedVersion, boolean installed) { return Optional.empty(); }
}
""",
        encoding="utf-8",
    )
    lifecycle_doc = workspace / "docs/app-update-lifecycle.md"
    lifecycle_doc.write_text(
        """
AppHost v1 uses an `apply_when_stopped` policy.
Silent automatic update is not the default.
Applying an update requires an operator or explicit API caller.
The policy modes are manual, stage, and apply_when_stopped.
Rollback covers only the immutable installed bundle.
Rollback does not roll back app data directories or app cache directories.
""",
        encoding="utf-8",
    )


def fake_cli_python_source() -> str:
    return r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


def option_value(args, name):
    for index, value in enumerate(args):
        if value == name and index + 1 < len(args):
            return args[index + 1]
    return ""


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def property_value(path, name):
    if not path.is_file():
        return ""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1]
    return ""


def init_app(args):
    directory_text = option_value(args, "--dir")
    if not directory_text:
        return 2
    directory = Path(directory_text)
    (directory / "bin").mkdir(parents=True, exist_ok=True)
    (directory / "static/crypta-ui").mkdir(parents=True, exist_ok=True)
    write_text(
        directory / "cryptad-app.properties",
        "\n".join(
            [
                "manifest.version=1",
                "app.id=cert-smoke",
                "app.name=Certification Smoke",
                "app.version=0.1.0",
                "app.exec=bin/start.sh",
                "api.minimumVersion=1",
                "api.maximumTestedVersion=1",
                "api.experimentalCapabilitiesAccepted=false",
                "app.ui.mode=static",
                "app.ui.entry=static/index.html",
                "app.permissions=queue.read",
            ]
        )
        + "\n",
    )
    write_text(directory / "bin/start.sh", "#!/usr/bin/env sh\nexit 0\n")
    write_text(
        directory / "static/index.html",
        '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Certification Smoke</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary><code>queue.read</code></section><h1>Certification Smoke</h1></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>\n',
    )
    write_text(
        directory / "static/app.js",
        'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });\n',
    )
    write_text(directory / "static/app.css", "body{}\n")
    write_text(directory / "static/crypta-ui/crypta-ui-tokens.css", ":root{--cr-space-4:1rem;}\n")
    write_text(directory / "static/crypta-ui/crypta-ui.css", ".cr-app{}.cr-shell{}.cr-button{}\n")
    write_text(directory / "static/crypta-ui/crypta-ui-components.js", 'window.CryptaUi={version:"1"};\n')
    write_text(
        directory / "static/crypta-platform.js",
        'window.CryptaPlatform={}; X="X-Crypta-App-Session";\n',
    )
    return 0


def ui_lint(args):
    output_text = option_value(args, "--json")
    bundle_text = option_value(args, "--bundle-dir")
    app_id = "cert-smoke"
    ui_mode = "static"
    if bundle_text:
        manifest = Path(bundle_text) / "cryptad-app.properties"
        app_id = property_value(manifest, "app.id") or app_id
        ui_mode = property_value(manifest, "app.ui.mode") or ui_mode
    payload = {
        "appId": app_id,
        "uiMode": ui_mode,
        "applicable": True,
        "summary": {"errors": 0, "warnings": 0, "notes": 0},
        "findings": [],
    }
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP") == "1":
        payload["appId"] = "wrong-app"
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS") == "1":
        payload["summary"]["errors"] = 1
        payload["findings"] = [{"id": "fake-error", "severity": "error"}]
    if output_text:
        if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON") == "1":
            return 0
        if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON") == "1":
            write_text(Path(output_text), "{not-json\n")
            return 0
        write_text(Path(output_text), json.dumps(payload, sort_keys=True) + "\n")
    return 0


def pack_app(args):
    output_text = option_value(args, "--output")
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT") == "1":
        return 0
    if not output_text:
        return 2
    output = Path(output_text)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"zip")
    return 0


def create_catalog(args):
    catalog_text = option_value(args, "--catalog-file")
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT") == "1":
        return 0
    if not catalog_text:
        return 2
    entries = []
    review_receipts = []
    catalog_id = option_value(args, "--catalog-id") or "cert-smoke"
    catalog_name = option_value(args, "--name") or "Certification Smoke Apps"
    generated_at = option_value(args, "--generated-at") or "2026-05-01T00:00:00Z"
    index = 0
    while index < len(args):
        if args[index] == "--entry" and index + 1 < len(args):
            entries.append(Path(args[index + 1]))
            index += 2
            continue
        if args[index] == "--review-receipt" and index + 1 < len(args):
            review_receipts.append(Path(args[index + 1]))
            index += 2
            continue
        index += 1
    if not entries:
        entries = [Path("cert-smoke-entry.properties")]
    catalog = Path(catalog_text)
    app_ids = []
    lines = [
        "catalog.version=1",
        f"catalog.id={catalog_id}",
        f"catalog.name={catalog_name}",
        f"catalog.generatedAt={generated_at}",
    ]
    app_lines = []
    for descriptor in entries:
        app_id = property_value(descriptor, "app.id") or "cert-smoke"
        app_ids.append(app_id)
        artifact_path = Path(property_value(descriptor, "artifact.path") or "/tmp/cert-smoke.zip")
        artifact_size = artifact_path.stat().st_size if artifact_path.is_file() else 3
        app_lines.extend(
            [
                f"app.{app_id}.id={app_id}",
                f"app.{app_id}.name={property_value(descriptor, 'name') or 'Certification Smoke'}",
                f"app.{app_id}.version={property_value(descriptor, 'version') or '0.1.0'}",
                f"app.{app_id}.summary={property_value(descriptor, 'summary') or 'Certification smoke app.'}",
                f"app.{app_id}.bundle.uri={property_value(descriptor, 'bundle.uri') or 'file:///tmp/cert-smoke.zip'}",
                "app." + app_id + ".bundle.sha256=0000000000000000000000000000000000000000000000000000000000000000",
                f"app.{app_id}.bundle.size.bytes={artifact_size}",
                f"app.{app_id}.bundle.type=zip",
                f"app.{app_id}.permissions={property_value(descriptor, 'permissions') or 'queue.read'}",
            ]
        )
        if review_receipts:
            app_lines.extend(
                [
                    f"app.{app_id}.review.receipt.status=reviewed",
                    f"app.{app_id}.review.receipt.reviewer.key.id=cert-review",
                    f"app.{app_id}.review.receipt.policy.id=crypta-app-review-v1",
                    f"app.{app_id}.review.receipt.policy.version=1",
                ]
            )
    lines.append("catalog.entries=" + ",".join(app_ids))
    lines.extend(app_lines)
    write_text(catalog, "\n".join(lines) + "\n")
    return 0


def api_snapshot(args):
    output_text = option_value(args, "--output")
    if not output_text:
        return 2
    output = Path(output_text)
    write_text(
        output,
        json.dumps(
            {
                "contract": {
                    "apiVersion": "v1",
                    "contractVersion": 2,
                    "generatedBy": "cryptad",
                    "stabilityPolicy": "self-test",
                    "capabilities": [
                        {
                            "name": "queue.read",
                            "stability": "stable",
                            "sinceContractVersion": 1,
                            "deprecation": None,
                            "description": "Read queue state.",
                        },
                        {
                            "name": "platform.contract.read",
                            "stability": "stable",
                            "sinceContractVersion": 1,
                            "deprecation": None,
                            "description": "Read contract snapshots.",
                        },
                    ],
                    "endpoints": [
                        {
                            "routeFamily": "queue",
                            "method": "GET",
                            "routeTemplate": "/queue",
                            "actionLabel": "queue.read",
                            "requiredCapabilities": ["queue.read"],
                            "hostOperatorBypassAllowed": True,
                            "appProcessPrincipalsAllowed": True,
                            "appBrowserPrincipalsAllowed": True,
                            "stability": "stable",
                            "sinceContractVersion": 1,
                            "deprecation": None,
                            "description": "Read queue state.",
                        }
                    ],
                }
            },
            sort_keys=True,
        )
        + "\n",
    )
    return 0


def main():
    if len(sys.argv) < 2:
        return 0
    command = sys.argv[1]
    args = sys.argv[2:]
    if command == "init":
        return init_app(args)
    if command == "validate":
        return 0
    if command == "ui":
        subcommand = args[0] if args else ""
        if subcommand == "lint":
            return ui_lint(args[1:])
        return 0
    if command == "pack":
        return pack_app(args)
    if command == "catalog":
        subcommand = args[0] if args else ""
        if subcommand == "create":
            return create_catalog(args[1:])
        if subcommand in {"sign", "verify"}:
            return 0
    if command == "api":
        subcommand = args[0] if args else ""
        if subcommand == "snapshot":
            return api_snapshot(args[1:])
    if command == "compat":
        return 0
    if command in {"sign", "verify"}:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def make_fake_cli(workspace: Path) -> Path:
    bin_dir = workspace / "platform-devtools/build/install/crypta-app/bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cli = bin_dir / ("crypta-app.bat" if platform.system() == "Windows" else "crypta-app")
    if platform.system() == "Windows":
        helper = bin_dir / "crypta-app-fake.py"
        helper.write_text(fake_cli_python_source(), encoding="utf-8")
        cli.write_text(
            """@echo off
py -3 "%~dp0crypta-app-fake.py" %*
if not errorlevel 9009 exit /b %ERRORLEVEL%
python3 "%~dp0crypta-app-fake.py" %*
exit /b %ERRORLEVEL%
""",
            encoding="utf-8",
        )
    else:
        cli.write_text(
            """#!/usr/bin/env sh
set -eu
cmd="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
case "$cmd" in
  init)
    dir=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--dir" ]; then dir="$2"; shift 2; else shift; fi
    done
    mkdir -p "$dir/bin" "$dir/static/crypta-ui"
    printf '%s\n' 'manifest.version=1' 'app.id=cert-smoke' 'app.name=Certification Smoke' 'app.version=0.1.0' 'app.exec=bin/start.sh' 'api.minimumVersion=1' 'api.maximumTestedVersion=1' 'api.experimentalCapabilitiesAccepted=false' 'app.ui.mode=static' 'app.ui.entry=static/index.html' 'app.permissions=queue.read' > "$dir/cryptad-app.properties"
    printf '%s\n' '#!/usr/bin/env sh' 'exit 0' > "$dir/bin/start.sh"
    printf '%s\n' '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Certification Smoke</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary><code>queue.read</code></section><h1>Certification Smoke</h1></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>' > "$dir/static/index.html"
    printf '%s\n' 'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });' > "$dir/static/app.js"
    printf '%s\n' 'body{}' > "$dir/static/app.css"
    printf '%s\n' ':root{--cr-space-4:1rem;}' > "$dir/static/crypta-ui/crypta-ui-tokens.css"
    printf '%s\n' '.cr-app{}.cr-shell{}.cr-button{}' > "$dir/static/crypta-ui/crypta-ui.css"
    printf '%s\n' 'window.CryptaUi={version:"1"};' > "$dir/static/crypta-ui/crypta-ui-components.js"
    printf '%s\n' 'window.CryptaPlatform={}; X="X-Crypta-App-Session";' > "$dir/static/crypta-platform.js"
    ;;
  validate)
    exit 0
    ;;
  ui)
    sub="${1:-}"; shift || true
    if [ "$sub" = "lint" ]; then
      out=""
      bundle=""
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --json)
            out="$2"
            shift 2
            ;;
          --bundle-dir)
            bundle="$2"
            shift 2
            ;;
          *)
            shift
            ;;
        esac
      done
      if [ -n "$out" ]; then
        if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON:-0}" = "1" ]; then
          exit 0
        fi
        mkdir -p "$(dirname "$out")"
        if [ "${CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON:-0}" = "1" ]; then
          printf '%s\n' '{not-json' > "$out"
          exit 0
        fi
        app_id="cert-smoke"
        ui_mode="static"
        if [ -n "$bundle" ] && [ -f "$bundle/cryptad-app.properties" ]; then
          app_id="$(awk -F= '$1 == "app.id" {print substr($0, index($0, "=") + 1); exit}' "$bundle/cryptad-app.properties")"
          ui_mode="$(awk -F= '$1 == "app.ui.mode" {print substr($0, index($0, "=") + 1); exit}' "$bundle/cryptad-app.properties")"
          app_id="${app_id:-cert-smoke}"
          ui_mode="${ui_mode:-static}"
        fi
        if [ "${CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP:-0}" = "1" ]; then
          app_id="wrong-app"
        fi
        error_count="0"
        findings="[]"
        if [ "${CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS:-0}" = "1" ]; then
          error_count="1"
          findings='[{"id":"fake-error","severity":"error"}]'
        fi
        printf '{"appId":"%s","applicable":true,"findings":%s,"summary":{"errors":%s,"notes":0,"warnings":0},"uiMode":"%s"}\n' "$app_id" "$findings" "$error_count" "$ui_mode" > "$out"
      fi
      exit 0
    fi
    ;;
  pack)
    out=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--output" ]; then out="$2"; shift 2; else shift; fi
    done
    if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT:-0}" = "1" ]; then
      exit 0
    fi
    printf 'zip' > "$out"
    ;;
  catalog)
    sub="$1"; shift
    case "$sub" in
      create)
        if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT:-0}" = "1" ]; then
          exit 0
        fi
        python3 - "$@" <<'PY'
import sys
from pathlib import Path

args = sys.argv[1:]

def option(name, default=""):
    for index, value in enumerate(args):
        if value == name and index + 1 < len(args):
            return args[index + 1]
    return default

def values(name):
    found = []
    index = 0
    while index < len(args):
        if args[index] == name and index + 1 < len(args):
            found.append(Path(args[index + 1]))
            index += 2
        else:
            index += 1
    return found

def prop(path, name):
    if not path.is_file():
        return ""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1]
    return ""

catalog_text = option("--catalog-file")
if not catalog_text:
    raise SystemExit(2)
catalog = Path(catalog_text)
entries = values("--entry") or [Path("cert-smoke-entry.properties")]
review_receipts = values("--review-receipt")
app_ids = []
lines = [
    "catalog.version=1",
    "catalog.id=" + option("--catalog-id", "cert-smoke"),
    "catalog.name=" + option("--name", "Certification Smoke Apps"),
    "catalog.generatedAt=" + option("--generated-at", "2026-05-01T00:00:00Z"),
]
app_lines = []
for descriptor in entries:
    app_id = prop(descriptor, "app.id") or "cert-smoke"
    app_ids.append(app_id)
    artifact = Path(prop(descriptor, "artifact.path") or "/tmp/cert-smoke.zip")
    size = artifact.stat().st_size if artifact.is_file() else 3
    app_lines.extend([
        f"app.{app_id}.id={app_id}",
        f"app.{app_id}.name={prop(descriptor, 'name') or 'Certification Smoke'}",
        f"app.{app_id}.version={prop(descriptor, 'version') or '0.1.0'}",
        f"app.{app_id}.summary={prop(descriptor, 'summary') or 'Certification smoke app.'}",
        f"app.{app_id}.bundle.uri={prop(descriptor, 'bundle.uri') or 'file:///tmp/cert-smoke.zip'}",
        f"app.{app_id}.bundle.sha256=0000000000000000000000000000000000000000000000000000000000000000",
        f"app.{app_id}.bundle.size.bytes={size}",
        f"app.{app_id}.bundle.type=zip",
        f"app.{app_id}.permissions={prop(descriptor, 'permissions') or 'queue.read'}",
    ])
    if review_receipts:
        app_lines.extend([
            f"app.{app_id}.review.receipt.status=reviewed",
            f"app.{app_id}.review.receipt.reviewer.key.id=cert-review",
            f"app.{app_id}.review.receipt.policy.id=crypta-app-review-v1",
            f"app.{app_id}.review.receipt.policy.version=1",
        ])
catalog.parent.mkdir(parents=True, exist_ok=True)
catalog.write_text("\\n".join(lines + ["catalog.entries=" + ",".join(app_ids)] + app_lines) + "\\n", encoding="utf-8")
PY
        ;;
      sign|verify)
        exit 0
        ;;
    esac
    ;;
  api)
    sub="${1:-}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
      snapshot)
        output=""
        while [ "$#" -gt 0 ]; do
          if [ "$1" = "--output" ]; then output="$2"; shift 2; else shift; fi
        done
        if [ -z "$output" ]; then
          exit 2
        fi
        mkdir -p "$(dirname "$output")"
        cat > "$output" <<'JSON'
{
  "contract": {
    "apiVersion": "v1",
    "contractVersion": 2,
    "generatedBy": "cryptad",
    "stabilityPolicy": "self-test",
    "capabilities": [
      {
        "name": "queue.read",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read queue state."
      },
      {
        "name": "platform.contract.read",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read contract snapshots."
      }
    ],
    "endpoints": [
      {
        "routeFamily": "queue",
        "method": "GET",
        "routeTemplate": "/queue",
        "actionLabel": "queue.read",
        "requiredCapabilities": [
          "queue.read"
        ],
        "hostOperatorBypassAllowed": true,
        "appProcessPrincipalsAllowed": true,
        "appBrowserPrincipalsAllowed": true,
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read queue state."
      }
    ]
  }
}
JSON
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  compat)
    sub="${1:-}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
      verify)
        contract=""
        target=""
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --contract)
              contract="$2"
              shift 2
              ;;
            --bundle-dir|--catalog-entry)
              target="$2"
              shift 2
              ;;
            --strict)
              shift
              ;;
            *)
              shift
              ;;
          esac
        done
        if [ -z "$contract" ] || [ ! -f "$contract" ]; then
          exit 2
        fi
        if [ -z "$target" ]; then
          exit 2
        fi
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  sign|verify)
    exit 0
    ;;
esac
""",
            encoding="utf-8",
        )
        cli.chmod(0o755)
    return cli


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test(Path(__file__).resolve().parents[2])
        print("app-platform-smoke self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"App platform smoke {summary['status']}: {settings.out_dir / SUMMARY_FILE_NAME}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
