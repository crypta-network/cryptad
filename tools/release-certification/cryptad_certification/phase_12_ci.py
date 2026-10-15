"""Read-only original hosted CI admission, separate from retained record consistency.

Historical builds retained runnable products without complete analyzer/test evidence. The
fixed original producer below now projects bounded JUnit, SpotBugs and Error Prone facts,
without publishing raw diagnostic payloads. Only authenticated exact-source complete facts
and original jobs can satisfy CI acceptance. No caller supplies a findings disposition.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from .transparency_bundle import MAX_FILE, canonical, parse, timestamp, read_file, digest

ROOT = Path(__file__).resolve().parents[3]
REPOSITORY = "crypta-network/cryptad"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
WORKFLOWS = {".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml",
             ".github/workflows/public-ecosystem-transparency.yml"}
# These finite semantics belong to the existing workflow triggers. A trigger edit requires
# updating this reviewed adapter; it cannot silently change an exemption during evaluation.
TRIGGERS = {
    ".github/workflows/ci.yml": "  push:\n    branches: [ main, develop, 'release/**', 'hotfix/**' ]\n    tags: [ 'v[0-9]+' ]\n  pull_request:\n    branches: [ main, develop, 'feature/**', 'bugfix/**', 'hotfix/**', 'release/**' ]\n",
    ".github/workflows/production-beta-release.yml": "  pull_request:\n    branches: [ main, develop, 'release/**', 'hotfix/**' ]\n  push:\n    branches: [ 'release/**' ]\n    tags: [ 'v*' ]\n",
    ".github/workflows/public-ecosystem-transparency.yml": "  pull_request:\n    paths:\n      - 'tools/ecosystem-transparency/**'\n      - 'tools/release-certification/cryptad_certification/transparency*'\n      - 'tools/release-certification/cryptad_certification/tests/test_transparency*'\n      - '.github/workflows/public-ecosystem-transparency.yml'\n",
}
CI_STEPS = {
    "build / build": ("Build and analyze (Gradle)", "Build (no Sonar token)"),
    "Exact packaged runtime subject integration": (
        "Build fixed native test tools", "Verify private selection envelope prerequisite",
        "Exercise isolated original runtime baseline and reviewer admission",
        "Exercise synthetic producer and original consumer semantics",
        "Exercise real catalog-origin packaged lifecycle",
        "Exercise packaged shared app budgets and native Trust Graph stores",
        "Exercise real scheduler pressure and bounded resource recovery"),
    "interop-smoke": ("Run Hyphanet interop smoke",),
    "dependency-submission": ("Generate and submit dependency graph",),
    **{f"interop parser/client self-test ({system})":
       ("Run interop parser/client self-test",) +
       (("Run offline cross-version adapter tests",) if system == "ubuntu-latest" else ())
       for system in ("ubuntu-latest", "macos-latest", "windows-latest")},
    **{f"performance smoke self-test ({system})": ("Run performance smoke self-test",)
       for system in ("ubuntu-latest", "macos-latest", "windows-latest")},
    **{f"release certification self-test ({system})":
       ("Run release certification self-tests", "Test protected producer boundaries offline",
        "Reconcile Phase 12 without operational inputs") for system in ("ubuntu-latest", "macos-latest")},
}
# Explicit lane IDs are source-owned. A supplied platform list cannot shrink the graph.
NATIVE_STEPS = {f"native ({lane}) / build": ("Run native Java verification",)
                for lane in ("macos-arm64", "windows-amd64")}
STEPS = {
    ".github/workflows/ci.yml": CI_STEPS,
    ".github/workflows/production-beta-release.yml": {"dry-run-or-release-candidate":
        ("Run production beta pipeline self-test", "Run CI-safe production beta pipeline")},
    ".github/workflows/public-ecosystem-transparency.yml": {"offline":
        ("Offline conformance", "Empty production preview", "Admitted synthetic demo preview", "Browser conformance")},
}
EXPECTED_SKIPS = {".github/workflows/ci.yml": {"interop-extended", "performance-smoke"},
                  ".github/workflows/production-beta-release.yml": {"production-beta"},
                  ".github/workflows/public-ecosystem-transparency.yml":
                      {"build", "transfer-verify", "deploy", "observe"}}
MAX_JSON = 2 * 1024 * 1024
MAX_LOG = 8 * 1024 * 1024
MAX_REPORTS = 4096
MAX_REPORT_BYTES = 256 * 1024 * 1024
REPORT_FILE = "phase-12-ci-reports.json"
PREPARE_STEP = "Prepare bounded CI report retention"
RETAIN_STEP = "Retain typed CI test and analyzer facts"
ATTEST_STEP = "Attest exact CI report facts"
UPLOAD_STEP = "Upload bounded CI report facts"
MODULES = (".", "apps/queue-manager", "apps/publisher", "apps/feed-reader", "apps/profile-publisher",
           "apps/social-inbox", "apps/site-publisher", "apps/trust-graph", "apps/mail-prototype",
           "platform-design-system", "platform-appvault", "platform-appdist", "platform-devtools",
           "platform-app-ui", "platform-appcatalog", "platform-trustgraph", "foundation-support",
           "foundation-store", "foundation-store-contracts", "foundation-crypto-keys", "interop-wire",
           "foundation-config", "foundation-fs", "foundation-compat", "kernel-content", "kernel-transport",
           "kernel-routing", "runtime-spi", "platform-api", "platform-apphost", "platform-sdk-js",
           "platform-web-shell", "runtime-alerts", "runtime-node", "adapter-fcp", "bridge-fcp-runtime",
           "bridge-http-runtime", "adapter-http-legacy-admin", "adapter-http-legacy-browse",
           "thirdparty-onion", "thirdparty-legacy", "launcher-desktop")
REPORT_KINDS = {"junit", "spotbugs-main", "spotbugs-test", "errorprone-main", "errorprone-test"}
LANES = {
    "linux-amd64": ("Linux", "X64", "ubuntu-latest", "build / build"),
    "macos-arm64": ("macOS", "ARM64", "macos-latest", "native (macos-arm64) / build"),
    "windows-amd64": ("Windows", "X64", "windows-latest", "native (windows-amd64) / build"),
}
TASK_KINDS = {"test": "junit", "spotbugsMain": "spotbugs-main", "spotbugsTest": "spotbugs-test",
              "compileJava": "errorprone-main", "compileTestJava": "errorprone-test"}
OUTCOMES = {"executed", "up-to-date", "from-cache", "no-source", "skipped", "failed", "incomplete", "not-observed"}
# Exact source-owned platform branches; capability/permission/tool absences are not exemptions.
PLATFORM_NA = {
    ("platform-apphost", "network.crypta.platform.apphost.runtime.LocalProcessAppHostTest",
     "installFromDirectory_whenWindowsJunctionEscapesStagingRoot_expectFailure()"): {"linux-amd64", "macos-arm64"},
    ("platform-apphost", "network.crypta.platform.apphost.runtime.LocalProcessAppHostTest",
     "uninstall_whenWindowsJunctionExistsUnderAppData_expectTargetPreserved()"): {"linux-amd64", "macos-arm64"},
    ("platform-appdist", "network.crypta.platform.appdist.AppBundleDigestWriterTest",
     "write_whenWindowsJunctionEscapesBundleRoot_expectFailure()"): {"linux-amd64", "macos-arm64"},
    (".", "network.crypta.support.io.NativeThreadTest",
     "usingNativeCode_whenNotLinux_expectFalse()"): {"linux-amd64"},
    (".", "network.crypta.support.io.NativeThreadTest",
     "usingNativeCode_whenLinux_expectConsistentBoolean()"): {"macos-arm64", "windows-amd64"},
    (".", "network.crypta.crypt.EncryptedRandomAccessBufferTest",
     "restoreRAFFrom_whenWrongSecret_onWindows_releasesUnderlyingFileHandle [1] CHACHA_128"): {"linux-amd64", "macos-arm64"},
    (".", "network.crypta.crypt.EncryptedRandomAccessBufferTest",
     "restoreRAFFrom_whenWrongSecret_onWindows_releasesUnderlyingFileHandle [2] CHACHA_256"): {"linux-amd64", "macos-arm64"},
    (".", "network.crypta.support.io.PaddedRandomAccessBufferTest$DeserializationConstructorTests",
     "constructor_whenRealSizeGreaterThanInner_onWindows_releasesFileHandle(Path)"): {"linux-amd64", "macos-arm64"},
    (".", "network.crypta.support.io.FallocateTest",
     "execute_whenUnsupportedAndWindows_writesSingleByteAtEnd()"): {"linux-amd64", "macos-arm64"},
    (".", "network.crypta.support.io.FallocateTest",
     "execute_whenUnsupportedAndNonWindows_writesExactRemainingFromOffset()"): {"windows-amd64"},
    (".", "network.crypta.support.io.FallocateTest",
     "execute_whenUnsupportedAndNonWindowsAndPartialWrites_retriesUntilDone()"): {"windows-amd64"},
}
PLATFORM_RULE_IDS = dict(zip(PLATFORM_NA, (
    "windows-junction-install", "windows-junction-uninstall", "windows-junction-digest",
    "native-thread-nonlinux", "native-thread-linux", "windows-encrypted-buffer-chacha128",
    "windows-encrypted-buffer-chacha256", "windows-padded-buffer-handle", "windows-fallocate-legacy",
    "nonwindows-fallocate-offset", "nonwindows-fallocate-partial")))


def _xml_facts_v2(raw, kind, module, lane, *, expected_classes=None):
    facts = _xml_facts(raw, kind, module)
    if kind.startswith("spotbugs"):
        summary = ET.fromstring(raw).find("FindBugsSummary")
        packages = summary.findall("PackageStats")
        classes = [row for package in packages for row in package.findall("ClassStats")]
        names = [row.get("class") for row in classes]
        package_names = [row.get("package") for row in packages]
        if (any(not isinstance(name, str) or not name or len(name) > 1024 for name in names)
                or len(names) != len(set(names)) or len(package_names) != len(set(package_names))
                or facts["counts"]["classes"] != len(classes)
                or (expected_classes is not None and set(names) != expected_classes)
                or any(_number(package.get("total_types")) != len(package.findall("ClassStats")) for package in packages)):
            _deny()
    if kind == "junit":
        rules = []
        for case in ET.fromstring(raw).findall("testcase"):
            key = (module, case.get("classname"), case.get("name"))
            if case.find("skipped") is not None and lane in PLATFORM_NA.get(key, set()):
                rule = PLATFORM_RULE_IDS[key]
                if rule in rules:
                    _deny()
                rules.append(rule)
        facts["applicability"] = {"platformNotApplicable": len(rules), "unownedSkipped": facts["counts"]["skipped"] - len(rules), "rules": sorted(rules)}
    return facts


def _task_path(module, task):
    return (":" if module == "." else ":" + module.replace("/", ":") + ":") + task


def _milliseconds(value):
    if type(value) is not int or not 0 < value < 2**53:
        _deny()
    return dt.datetime.fromtimestamp(value / 1000, dt.timezone.utc).isoformat()


def _java_version(version, vendor):
    if not isinstance(version, str) or len(version) > 80:
        return False
    numeric = r"(?:2[5-9]|[3-9][0-9])(?:\.[0-9]{1,4}){0,3}"
    return bool(re.fullmatch(numeric + r"(?:[+-][0-9]{1,4})?(?:-LTS)?", version)
                or (vendor == "debian" and re.fullmatch(
                    numeric + r"\+[0-9]{1,4}-[0-9]{1,4}-deb[0-9]{1,2}u[0-9]{1,4}-Debian", version)))


def _runtime_facts(value):
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"javaVersion", "javaVendor", "javaArch", "filesystem", "provider"}
            or value["javaVendor"] not in {"temurin", "debian", "oracle", "other"}
            or value["javaArch"] not in {"amd64", "arm64", "other"}
            or value["filesystem"] not in {"overlay", "ext4", "xfs", "apfs", "hfs", "ntfs", "other"}
            or value["provider"] not in {"linux", "macos", "windows", "other"}
            or not _java_version(value["javaVersion"], value["javaVendor"])):
        _deny()


def _runtime_projection(value):
    if type(value) is not dict:
        return None
    version = value.get("javaVersion")
    vendor = {"Eclipse Adoptium": "temurin", "Eclipse Temurin": "temurin", "Debian": "debian", "Oracle Corporation": "oracle"}.get(value.get("javaVendor"), "other")
    if not _java_version(version, vendor):
        return None
    result = {"javaVersion": version,
              "javaVendor": vendor,
              "javaArch": {"amd64": "amd64", "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(value.get("javaArch"), "other"),
              "filesystem": value.get("filesystem", "").lower() if value.get("filesystem", "").lower() in {"overlay", "ext4", "xfs", "apfs", "hfs", "ntfs"} else "other",
              "provider": {"sun.nio.fs.LinuxFileSystemProvider": "linux", "sun.nio.fs.MacOSXFileSystemProvider": "macos", "sun.nio.fs.WindowsFileSystemProvider": "windows"}.get(value.get("provider"), "other")}
    _runtime_facts(result)
    return result


def _toolchain_projection(value):
    if type(value) is not dict:
        return None
    runtime = _runtime_projection({**value, "filesystem": "ext4", "provider": "sun.nio.fs.LinuxFileSystemProvider"})
    return {key: runtime[key] for key in ("javaVersion", "javaVendor", "javaArch")} if runtime else None


def _toolchain_facts(value):
    if value is None:
        return
    if type(value) is not dict or set(value) != {"javaVersion", "javaVendor", "javaArch"}:
        _deny()
    _runtime_facts({**value, "filesystem": "ext4", "provider": "linux"})


def _provider_facts(value, lane):
    if (type(value) is not dict or set(value) != {"os", "arch", "runner", "ImageOS", "ImageVersion"}
            or (value["os"], value["arch"], value["runner"]) != LANES[lane][:3]
            or (value["ImageOS"] is not None and (not isinstance(value["ImageOS"], str)
                or not re.fullmatch(r"(?:ubuntu[0-9]{2,4}|macos[0-9]{2,4}(?:-arm64)?|win[0-9]{2,4})", value["ImageOS"])))
            or (value["ImageVersion"] is not None and (not isinstance(value["ImageVersion"], str)
                or not re.fullmatch(r"[0-9]{8}(?:\.[0-9]{1,4}){1,3}", value["ImageVersion"])))):
        _deny()
    if (value["ImageOS"] is not None
            and not value["ImageOS"].startswith({"linux-amd64": "ubuntu", "macos-arm64": "macos", "windows-amd64": "win"}[lane])):
        _deny()


def _provider_projection(lane):
    result = {"os": LANES[lane][0], "arch": LANES[lane][1], "runner": LANES[lane][2]}
    for key, pattern in (("ImageOS", r"(?:ubuntu[0-9]{2,4}|macos[0-9]{2,4}(?:-arm64)?|win[0-9]{2,4})"),
                         ("ImageVersion", r"[0-9]{8}(?:\.[0-9]{1,4}){1,3}")):
        selected = os.environ.get(key)
        result[key] = selected if isinstance(selected, str) and re.fullmatch(pattern, selected) else None
    return result


def _task_evidence(raw):
    """Private Gradle rosters have their own bound; public JSON limits stay unchanged."""
    if len(raw) > 32 * 1024 * 1024:
        _deny()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _deny()
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: _deny())
        pending, count = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            if count > 2000000 or depth > 24:
                _deny()
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        if (type(value) is not dict or set(value) != {"schemaVersion", "kind", "tasks", "requestedTasks", "generatedAt", "runtime"}
                or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
                or value["kind"] != "phase-12-private-gradle-task-evidence"
                or type(value["tasks"]) is not list or len(value["tasks"]) > 512
                or type(value["requestedTasks"]) is not list or len(value["requestedTasks"]) > 32
                or any(not isinstance(task, str) or len(task) > 256 for task in value["requestedTasks"])):
            _deny()
        return value
    except (ValueError, UnicodeError, RecursionError):
        _deny()


def _task_projection(record, module, task, *, source_coverage="unavailable"):
    """Only fixed task facts leave the private Gradle observation; no input names or hashes."""
    if record is None:
        return {"outcome": "not-observed", "startedAt": None, "completedAt": None,
                "sourceFiles": 0, "inputClasses": 0, "filtered": False, "analysisEnabled": False,
                "toolchain": None, "sourceCoverage": "unavailable"}
    if record.get("taskPath") != _task_path(module, task) or record.get("outcome") not in OUTCOMES - {"not-observed"}:
        _deny()
    if record.get("inputs", {}).get("observation") == "input-observation-failed":
        return {"outcome": "incomplete", "startedAt": _milliseconds(record["startedAt"]),
                "completedAt": _milliseconds(record["completedAt"]) if record.get("completedAt") is not None else None,
                "sourceFiles": 0, "inputClasses": 0, "filtered": True, "analysisEnabled": False,
                "toolchain": None, "sourceCoverage": "unavailable"}
    sources = record.get("sourceFiles")
    if type(sources) is not list or len(sources) > 30000:
        _deny()
    for key in ("filtered", "errorProneEnabled"):
        if type(record.get(key)) is not bool:
            _deny()
    classes = record.get("inputClasses")
    if type(classes) is not int or not 0 <= classes <= 1000000:
        _deny()
    return {"outcome": record["outcome"], "startedAt": _milliseconds(record["startedAt"]),
            "completedAt": _milliseconds(record["completedAt"]) if record.get("completedAt") is not None else None, "sourceFiles": len(sources),
            "inputClasses": classes, "filtered": record["filtered"],
            "analysisEnabled": record["errorProneEnabled"], "toolchain": _toolchain_projection(record.get("toolchain")),
            "sourceCoverage": source_coverage}


def _private_source_coverage(record, expected_paths, root, checked_sources):
    """Validate exact owner/source-set bytes without exporting names, hashes or parse failures."""
    if (record is None or expected_paths is None
            or record.get("inputs", {}).get("observation") == "input-observation-failed"):
        return "unavailable"
    sources = record.get("sourceFiles")
    if (type(sources) is not list or len(sources) > 30000
            or any(type(row) is not dict or not isinstance(row.get("path"), str) for row in sources)):
        return "invalid"
    paths = [row["path"] for row in sources]
    if len(paths) != len(set(paths)) or set(paths) != expected_paths:
        return "invalid"
    from .active_source import read_source
    try:
        for row in sources:
            path = row["path"]
            if path not in checked_sources:
                checked_sources[path] = digest(read_source(root, path))
            if row.get("digest") != checked_sources[path]:
                return "invalid"
    except (OSError, ValueError):
        return "invalid"
    return "matched"


def _errorprone_completed(raw, source_count):
    tree = ET.fromstring(raw)
    return (tree.get("compilerCompleted") == "true" and tree.get("diagnosticsComplete") == "true"
            and _number(tree.get("sourceFiles")) == source_count)


def _private_test_coverage(record, module, root, checked_sources):
    """Detect arbitrary class Specs as well as the separately observed name/tag filters."""
    inputs = record.get("inputs", {})
    all_classes, candidates = inputs.get("testClasses"), inputs.get("candidateClasses")
    if type(all_classes) is not list or type(candidates) is not list:
        return "unavailable"
    if record.get("inputClasses") != len(candidates):
        return "invalid"
    if any(type(row) is not dict or not isinstance(row.get("path"), str) for row in all_classes):
        return "invalid"
    prefix = "" if module == "." else module + "/"
    roots = (prefix + "build/classes/java/test/", prefix + "build/classes/kotlin/test/")
    packages = ("network/crypta/", "com/jthemedetecor/", "com/onionnetworks/",
                "org/bitpedia/", "org/spaceroots/", "org/sevenzip/")
    expected_candidates = set()
    for row in all_classes:
        path = row["path"]
        base = next((base for base in roots if path.startswith(base)), None)
        if base is None or not path.endswith(".class"):
            return "invalid"
        relative = path[len(base):]
        if any(part in {"", ".", ".."} for part in relative.split("/")):
            return "invalid"
        name = relative.rsplit("/", 1)[-1]
        if module == "build-logic" or (relative.startswith(packages) and name.endswith("Test.class") and "$" not in name):
            expected_candidates.add(path)
    coverage = _private_source_coverage({"sourceFiles": all_classes}, {row["path"] for row in all_classes}, root, checked_sources)
    if coverage != "matched":
        return coverage
    return _private_source_coverage({"sourceFiles": candidates}, expected_candidates, root, checked_sources)


def _private_spotbugs_coverage(record, module, kind, root, checked_sources):
    """An analyzer's selected classes must equal its owning source-set outputs byte for byte."""
    inputs = record.get("inputs", {}) if record else {}
    owned, actual = inputs.get("ownedClasses"), inputs.get("classes")
    if type(owned) is not list or type(actual) is not list:
        return "unavailable"
    if len(owned) > 30000 or record.get("inputClasses") != len(actual):
        return "invalid"
    source_set = "test" if kind.endswith("test") else "main"
    prefix = "" if module == "." else module + "/"
    roots = tuple(prefix + "build/classes/" + language + "/" + source_set + "/" for language in ("java", "kotlin"))
    paths = set()
    for row in owned:
        if type(row) is not dict or not isinstance(row.get("path"), str):
            return "invalid"
        path = row["path"]
        base = next((base for base in roots if path.startswith(base)), None)
        if (base is None or not path.endswith(".class")
                or any(part in {"", ".", ".."} for part in path[len(base):].split("/"))):
            return "invalid"
        paths.add(path)
    coverage = _private_source_coverage({"sourceFiles": owned}, paths, root, checked_sources)
    if coverage != "matched":
        return coverage
    return _private_source_coverage({"sourceFiles": actual}, paths, root, checked_sources)


def _private_report_roster(record, paths, root):
    """Bind retained outputs to the exact bounded roster observed at task completion."""
    if record is None or record.get("reportObservation") != "complete":
        return "unavailable", {}
    rows = record.get("reportFiles")
    if type(rows) is not list or len(rows) > MAX_REPORTS:
        return "invalid", {}
    selected = {}
    for row in rows:
        if (type(row) is not dict or set(row) != {"path", "sha256", "size"}
                or not isinstance(row["path"], str) or not isinstance(row["sha256"], str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["sha256"])
                or type(row["size"]) is not int or not 0 <= row["size"] <= 16 * 1024 * 1024
                or row["path"] in selected):
            return "invalid", {}
        selected[row["path"]] = row
    try:
        current = {path.relative_to(root).as_posix() for path in paths if path.exists()}
    except (ValueError, OSError):
        return "invalid", {}
    if set(selected) != current:
        return "invalid", {}
    return "matched", selected


def _spotbugs_class_names(record, module, kind):
    # Called only after exact owner-prefix and byte validation by _private_spotbugs_coverage.
    source_set = "test" if kind.endswith("test") else "main"
    prefix = "" if module == "." else module + "/"
    roots = tuple(prefix + "build/classes/" + language + "/" + source_set + "/" for language in ("java", "kotlin"))
    names = set()
    for row in record["inputs"]["classes"]:
        base = next(base for base in roots if row["path"].startswith(base))
        names.add(row["path"][len(base):-len(".class")].replace("/", "."))
    return names


def _private_analyzer_configuration(record, kind, root, checked_sources):
    """Admit only the reviewed analyzer policy, without caller-supplied dispositions."""
    if kind == "junit":
        return "matched"
    inputs = record.get("inputs", {}) if record else {}
    configuration = inputs.get("analyzerConfiguration")
    if type(configuration) is not dict:
        return "unavailable"
    if kind.startswith("spotbugs"):
        expected = {"effort": None, "reportLevel": None, "extraArgs": [], "jvmArgs": [], "pluginJarFiles": []}
        if configuration != expected or any(type(configuration.get(key)) is not type(value) for key, value in expected.items()):
            return "invalid"
        if any(inputs.get(name) != [] for name in ("includeFilter", "baseline", "onlyAnalyze", "visitors", "omitVisitors", "chooseVisitors")):
            return "invalid"
        path = "build-logic/spotbugs-exclude" + ("-test" if kind.endswith("test") else "") + ".xml"
        return _private_source_coverage({"sourceFiles": inputs.get("excludeFilter")}, {path}, root, checked_sources)
    expected = {"enabled": True, "allErrorsAsWarnings": True, "disableAllChecks": False,
                "disableAllWarnings": False, "allSuggestionsAsWarnings": False,
                "allDisabledChecksAsWarnings": False, "disableWarningsInGeneratedCode": False,
                "ignoreUnknownCheckNames": False, "ignoreSuppressionAnnotations": False,
                "compilingTestOnlyCode": kind.endswith("test"), "excludedPaths": None,
                "checks": {}, "checkOptions": {}, "extraArgs": [],
                "compilerArgumentProviders": ["net.ltgt.gradle.errorprone.ErrorPronePlugin$ErrorProneCompilerArgumentProvider"],
                "forkJvmArgumentProviders": ["net.ltgt.gradle.errorprone.ErrorPronePlugin$ErrorProneJvmArgumentProvider"],
                "forkJvmArguments": [], "errorproneArgumentProviders": 0, "argumentFiles": []}
    arguments = ["-Xlint:deprecation", "-Xlint:unchecked", "-Xmaxwarns", "10000", "-Xmaxerrs", "10000"]
    if (configuration != expected or any(type(configuration.get(key)) is not type(value) for key, value in expected.items())
            or inputs.get("compilerArguments") != arguments or inputs.get("incremental") is not False):
        return "invalid"
    return "matched"


def retain_reports_v2(output, started_file, lane):
    """Project successful and failed jobs without granting either execution or acceptance."""
    from .active_source import source_roster, read_source
    if (lane not in LANES or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_JOB") != "build"
            or (os.environ.get("RUNNER_OS"), os.environ.get("RUNNER_ARCH")) != LANES[lane][:2]):
        _deny()
    source = source_roster(ROOT)
    started_path = Path(started_file).absolute()
    start = parse(read_source(started_path.parent, started_path.name, maximum=MAX_FILE))
    if set(start) != {"startedAt"}:
        _deny()
    _time(start["startedAt"])
    evidence_file = ROOT / "build/phase12/task-evidence.json"
    evidence = _task_evidence(read_source(ROOT, "build/phase12/task-evidence.json", maximum=32 * 1024 * 1024)) if evidence_file.exists() else {"tasks": [], "requestedTasks": []}
    records = evidence.get("tasks")
    if type(records) is not list or len(records) > 512:
        _deny()
    included_path = ROOT / "build-logic/build/phase12/task-evidence.json"
    if included_path.exists():
        included = _task_evidence(_read_report(included_path))
        if (included.get("schemaVersion") != 1 or included.get("kind") != "phase-12-private-gradle-task-evidence"
                or type(included.get("tasks")) is not list or len(included["tasks"]) > 512):
            _deny()
        for record in included["tasks"]:
            if not isinstance(record.get("taskPath"), str) or not record["taskPath"].startswith(":"):
                _deny()
            record["taskPath"] = ":build-logic" + record["taskPath"]
            records.append(record)
    if len(records) > 512:
        _deny()
    by_task = {row["taskPath"]: row for row in records}
    if len(by_task) != len(records):
        _deny()
    # Exact path sets belong to each reviewed module/source-set, not merely the global roster.
    # A same-count substitution or stale byte identity remains an exportable invalid observation.
    source_cohort_valid = True
    try:
        expected_sources = _v2_source_paths(ROOT, selected_paths=source.paths) if records else {}
    except (OSError, ValueError):
        expected_sources, source_cohort_valid = {}, False
    checked_sources = {}
    rows, total, report_count, budget_exhausted = [], 0, 0, False
    for module, kind in _v2_rows():
        task = next(task for task, selected_kind in TASK_KINDS.items() if selected_kind == kind)
        record = by_task.get(_task_path(module, task))
        coverage = _private_source_coverage(record, expected_sources.get((module, kind)), ROOT, checked_sources)
        if kind == "junit" and coverage == "matched":
            coverage = _private_test_coverage(record, module, ROOT, checked_sources)
        if kind.startswith("spotbugs") and coverage == "matched":
            coverage = _private_spotbugs_coverage(record, module, kind, ROOT, checked_sources)
        execution = _task_projection(record, module, task, source_coverage=coverage)
        configuration = _private_analyzer_configuration(record, kind, ROOT, checked_sources)
        if configuration != "matched":
            execution["filtered"] = True
        reports, unavailable = [], budget_exhausted and execution["outcome"] != "no-source"
        unavailable = unavailable or (record is not None and configuration != "matched")
        if execution["outcome"] != "no-source":
            try:
                paths = [] if budget_exhausted else _report_paths(ROOT, module, kind)
            except (OSError, ValueError):
                paths, unavailable = [], True
            report_coverage, snapshots = _private_report_roster(record, paths, ROOT)
            unavailable = unavailable or report_coverage != "matched"
            for path in paths:
                if budget_exhausted:
                    break
                if not path.exists():
                    continue
                report_count += 1
                if report_count > MAX_REPORTS:
                    budget_exhausted, unavailable = True, True
                    break
                try:
                    raw = _read_report(path)
                    total += len(raw)
                    if total > MAX_REPORT_BYTES:
                        budget_exhausted, unavailable = True, True
                        break
                    if report_coverage == "matched":
                        snapshot = snapshots[path.relative_to(ROOT).as_posix()]
                        if snapshot["size"] != len(raw) or snapshot["sha256"] != digest(raw):
                            raise ValueError("report-completion-mismatch")
                    expected_classes = (_spotbugs_class_names(record, module, kind)
                                        if kind.startswith("spotbugs") and coverage == "matched" else None)
                    facts = _xml_facts_v2(raw, kind, module, lane, expected_classes=expected_classes)
                    if kind.startswith("spotbugs") and facts["counts"]["classes"] != execution["inputClasses"]:
                        raise ValueError("analyzer-class-count-mismatch")
                    if kind.startswith("errorprone") and not _errorprone_completed(raw, execution["sourceFiles"]):
                        raise ValueError("incomplete-analysis")
                    reports.append(facts)
                except (ValueError, OSError, ET.ParseError):
                    # Never export parse errors, file names, exceptions, or private report hashes.
                    unavailable = True
        rows.append({"module": module, "kind": kind, "execution": execution,
                     "reportState": "invalid" if unavailable else "observed" if reports else "absent", "reports": reports})
    provider = _provider_projection(lane)
    _provider_facts(provider, lane)
    runtime = _runtime_projection(evidence.get("runtime"))
    value = {"schemaVersion": 2, "kind": "phase-12-original-ci-report-facts",
             "sourceCommit": source.source_commit, "sourceTree": source.source_tree, "sourceClass": source.source_class,
             "workflowSourceCommit": os.environ["GITHUB_SHA"], "signerCommit": os.environ["GITHUB_WORKFLOW_SHA"],
             "runId": int(os.environ["GITHUB_RUN_ID"]), "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
             "jobKey": "build", "lane": lane, "provider": provider, "runtime": runtime, "producerDigest": _producer_identity(),
             "startedAt": start["startedAt"], "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
             "fullSelection": source_cohort_valid and _observed_task_cohort(by_task) and evidence.get("requestedTasks") in (["build", "errorproneReport"],
                 ["build", "errorproneReport", "sonar"], ["test", "spotbugsMain", "spotbugsTest", "errorproneReport"],
                 ["build", "errorproneReport", ":platform-devtools:installDist", "assembleCryptadDist"]),
             "rows": rows, "sonarLint": "owner-skipped-standard-build", "rawPayloads": "not-exported"}
    output = Path(output)
    if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        _deny()
    output.mkdir(mode=0o700)
    raw = canonical(value)
    if len(raw) > MAX_JSON:
        _deny()
    (output / REPORT_FILE).write_bytes(raw)
    (output / REPORT_FILE).chmod(0o600)
    return value


def _producer_identity(schema_version=2, *, source_commit=None):
    from .active_source import read_source
    files = (".github/workflows/build.yml", "build.gradle.kts", "settings.gradle.kts",
             "build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts",
             "build-logic/src/main/kotlin/cryptad.sonar.gradle.kts",
             "tools/release-certification/cryptad_certification/phase_12_ci.py")
    if schema_version == 2:
        files += (
             "build-logic/src/main/kotlin/cryptad/Phase12TaskEvidence.kt",
             "build-logic/spotbugs-exclude.xml", "build-logic/spotbugs-exclude-test.xml",
             "build-logic/src/main/kotlin/cryptad/ActiveSourceFiles.kt",
             "build-logic/src/main/kotlin/cryptad.distribution.gradle.kts",
             "build-logic/src/main/kotlin/cryptad.supply-chain.gradle.kts",
             "build-logic/src/main/kotlin/cryptad.spotless.gradle.kts",
             "build-logic/build.gradle.kts", ".github/workflows/ci.yml",
             "tools/release-certification/cryptad_certification/active_source.py")
    elif schema_version != 1:
        _deny()
    def selected(name):
        if source_commit is None:
            return read_source(ROOT, name, maximum=MAX_FILE)
        return _historical_source(source_commit, name)
    return digest(canonical({name: digest(selected(name)) for name in files}))


def _historical_source(commit, name):
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        _deny()
    from .active_source import _git
    return _git(ROOT, "show", f"{commit}:{name}")


def _report_cohort(root):
    """Mirror the existing Java source-set/no-source rules, never a caller cohort flag."""
    _module_cohort(root)
    result = []
    for module in MODULES:
        project = root / module
        main = list((project / "src/main/java").rglob("*.java"))
        tests = list((project / "src/test/java").rglob("*.java"))
        kotlin = list((project / "src/test/kotlin").rglob("*.kt"))
        if len(main) + len(tests) + len(kotlin) > 30000:
            _deny()
        kinds = (["spotbugs-main", "errorprone-main"] if main else [])
        kinds += ["spotbugs-test", "errorprone-test"] if tests else []
        if tests or kotlin:
            kinds.append("junit")
        result.extend((module, kind) for kind in kinds)
    return sorted(result)


def _settings_modules(text):
    """Read the finite literal include syntax; computed/qualified rosters require owner review."""
    if len(text.encode("utf-8")) > 1024 * 1024:
        _deny()
    def trivia(index):
        while index < len(text):
            if text[index].isspace():
                index += 1
            elif text.startswith("//", index):
                end = text.find("\n", index + 2)
                index = len(text) if end < 0 else end + 1
            elif text.startswith("/*", index):
                index, depth = index + 2, 1
                while depth:
                    if index >= len(text) or depth > 24:
                        _deny()
                    if text.startswith("/*", index):
                        depth, index = depth + 1, index + 2
                    elif text.startswith("*/", index):
                        depth, index = depth - 1, index + 2
                    else:
                        index += 1
            else:
                break
        return index
    def quoted_end(index):
        quote = text[index]
        if text.startswith('"""', index):
            end = text.find('"""', index + 3)
            if end < 0:
                _deny()
            # A closing run may contain one or two literal quotes before its final delimiter.
            # Consume the complete run rather than leaving a dangling normal-string quote.
            while end < len(text) and text[end] == '"':
                end += 1
            return end
        index += 1
        while index < len(text):
            if text[index] == "\\":
                index += 2
            elif text[index] == quote:
                return index + 1
            else:
                index += 1
        _deny()
    selected, builds, index = [], [], 0
    identifier = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
    while index < len(text):
        index = trivia(index)
        if index >= len(text):
            break
        if text[index] in {'"', "'"}:
            index = quoted_end(index)
            continue
        token = identifier.match(text, index)
        if token is None:
            index += 1
            continue
        name, start = token.group(), index
        index += len(name)
        if not name.startswith("include"):
            continue
        if name not in {"include", "includeBuild"} or text[:start].rstrip().endswith("."):
            _deny()
        index = trivia(index)
        if index >= len(text) or text[index] != "(":
            _deny()
        index, values = trivia(index + 1), []
        while index < len(text) and text[index] != ")":
            if text[index] != '"' or text.startswith('"""', index):
                _deny()
            end = quoted_end(index)
            value = text[index + 1:end - 1]
            if not re.fullmatch(r":?[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)*", value):
                _deny()
            if name == "includeBuild" and value != "build-logic":
                _deny()
            values.append(value.removeprefix(":"))
            index = trivia(end)
            if index >= len(text) or text[index] not in {",", ")"}:
                _deny()
            if text[index] == ",":
                index = trivia(index + 1)
        if index >= len(text) or not values:
            _deny()
        index += 1
        (selected if name == "include" else builds).extend(values)
        if len(selected) > 64 or len(builds) > 1:
            _deny()
    if len(selected) != len(set(selected)) or builds not in ([], ["build-logic"]):
        _deny()
    return set(selected)


def _module_cohort(root):
    selected = _settings_modules((root / "settings.gradle.kts").read_text())
    if selected != {name.replace("/", ":") for name in MODULES if name != "."}:
        _deny()


def _report_paths(root, module, kind):
    build = root / module / "build"
    if kind == "junit":
        directory = build / "test-results/test"
        if not directory.exists():
            return []
        from .active_source import _checked_path
        _checked_path(root, directory.relative_to(root).as_posix())
        paths = []
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_REPORTS:
                    _deny()
                if fnmatch.fnmatchcase(entry.name, "TEST-*.xml"):
                    paths.append(directory / entry.name)
        return sorted(paths)
    task = "compileTestJava" if kind.endswith("test") else "compileJava"
    if kind.startswith("spotbugs"):
        return [build / "reports/spotbugs" / ("spotbugsTest.xml" if kind.endswith("test") else "spotbugsMain.xml")]
    label = ((module.replace("/", "_") + "_") if module != "." else "") + task
    return [build / "reports/errorprone" / label / (task + ".xml")]


def _v2_rows():
    return [(module, kind) for module in MODULES for kind in TASK_KINDS.values()] + [("build-logic", "junit")]


def _observed_task_cohort(by_task):
    expected = {_task_path(module, next(task for task, selected in TASK_KINDS.items() if selected == kind))
                for module, kind in _v2_rows()}
    return set(by_task) <= expected


def _v2_source_paths(root, *, selected_paths=None):
    """Exact expectations for the fixed reviewed source-set configuration.

    Task observations remain authoritative for actual selection; a disagreement blocks. Git
    and the approved export roster select current files without a recursive history scan.
    """
    from .active_source import source_roster
    _module_cohort(root)
    paths = source_roster(root).paths if selected_paths is None else selected_paths
    expected = {}
    for module, kind in _v2_rows():
        prefix = "" if module == "." else module + "/"
        roots = ([prefix + "src/test/java/", prefix + "src/test/kotlin/"] if kind == "junit"
                 else [prefix + ("src/test/java/" if kind.endswith("test") else "src/main/java/")])
        files = {path for path in paths if any(path.startswith(base) for base in roots)
                 and path.endswith((".java", ".kt") if kind == "junit" else ".java")}
        if len(files) > 30000:
            _deny()
        template = prefix + "src/main/java/network/crypta/node/Version.java"
        if module in {".", "interop-wire"} and not kind.endswith("test") and kind != "junit" and template in files:
            files.remove(template)
            files.add(prefix + "build/tmp/compileVersion/network/crypta/node/Version.java")
        expected[module, kind] = files
    return expected


def _v2_source_counts(root):
    return {key: len(paths) for key, paths in _v2_source_paths(root).items()}


def _number(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,16}", value):
        _deny()
    return int(value)


def _read_report(path):
    from .active_source import read_source
    path = Path(path).absolute()
    raw = read_source(path.parent, path.name)
    if not raw:
        _deny()
    return raw


def _xml_facts(raw, kind, module):
    """Discard all paths, case names, messages, stdout/stderr and private-content digests.

    Counts sufficient for a zero-finding disposition survive. Any finding remains blocking;
    this projection offers no caller-supplied waiver and never publishes diagnostic payloads.
    """
    if len(raw) > 16 * 1024 * 1024:
        _deny()
    document = raw.decode("utf-8")
    if "\x00" in document or "<!DOCTYPE" in document.upper() or "<!ENTITY" in document.upper():
        _deny()
    tree = ET.fromstring(document)
    pending, count = [(tree, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 200000 or depth > 24:
            _deny()
        pending.extend((child, depth + 1) for child in node)
    if kind == "junit":
        if tree.tag != "testsuite":
            _deny()
        cases = tree.findall("testcase")
        result = {name: _number(tree.get(name)) for name in ("tests", "errors", "failures", "skipped")}
        if (result["tests"] != len(cases) or result["errors"] != sum(len(row.findall("error")) for row in cases)
                or result["failures"] != sum(len(row.findall("failure")) for row in cases)
                or result["skipped"] != sum(len(row.findall("skipped")) for row in cases)):
            _deny()
        observed = tree.get("timestamp")
        if isinstance(observed, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?", observed):
            observed += "Z"  # Gradle's unzoned JUnit report timestamps are UTC.
        _time(observed)
        return {"counts": result, "executedAt": observed}
    if kind.startswith("spotbugs"):
        if tree.tag != "BugCollection":
            _deny()
        summary, errors = tree.find("FindBugsSummary"), tree.find("Errors")
        if summary is None or errors is None:
            _deny()
        bugs = len(tree.findall("BugInstance"))
        if _number(summary.get("total_bugs")) != bugs:
            _deny()
        counts = {"bugs": bugs, "errors": len(errors.findall("Error")),
                  "missingClasses": len(errors.findall("MissingClass")),
                  "classes": _number(summary.get("total_classes"))}
        if (counts["errors"] != _number(errors.get("errors"))
                or counts["missingClasses"] != _number(errors.get("missingClasses", "0"))):
            _deny()
        observed = dt.datetime.fromtimestamp(_number(tree.get("analysisTimestamp")) / 1000, dt.timezone.utc)
        return {"counts": counts, "executedAt": observed.isoformat()}
    if (tree.tag != "errorproneReport" or tree.get("project") != (":" if module == "." else ":" + module.replace("/", ":"))
            or tree.get("task") != ("compileTestJava" if kind.endswith("test") else "compileJava")):
        _deny()
    counts = {"warnings": 0, "errors": 0}
    for row in tree.findall("diagnostic"):
        if row.get("severity") not in {"warning", "error"}:
            _deny()
        counts["warnings" if row.get("severity") == "warning" else "errors"] += 1
    _time(tree.get("generatedAt"))
    return {"counts": counts, "executedAt": tree.get("generatedAt")}


def retain_reports(output, started_file):
    """Success-only original producer: emit bounded facts, never raw XML or payload digests."""
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_JOB") != "build"):
        _deny()
    source = subprocess.run(["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=ROOT,
                            capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()
    start = parse(read_file(started_file))
    if set(start) != {"startedAt"}:
        _deny()
    _time(start["startedAt"])
    rows, total = [], 0
    for module, kind in _report_cohort(ROOT):
        reports = []
        for path in _report_paths(ROOT, module, kind):
            if not path.exists():
                continue
            raw = _read_report(path)
            total += len(raw)
            if total > 256 * 1024 * 1024 or len(reports) > 4096:
                _deny()
            reports.append(_xml_facts(raw, kind, module))
        rows.append({"module": module, "kind": kind, "reports": reports})
    result = {"schemaVersion": 1, "kind": "phase-12-original-ci-report-facts", "sourceCommit": source[0],
              "sourceTree": source[1], "workflowSourceCommit": os.environ["GITHUB_SHA"],
              "signerCommit": os.environ["GITHUB_WORKFLOW_SHA"],
              "runId": int(os.environ["GITHUB_RUN_ID"]), "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
              "jobKey": "build", "producerDigest": _producer_identity(1), "startedAt": start["startedAt"],
              "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "rows": rows,
              "sonarLint": "owner-skipped-standard-build", "rawPayloads": "not-exported"}
    output = Path(output)
    if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        _deny()
    output.mkdir(mode=0o700)
    raw = canonical(result)
    if len(raw) > MAX_JSON:
        _deny()
    (output / REPORT_FILE).write_bytes(raw)
    (output / REPORT_FILE).chmod(0o600)
    return result


class OriginalCIUnavailable(ValueError):
    """Original GET response could not be acquired within the closed access/size bounds."""


def _deny():
    raise ValueError("phase12-original-ci-invalid")


def _time(value):
    if not isinstance(value, str):
        _deny()
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        _deny()
    return result


def _step_contains(step, instant):
    # Original Actions step timestamps have second precision; raw report/log clocks can have
    # fractions. Preserve that exact API precision interval rather than treating truncation
    # as an unavailable or forged checkout/report.
    return _time(step["started_at"]) <= instant < _time(step["completed_at"]) + dt.timedelta(seconds=1)


def _source_clean(source):
    """A commit label cannot cover locally changed implementation, tests or workflows."""
    from .active_source import source_roster
    selected = source_roster(ROOT)
    if (selected.source_commit, selected.source_tree) != (source["commit"], source["tree"]):
        _deny()
    return selected.source_class == "committed-source"


class _GitHub:
    """Fixed bounded GET endpoints and explicitly selected repository operator identity."""
    def __init__(self):
        from .transparency_sources import _original_helper
        self.owner = _original_helper()
        self.environment = self.owner._environment()  # gh auth token --user leumor outside Actions.
        # Machine responses must not depend on the invoking terminal's forced colour settings.
        for name in ("FORCE_COLOR", "CLICOLOR_FORCE", "GH_FORCE_TTY"):
            self.environment.pop(name, None)
        self.environment["NO_COLOR"] = "1"
        self.calls = 0

    def get(self, suffix, *, raw=False):
        if not re.fullmatch(
            r"(?:actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*(?:/jobs\?per_page=100)?|"
            r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100|actions/artifacts/[1-9][0-9]*/zip|"
            r"actions/jobs/[1-9][0-9]*/logs|check-runs/[1-9][0-9]*(?:/annotations\?per_page=100)?|"
            r"commits/[0-9a-f]{40}/check-runs\?filter=latest&per_page=100|"
            r"git/commits/[0-9a-f]{40}|pulls/[1-9][0-9]*(?:/files\?per_page=100&page=[1-3])?)", suffix):
            _deny()
        self.calls += 1
        if self.calls > 128:
            _deny()
        from bounded_process import run
        try:
            result = run(["gh", "api", "--method", "GET", f"repos/{REPOSITORY}/{suffix}"],
                         environment=self.environment, timeout=45, output_limit=MAX_LOG if raw else MAX_JSON)
        except (ValueError, OSError):
            raise OriginalCIUnavailable("phase12-original-ci-access-unavailable") from None
        if raw:
            return result
        return parse(result)

    def attest(self, raw, run, workflow_source, signer):
        with tempfile.TemporaryDirectory(prefix="phase12-ci-attest-") as temporary:
            path = Path(temporary) / REPORT_FILE
            path.write_bytes(raw)
            result = self.owner._gh(["attestation", "verify", str(path), "--repo", REPOSITORY,
                "--signer-workflow", REPOSITORY + "/.github/workflows/build.yml",
                "--source-digest", workflow_source, "--signer-digest", signer, "--format", "json"],
                self.environment)
        invocation = f"https://github.com/{REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        if not isinstance(result, list) or not any(
                row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI") == invocation
                for row in result if isinstance(row, dict)):
            _deny()


def _report_facts(raw, source, run, job, evaluation, workflow_source, signer):
    value = parse(raw)
    if type(value) is dict and value.get("schemaVersion") == 2:
        return _report_facts_v2(value, source, run, job, evaluation, workflow_source, signer)
    fields = {"schemaVersion", "kind", "sourceCommit", "sourceTree", "workflowSourceCommit", "runId",
              "runAttempt", "jobKey", "producerDigest", "startedAt", "generatedAt", "rows", "sonarLint", "rawPayloads", "signerCommit"}
    if (type(value) is not dict or set(value) != fields or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "phase-12-original-ci-report-facts" or value["sourceCommit"] != source["commit"]
            or value["sourceTree"] != source["tree"] or value["workflowSourceCommit"] != workflow_source or value["signerCommit"] != signer
            or type(value["runId"]) is not int or type(value["runAttempt"]) is not int
            or value["runId"] != run["id"] or value["runAttempt"] != run["run_attempt"] or value["jobKey"] != "build"
            or value["producerDigest"] != _producer_identity(1, source_commit=source["commit"]) or value["sonarLint"] != "owner-skipped-standard-build"
            or value["rawPayloads"] != "not-exported" or type(value["rows"]) is not list):
        _deny()
    steps = {step["name"]: step for step in job["steps"]}
    start, end = _time(value["startedAt"]), _time(value["generatedAt"])
    if not (_step_contains(steps[PREPARE_STEP], start) and _step_contains(steps[RETAIN_STEP], end)
            and start <= end <= evaluation):
        _deny()
    if [(row.get("module"), row.get("kind")) for row in value["rows"]] != _report_cohort(ROOT):
        _deny()
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "bugs": 0,
              "missingClasses": 0, "warnings": 0}
    blockers, report_count = [], 0
    if b"--lane" in _historical_source(source["commit"], ".github/workflows/build.yml"):
        blockers.append("original-ci-v1-cannot-replace-required-native-results")
    for row in value["rows"]:
        if set(row) != {"module", "kind", "reports"} or type(row["reports"]) is not list or len(row["reports"]) > 4096:
            _deny()
        expected = ({"tests", "failures", "errors", "skipped"} if row["kind"] == "junit" else
                    {"bugs", "errors", "missingClasses", "classes"} if row["kind"].startswith("spotbugs") else {"warnings", "errors"})
        if not row["reports"]:
            blockers.append("original-ci-required-report-missing")
        for report in row["reports"]:
            report_count += 1
            if (report_count > 4096 or type(report) is not dict or set(report) != {"counts", "executedAt"}
                    or type(report["counts"]) is not dict or set(report["counts"]) != expected
                    or any(type(number) is not int or not 0 <= number <= 10000000 for number in report["counts"].values())):
                _deny()
            if not start <= _time(report["executedAt"]) <= end:
                blockers.append("original-ci-report-execution-outside-selected-job")
            if row["kind"] == "junit" and (not report["counts"]["tests"]
                    or sum(report["counts"][key] for key in ("failures", "errors", "skipped")) > report["counts"]["tests"]):
                _deny()
            if row["kind"].startswith("spotbugs") and not report["counts"]["classes"]:
                blockers.append("original-ci-analyzer-class-coverage-empty")
            for name, number in report["counts"].items():
                if name in totals:
                    totals[name] += number
    if not totals["tests"]:
        blockers.append("original-ci-tests-not-observed")
    if totals["failures"] or totals["errors"]:
        blockers.append("original-ci-test-or-analyzer-failures")
    if totals["bugs"] or totals["missingClasses"] or totals["warnings"]:
        blockers.append("original-ci-analyzer-findings-require-disposition")
    if totals["skipped"]:
        blockers.append("original-ci-skipped-tests-require-owner-disposition")
    return {"cohortRows": len(value["rows"]), "reportCount": report_count, "totals": totals,
            "sonarLint": value["sonarLint"], "rawPayloads": "not-exported", "workflowSourceCommit": workflow_source,
            "signerCommit": signer, "blockers": sorted(set(blockers))}


def _report_facts_v2(value, source, run, job, evaluation, workflow_source, signer):
    fields = {"schemaVersion", "kind", "sourceCommit", "sourceTree", "sourceClass", "workflowSourceCommit",
              "signerCommit", "runId", "runAttempt", "jobKey", "lane", "provider", "producerDigest", "startedAt",
              "generatedAt", "fullSelection", "rows", "sonarLint", "rawPayloads", "runtime"}
    lane = value.get("lane")
    if (set(value) != fields or type(value["schemaVersion"]) is not int or lane not in LANES
            or value["kind"] != "phase-12-original-ci-report-facts"
            or value["sourceCommit"] != source["commit"] or value["sourceTree"] != source["tree"]
            or value["sourceClass"] not in {"committed-source", "working-source", "manifest-source-export"}
            or value["workflowSourceCommit"] != workflow_source or value["signerCommit"] != signer
            or type(value["runId"]) is not int or value["runId"] != run["id"]
            or type(value["runAttempt"]) is not int or value["runAttempt"] != run["run_attempt"]
            or value["jobKey"] != "build" or job["name"] != LANES[lane][3]
            or value["producerDigest"] != _producer_identity() or type(value["fullSelection"]) is not bool
            or value["rawPayloads"] != "not-exported" or value["sonarLint"] != "owner-skipped-standard-build"):
        _deny()
    provider = value["provider"]
    _runtime_facts(value["runtime"])
    _provider_facts(provider, lane)
    steps = {step["name"]: step for step in job["steps"]}
    start, end = _time(value["startedAt"]), _time(value["generatedAt"])
    if not (_step_contains(steps[PREPARE_STEP], start) and _step_contains(steps[RETAIN_STEP], end)
            and start <= end <= evaluation):
        _deny()
    expected_rows = _v2_rows()
    rows = value["rows"]
    if (type(rows) is not list or [(row.get("module"), row.get("kind")) for row in rows] != expected_rows):
        _deny()
    blockers, reports_count = [], 0
    if not value["fullSelection"]:
        blockers.append("original-ci-filtered-task-selection")
    if value["sourceClass"] != "committed-source":
        blockers.append("ci-effective-source-differs-from-hosted-commit")
    if value["runtime"] is None:
        blockers.append("original-ci-runtime-observation-unavailable")
    elif (value["runtime"]["javaArch"] != ("arm64" if lane == "macos-arm64" else "amd64")
          or value["runtime"]["provider"] != {"linux-amd64": "linux", "macos-arm64": "macos", "windows-amd64": "windows"}[lane]
          or value["runtime"]["filesystem"] == "other"):
        blockers.append("original-ci-native-provider-mismatch")
    if provider["ImageOS"] is None or provider["ImageVersion"] is None:
        blockers.append("original-ci-provider-image-unavailable")
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "bugs": 0, "warnings": 0, "missingClasses": 0}
    outcomes = {name: 0 for name in sorted(OUTCOMES)}
    applicability_totals = {"platformNotApplicable": 0, "unownedSkipped": 0}
    seen_rules = set()
    expected_sources = _v2_source_counts(ROOT)
    for row in rows:
        if (set(row) != {"module", "kind", "execution", "reportState", "reports"}
                or type(row["reports"]) is not list or len(row["reports"]) > 4096
                or row["reportState"] not in {"observed", "absent", "invalid"}):
            _deny()
        task = row["execution"]
        if (type(task) is not dict or set(task) != {"outcome", "startedAt", "completedAt", "sourceFiles",
                                                 "inputClasses", "filtered", "analysisEnabled", "toolchain", "sourceCoverage"}
                or task["outcome"] not in OUTCOMES
                or any(type(task[key]) is not bool for key in ("filtered", "analysisEnabled"))
                or any(type(task[key]) is not int or not 0 <= task[key] <= 1000000 for key in ("sourceFiles", "inputClasses"))):
            _deny()
        outcome = task["outcome"]
        if task["sourceCoverage"] not in {"matched", "invalid", "unavailable"}:
            _deny()
        _toolchain_facts(task["toolchain"])
        outcomes[outcome] += 1
        if task["sourceFiles"] != expected_sources[row["module"], row["kind"]]:
            blockers.append("original-ci-source-set-coverage-differs")
        if task["sourceCoverage"] != "matched":
            blockers.append("original-ci-exact-source-set-coverage-unproven")
        if not expected_sources[row["module"], row["kind"]] and task["inputClasses"]:
            blockers.append("original-ci-source-free-stale-classes-observed")
        if outcome == "not-observed":
            if task["startedAt"] is not None or task["completedAt"] is not None:
                _deny()
        elif outcome == "incomplete" and task["completedAt"] is None:
            if not start <= _time(task["startedAt"]) <= end:
                blockers.append("original-ci-task-execution-outside-selected-job")
        elif not start <= _time(task["startedAt"]) <= _time(task["completedAt"]) <= end:
            blockers.append("original-ci-task-execution-outside-selected-job")
        if outcome == "no-source":
            if task["inputClasses"] or row["reports"] or row["reportState"] != "absent":
                _deny()
            if task["sourceFiles"]:
                blockers.append("original-ci-source-cohort-not-executed")
            continue
        if outcome != "executed":
            blockers.append("original-ci-required-task-not-freshly-executed")
        if (task["toolchain"] is None or task["toolchain"]["javaVendor"] == "other"
                or task["toolchain"]["javaArch"] != ("arm64" if lane == "macos-arm64" else "amd64")):
            blockers.append("original-ci-task-toolchain-unavailable-or-mismatched")
        if task["filtered"]:
            blockers.append("original-ci-filtered-task-selection")
        if row["kind"].startswith("errorprone") and (not task["analysisEnabled"] or not task["sourceFiles"]):
            blockers.append("original-ci-analyzer-execution-unproven")
        if row["kind"] == "junit" and (not task["sourceFiles"] or not task["inputClasses"]):
            blockers.append("original-ci-test-coverage-empty")
        if row["kind"].startswith("spotbugs") and not task["inputClasses"]:
            blockers.append("original-ci-analyzer-class-coverage-empty")
        if row["reportState"] != "observed" or not row["reports"]:
            blockers.append("original-ci-required-report-missing-or-invalid")
        expected = ({"tests", "failures", "errors", "skipped"} if row["kind"] == "junit" else
                    {"bugs", "errors", "missingClasses", "classes"} if row["kind"].startswith("spotbugs") else {"warnings", "errors"})
        for report in row["reports"]:
            reports_count += 1
            report_fields = {"counts", "executedAt"} | ({"applicability"} if row["kind"] == "junit" else set())
            if (reports_count > 4096 or type(report) is not dict or set(report) != report_fields
                    or type(report["counts"]) is not dict or set(report["counts"]) != expected
                    or any(type(number) is not int or not 0 <= number <= 10000000 for number in report["counts"].values())):
                _deny()
            if row["kind"] == "junit":
                applicability = report["applicability"]
                if (type(applicability) is not dict or set(applicability) != set(applicability_totals) | {"rules"}
                        or any(type(applicability[key]) is not int or applicability[key] < 0 for key in applicability_totals)
                        or applicability["platformNotApplicable"] + applicability["unownedSkipped"] != report["counts"]["skipped"]
                        or type(applicability["rules"]) is not list or len(applicability["rules"]) != applicability["platformNotApplicable"]
                        or any(not isinstance(rule, str) for rule in applicability["rules"])):
                    _deny()
                allowed_rules = {PLATFORM_RULE_IDS[key] for key, lanes in PLATFORM_NA.items() if key[0] == row["module"] and lane in lanes}
                rules = applicability["rules"]
                if (len(set(rules)) != len(rules) or not set(rules) <= allowed_rules or seen_rules.intersection(rules)):
                    _deny()
                seen_rules.update(rules)
                for key in applicability_totals:
                    applicability_totals[key] += applicability[key]
            # JUnit's original XML clock has second precision. Do not use file modification times.
            observed = _time(report["executedAt"])
            precision = dt.timedelta(seconds=1) if row["kind"] == "junit" else dt.timedelta(0)
            if outcome == "executed" and not _time(task["startedAt"]) < observed + precision and precision:
                blockers.append("original-ci-report-execution-outside-selected-task")
            if outcome == "executed" and (observed > _time(task["completedAt"])
                    or (not precision and observed < _time(task["startedAt"]))):
                blockers.append("original-ci-report-execution-outside-selected-task")
            if row["kind"] == "junit" and (not report["counts"]["tests"] or sum(report["counts"][key] for key in ("failures", "errors", "skipped")) > report["counts"]["tests"]):
                _deny()
            if row["kind"].startswith("spotbugs") and not report["counts"]["classes"]:
                blockers.append("original-ci-analyzer-class-coverage-empty")
            for key, number in report["counts"].items():
                if key in totals:
                    totals[key] += number
    if not totals["tests"]:
        blockers.append("original-ci-tests-not-observed")
    if totals["failures"] or totals["errors"]:
        blockers.append("original-ci-test-or-analyzer-failures")
    if totals["bugs"] or totals["warnings"] or totals["missingClasses"]:
        blockers.append("original-ci-analyzer-findings-require-disposition")
    if applicability_totals["unownedSkipped"]:
        blockers.append("original-ci-skipped-tests-require-owner-disposition")
    return {"schemaVersion": 2, "lane": lane, "provider": provider, "runtime": value["runtime"], "cohortRows": len(rows),
            "reportCount": reports_count, "totals": totals, "taskOutcomes": outcomes, "applicability": applicability_totals,
            "sonarLint": value["sonarLint"], "rawPayloads": "not-exported", "workflowSourceCommit": workflow_source,
            "signerCommit": signer, "blockers": sorted(set(blockers))}


def _reports(client, run, job, source, evaluation, lane="linux-amd64"):
    steps = {step["name"]: step for step in job["steps"]}
    if any(steps.get(name, {}).get("conclusion") != "success" for name in (PREPARE_STEP, RETAIN_STEP, ATTEST_STEP, UPLOAD_STEP)):
        return None
    listed = client.get(f"actions/runs/{run['id']}/artifacts?per_page=100")
    if (type(listed) is not dict or listed.get("total_count") != len(listed.get("artifacts", []))
            or len(listed["artifacts"]) > 100):
        _deny()
    name = f"phase-12-ci-reports-{run['id']}-{run['run_attempt']}"
    names = {name + "-" + lane} | ({name} if lane == "linux-amd64" else set())
    selected = [row for row in listed["artifacts"] if row.get("name") in names]
    if not selected:
        return None
    if len(selected) != 1:
        _deny()
    artifact = selected[0]
    if (artifact.get("expired") is not False or artifact.get("workflow_run", {}).get("id") != run["id"]
            or artifact["workflow_run"].get("head_sha") != run["head_sha"]
            or not _time(steps[UPLOAD_STEP]["started_at"]) <= _time(artifact["created_at"]) <= _time(steps[UPLOAD_STEP]["completed_at"])
            or type(artifact.get("id")) is not int or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= MAX_JSON or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(artifact.get("digest")))):
        _deny()
    archive = client.get(f"actions/artifacts/{artifact['id']}/zip", raw=True)
    if len(archive) != artifact["size_in_bytes"] or digest(archive) != artifact["digest"]:
        _deny()
    if (len(archive) < 22 or archive[:4] != b"PK\x03\x04" or archive[-22:-18] != b"PK\x05\x06"
            or int.from_bytes(archive[-10:-6], "little") + int.from_bytes(archive[-6:-2], "little") != len(archive) - 22):
        _deny()
    with zipfile.ZipFile(io.BytesIO(archive)) as container:
        members = container.infolist()
        if container.comment or len(members) != 1 or members[0].filename != REPORT_FILE:
            _deny()
        member = members[0]
        if (member.file_size > MAX_JSON or member.flag_bits & 1 or member.is_dir() or member.extra or member.comment
                or member.header_offset != 0 or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFREG}):
            _deny()
        raw = container.read(member)
    # A PR can execute a reviewed head while its local reusable workflow/signature originates
    # at the original test merge. Validate that actual parent relationship and exact original
    # attestation, retaining the difference instead of replacing either commit with the other.
    selected = parse(raw)
    if (selected.get("schemaVersion") == 2 and (selected.get("lane") != lane
            or artifact.get("name") != name + "-" + lane)):
        _deny()
    if selected.get("schemaVersion") == 1 and lane != "linux-amd64":
        _deny()
    workflow_source, signer = selected.get("workflowSourceCommit"), selected.get("signerCommit")
    if (not isinstance(workflow_source, str) or not re.fullmatch(r"[a-f0-9]{40}", workflow_source)
            or signer != workflow_source):
        _deny()
    different = workflow_source != run["head_sha"]
    if different:
        if run["event"] != "pull_request":
            _deny()
        commit = client.get("git/commits/" + workflow_source)
        if (commit.get("sha") != workflow_source or len(commit.get("parents", [])) != 2
                or run["head_sha"] not in {row["sha"] for row in commit["parents"]}):
            _deny()
    client.attest(raw, run, workflow_source, signer)
    facts = _report_facts(raw, source, run, job, evaluation, workflow_source, signer)
    if different:
        facts["blockers"].append("original-workflow-source-differs-from-audited-product")
    return facts


def _checkout_sha(job, raw):
    """Read only the pinned checkout action's exact original step interval in the job log."""
    checkout = [step for step in job["steps"] if step.get("name") == "Run " + CHECKOUT]
    if len(checkout) != 1 or checkout[0].get("conclusion") != "success":
        return None
    step = checkout[0]
    lines = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z) (.*)", line)
        if match and _step_contains(step, _time(match[1])):
            lines.append(match[2])
    selected = []
    for index, line in enumerate(lines[:-1]):
        # checkout emits a quoted absolute executable on Windows (including spaces).
        # Match the executable token, not an arbitrary prefix containing a git command.
        executable = r'(?:git(?:\.exe)?|/[^\r\n" ]*/git(?:\.exe)?|"[A-Za-z]:\\[^\r\n"]*\\git\.exe")'
        if re.fullmatch(r"\[command\]" + executable + r" log -1 --format=(?:%H|'\%H'|\"%H\")", line):
            value = lines[index + 1].strip()
            if re.fullmatch(r"[0-9a-f]{40}", value):
                selected.append(value)
    return selected[0] if len(selected) == 1 else None


def _workflow_applicability(client, run, evaluation):
    """Use original event coordinates and complete current metadata for that exact PR diff.

    Retained callers never provide changed paths. GitHub's PR-file API is mutable, so both
    sides of its bounded read must still match the head/base recorded on the original run.
    Missing, moved or truncated context is unknown; it cannot grant a path exemption.
    """
    def unknown(code):
        return {"state": "unknown", "requiredWorkflows": [], "context": None}, [code]
    for path, expected in TRIGGERS.items():
        text = read_file(ROOT / path).decode("utf-8")
        if "\non:\n" not in text or text.split("\non:\n", 1)[1].split("  workflow_dispatch:\n", 1)[0] != expected:
            return unknown("original-ci-workflow-trigger-policy-drift")
    required = set()
    if run["event"] == "push":
        branch = run.get("head_branch")
        if not isinstance(branch, str) or not branch:
            return unknown("original-ci-push-ref-metadata-unavailable")
        # These disjoint repository release names distinguish the owner's branch and tag
        # trigger classes. Other names cannot be inferred to be an eligible push reference.
        if branch in {"main", "develop"} or re.fullmatch(r"(?:release|hotfix)/.+", branch):
            required.add(".github/workflows/ci.yml")
        if branch.startswith("release/") or re.fullmatch(r"v[^/]*", branch):
            required.add(".github/workflows/production-beta-release.yml")
        if re.fullmatch(r"v[0-9]+", branch):
            required.add(".github/workflows/ci.yml")
        if not required:
            return unknown("original-ci-push-ref-outside-owner-filters")
        return {"state": "authenticated-event-filters", "requiredWorkflows": sorted(required),
                "context": {"event": "push", "refName": branch}}, []
    originals = run.get("pull_requests")
    if type(originals) is not list or len(originals) != 1:
        return unknown("original-ci-pr-event-metadata-unavailable")
    original = originals[0]
    number = original.get("number")
    if type(number) is not int or not 0 < number < 2**53:
        return unknown("original-ci-pr-event-metadata-unavailable")
    head, base = original.get("head", {}), original.get("base", {})
    if (head.get("sha") != run["head_sha"] or not isinstance(base.get("ref"), str)
            or not re.fullmatch(r"[a-f0-9]{40}", str(base.get("sha")))):
        return unknown("original-ci-pr-event-metadata-unavailable")
    try:
        before = client.get(f"pulls/{number}")
        if (before.get("number") != number or before.get("base", {}).get("repo", {}).get("full_name") != REPOSITORY):
            _deny()
        def identity(value):
            return (value.get("head", {}).get("sha"), value.get("base", {}).get("sha"),
                    value.get("base", {}).get("ref"), value.get("changed_files"), value.get("updated_at"))
        if identity(before)[:3] != (run["head_sha"], base["sha"], base["ref"]):
            return unknown("original-ci-pr-diff-source-drift")
        total = before.get("changed_files")
        if type(total) is not int or not 0 < total <= 300:
            return unknown("original-ci-pr-diff-truncated-or-unavailable")
        if _time(before.get("updated_at")) > evaluation:
            return unknown("original-ci-pr-metadata-after-evaluation")
        files = []
        for page in range(1, (total + 99) // 100 + 1):
            found = client.get(f"pulls/{number}/files?per_page=100&page={page}")
            if type(found) is not list or len(found) != min(100, total - len(files)):
                return unknown("original-ci-pr-diff-truncated-or-unavailable")
            files.extend(found)
        after = client.get(f"pulls/{number}")
        if identity(after) != identity(before):
            return unknown("original-ci-pr-diff-source-drift")
    except OriginalCIUnavailable:
        return unknown("original-ci-pr-applicability-access-unavailable")
    paths = []
    for item in files:
        path = item.get("filename")
        names = [path] + ([item.get("previous_filename")] if item.get("status") == "renamed" else [])
        if any(not isinstance(name, str) or len(name) > 2048 or name.startswith("/") or "\\" in name
               or any(part in {"", ".", ".."} for part in name.split("/"))
               or any(ord(char) < 32 for char in name) for name in names):
            _deny()
        paths.extend(names)
    if len({item["filename"] for item in files}) != total:
        return unknown("original-ci-pr-diff-truncated-or-unavailable")
    branch = base["ref"]
    if branch in {"main", "develop"} or re.fullmatch(r"(?:feature|bugfix|hotfix|release)/.+", branch):
        required.add(".github/workflows/ci.yml")
    if branch in {"main", "develop"} or re.fullmatch(r"(?:release|hotfix)/.+", branch):
        required.add(".github/workflows/production-beta-release.yml")
    if any(re.fullmatch(r"(?:tools/ecosystem-transparency/.+|"
            r"tools/release-certification/cryptad_certification/transparency[^/]*|"
            r"tools/release-certification/cryptad_certification/tests/test_transparency[^/]*|"
            r"\.github/workflows/public-ecosystem-transparency\.yml)", path) for path in paths):
        required.add(".github/workflows/public-ecosystem-transparency.yml")
    return {"state": "authenticated-event-and-complete-pr-diff", "requiredWorkflows": sorted(required),
            "context": {"event": "pull_request", "number": number, "baseCommit": base["sha"],
                        "baseBranch": branch, "changedFiles": total}}, []


def _run(client, requested, source, as_of):
    selected = requested["run"]
    run_id, attempt = selected["id"], selected["run_attempt"]
    prefix = f"actions/runs/{run_id}/attempts/{attempt}"
    run = client.get(prefix)
    if (run.get("id") != run_id or run.get("run_attempt") != attempt
            or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("head_sha") != source["commit"] or run.get("path") not in WORKFLOWS
            or run.get("path") != selected["path"] or run.get("event") != selected["event"]
            or run.get("event") not in {"push", "pull_request"}
            or run.get("status") != "completed" or _time(run["updated_at"]) > as_of):
        _deny()
    jobs = client.get(prefix + "/jobs?per_page=100")
    if (type(jobs) is not dict or type(jobs.get("jobs")) is not list
            or jobs.get("total_count") != len(jobs["jobs"]) or len(jobs["jobs"]) > 32):
        _deny()
    actual = {row["name"]: row for row in jobs["jobs"]}
    expected = dict(STEPS[run["path"]])
    if run["path"] == ".github/workflows/ci.yml" and set(NATIVE_STEPS).intersection(actual):
        expected.update(NATIVE_STEPS)
    if (len(actual) != len(jobs["jobs"]) or not set(expected) <= set(actual)
            or not set(actual) <= set(expected) | EXPECTED_SKIPS[run["path"]]):
        _deny()
    records, blockers = [], []
    for name, job in sorted(actual.items()):
        if (job.get("run_id") != run_id or job.get("run_attempt", attempt) != attempt
                or job.get("head_sha") != source["commit"] or type(job.get("id")) is not int
                or type(job.get("steps")) is not list or len(job["steps"]) > 100):
            _deny()
        conclusion = job.get("conclusion")
        if name not in expected:
            if conclusion != "skipped":
                _deny()
            records.append({"jobId": job["id"], "name": name, "execution": "skipped",
                            "scope": "owner-event-inapplicable"})
            continue
        steps = {step["name"]: step for step in job["steps"]}
        if len(steps) != len(job["steps"]):
            _deny()
        required = expected[name]
        passing = [step for step in required if steps.get(step, {}).get("conclusion") == "success"]
        executed = (conclusion == "success" and (len(passing) == 1 if name == "build / build"
                                                 else len(passing) == len(required)))
        if not executed:
            blockers.append("required-original-ci-job-not-executed-pass")
        try:
            checked = _checkout_sha(job, client.get(f"actions/jobs/{job['id']}/logs", raw=True))
        except OriginalCIUnavailable:
            checked = None
            blockers.append("original-checkout-log-unavailable")
        if checked is None:
            blockers.append("original-checkout-identity-unavailable")
        elif checked != source["commit"]:
            blockers.append("original-checkout-differs-from-audited-source")
        kind = "push" if run["event"] == "push" else "pr-head" if checked == source["commit"] else "pr-test-merge-unverified"
        if checked and checked != source["commit"]:
            commit = client.get("git/commits/" + checked)
            if commit.get("sha") != checked:
                _deny()
            if run["event"] == "pull_request" and source["commit"] in {p["sha"] for p in commit.get("parents", [])}:
                kind = "pr-test-merge"
        check_url = job.get("check_run_url", "")
        match = re.fullmatch(r"https://api.github.com/repos/crypta-network/cryptad/check-runs/([1-9][0-9]*)", check_url)
        if match is None:
            _deny()
        check = client.get("check-runs/" + match[1])
        if (check.get("id") != int(match[1]) or check.get("head_sha") != source["commit"]
                or check.get("name") != name or check.get("app", {}).get("slug") != "github-actions"
                or check.get("conclusion") != conclusion):
            _deny()
        count = check.get("output", {}).get("annotations_count")
        if type(count) is not int or not 0 <= count <= 100:
            _deny()
        annotations = client.get("check-runs/" + match[1] + "/annotations?per_page=100")
        if type(annotations) is not list or len(annotations) != count:
            _deny()
        levels = {level: 0 for level in ("notice", "warning", "failure")}
        for item in annotations:
            level = item.get("annotation_level")
            if level not in levels:
                _deny()
            levels[level] += 1
        if levels["warning"] or levels["failure"]:
            blockers.append("original-ci-annotations-require-disposition")
        if name == "build / build" and steps.get("Build and analyze (Gradle)", {}).get("conclusion") == "success":
            blockers.append("original-sonarcloud-disposition-unavailable")
        reports = None
        if name == "build / build" or name in NATIVE_STEPS:
            try:
                lane = next(key for key, spec in LANES.items() if spec[3] == name)
                reports = _reports(client, run, job, source, as_of, lane)
            except OriginalCIUnavailable:
                blockers.append("original-ci-report-access-unavailable")
            if reports is not None:
                blockers.extend(reports["blockers"])
        skipped = (conclusion in {"skipped", "neutral"} or (conclusion == "success" and not executed
                   and any(steps.get(step, {}).get("conclusion") in {None, "skipped", "neutral"} for step in required)))
        records.append({"jobId": job["id"], "name": name,
            "execution": "executed-pass" if conclusion == "success" and job["steps"] else "skipped" if conclusion in {"skipped", "neutral"} else "executed-fail",
            "requiredStepExecution": "executed-pass" if executed else "skipped" if skipped else "executed-fail",
            "jobConclusion": conclusion,
            "checkedCommit": checked, "checkoutKind": kind, "checkRunId": check["id"],
            "annotationCounts": levels, "reportFacts": reports,
            "tests": "original-attested-report-facts" if reports is not None else "original-machine-reports-unavailable",
            "analyzers": "original-attested-applicable-report-facts" if reports is not None else
                         "annotation-counts-only;complete-original-reports-unavailable"})
    applicability, gaps = _workflow_applicability(client, run, as_of)
    blockers.extend(gaps)
    return {"runId": run_id, "attempt": attempt, "workflow": run["path"], "event": run["event"],
            "sourceCommit": source["commit"], "requiredWorkflows": applicability["requiredWorkflows"],
            "applicability": applicability, "jobs": records}, blockers


def _external_checks(client, source, evaluation):
    """Observe the server-selected latest fixed scanners; absence never asserts scan execution."""
    scanners = {"SonarCloud Code Analysis": ("sonarqubecloud", "sonarcloud"),
                "Analyze (python)": ("github-actions", "codeql-python"),
                "Analyze (actions)": ("github-actions", "codeql-actions"),
                "Analyze (javascript-typescript)": ("github-actions", "codeql-javascript-typescript")}
    def unavailable(code):
        return {"state": "unavailable", "checks": []}, [code]
    try:
        value = client.get(f"commits/{source['commit']}/check-runs?filter=latest&per_page=100")
    except OriginalCIUnavailable:
        return unavailable("original-ci-external-check-access-unavailable")
    if (type(value) is not dict or type(value.get("total_count")) is not int
            or not 0 <= value["total_count"] <= 100 or type(value.get("check_runs")) is not list
            or len(value["check_runs"]) != value["total_count"]):
        return unavailable("original-ci-external-check-coverage-incomplete")
    checks, blockers, identities, check_ids = [], [], set(), set()
    statuses = {"queued", "in_progress", "completed", "waiting", "requested", "pending"}
    conclusions = {"success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure"}
    for check in value["check_runs"]:
        if (type(check) is not dict or type(check.get("id")) is not int or not 0 < check["id"] < 2**53
                or check["id"] in check_ids or check.get("head_sha") != source["commit"]):
            return unavailable("original-ci-external-check-metadata-unverified")
        check_ids.add(check["id"])
        name = check.get("name")
        if name not in scanners:
            continue
        app, scanner = scanners[name]
        if check.get("app", {}).get("slug") != app or scanner in identities:
            return unavailable("original-ci-external-check-identity-ambiguous")
        identities.add(scanner)
        status, conclusion = check.get("status"), check.get("conclusion")
        if status not in statuses or (status == "completed" and conclusion not in conclusions) or (status != "completed" and conclusion is not None):
            return unavailable("original-ci-external-check-metadata-unverified")
        try:
            started = _time(check.get("started_at"))
            completed = _time(check.get("completed_at")) if check.get("completed_at") is not None else None
            if (started > evaluation or (completed is not None and not started <= completed <= evaluation)
                    or (status == "completed") != (completed is not None)):
                return unavailable("original-ci-external-check-clock-unverified")
        except (TypeError, ValueError):
            return unavailable("original-ci-external-check-clock-unverified")
        checks.append({"scanner": scanner, "checkRunId": check["id"], "status": status, "conclusion": conclusion,
                       "startedAt": started.isoformat(), "completedAt": completed.isoformat() if completed is not None else None,
                       "provenance": "original-check-only", "disposition": "unverified"})
        if scanner == "sonarcloud":
            blockers.append("original-sonarcloud-check-failed" if status == "completed" and conclusion == "failure"
                            else "original-sonarcloud-disposition-unavailable")
        elif status != "completed" or conclusion != "success":
            blockers.append("original-codeql-check-not-executed-pass")
    return {"state": "complete-original-check-list", "checks": sorted(checks, key=lambda row: row["scanner"])}, sorted(set(blockers))


def verify(raw, source, as_of, *, collect_original=False):
    """Reauthenticate selected retained run coordinates only when explicitly requested.

    Historical missing reports remain unavailable. Newly retained source-owned facts must
    pass exact original artifact/attestation admission and the complete report cohort; no
    caller-supplied flag or locally resealed summary can grant acceptance.
    """
    from .phase_12_provenance import hosted_records
    retained = hosted_records(raw, source, as_of)
    if not collect_original:
        return retained
    try:
        clean = _source_clean(source)
        now = timestamp(as_of).replace(tzinfo=dt.timezone.utc)
        if now > dt.datetime.now(dt.timezone.utc):
            _deny()
        client = _GitHub()
        records, blockers, workflows = [], [], set()
        external, external_gaps = _external_checks(client, source, now)
        blockers.extend(external_gaps)
        if not clean:
            blockers.append("ci-effective-source-differs-from-hosted-commit")
        for selected in parse(raw)["runs"]:
            record, gaps = _run(client, selected, source, now)
            if record["workflow"] in workflows:
                _deny()
            workflows.add(record["workflow"])
            records.append(record)
            blockers.extend(gaps)
        required_workflows = {path for record in records for path in record["requiredWorkflows"]}
        if records and all(record["applicability"]["state"] != "unknown" for record in records):
            if len({canonical(record["applicability"]["context"]) for record in records}) != 1:
                _deny()
            if workflows != required_workflows:
                blockers.append("required-original-ci-workflow-not-selected")
        # Historical builds retain only product archives. The new source-owned attested
        # projection permits an actual complete path without exposing raw diagnostic payloads.
        report_sets = [job["reportFacts"] for record in records for job in record["jobs"]
                       if job.get("reportFacts") is not None]
        if len(report_sets) != 1:
            if not report_sets or not any(item.get("schemaVersion") == 2 for item in report_sets):
                blockers.extend(["original-ci-test-report-retention-unavailable",
                                 "original-ci-nonblocking-analyzer-reports-unavailable"])
        platform_reports = [item for item in report_sets if item.get("schemaVersion") == 2]
        if platform_reports and (len(platform_reports) != len(LANES)
                or {item["lane"] for item in platform_reports} != set(LANES)):
            blockers.append("original-ci-supported-platform-results-incomplete")
        required_jobs = [job for record in records for job in record["jobs"] if "scope" not in job]
        state = ("executed-fail" if any(job["requiredStepExecution"] == "executed-fail" for job in required_jobs)
                 else "skipped" if any(job["requiredStepExecution"] == "skipped" for job in required_jobs)
                 else "unknown" if blockers else "executed-pass")
        return {"originalProvenance": "authenticated" if records else "not-supplied", "ci": state,
                "records": records, "observedAt": as_of, "retainedBytesDigest": retained["retainedBytesDigest"],
                "externalAnalyzers": external,
                "sourceDrift": not clean,
                "supportedPlatforms": "complete" if platform_reports and not blockers else "incomplete" if platform_reports else "unavailable-v1",
                "blockers": sorted(set(blockers))}
    except OriginalCIUnavailable:
        return {**retained, "sourceDrift": not clean,
                "blockers": sorted(set(retained["blockers"] + ["original-ci-access-unavailable"]))}
    except Exception:
        raise ValueError("phase12-original-ci-invalid") from None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", type=Path)
    parser.add_argument("--retain", type=Path)
    parser.add_argument("--started", type=Path)
    parser.add_argument("--lane", choices=tuple(LANES))
    args = parser.parse_args()
    try:
        if args.prepare and not args.retain and not args.started:
            with args.prepare.open("xb") as output:
                output.write(canonical({"startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}))
            args.prepare.chmod(0o600)
        elif args.retain and args.started and not args.prepare:
            if args.lane:
                retain_reports_v2(args.retain, args.started, args.lane)
            else:
                retain_reports(args.retain, args.started)
        else:
            _deny()
    except Exception:
        raise SystemExit("phase12-ci-report-retention-failed") from None
