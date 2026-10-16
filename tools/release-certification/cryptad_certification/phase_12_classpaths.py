"""Source-owned expectations for ordered verification classpaths, never task-supplied authority."""
import argparse
import json
from pathlib import Path
import re

from .active_source import _git, read_source, source_roster
from .transparency_bundle import digest, parse


ROSTER = "tools/release-certification/phase-12-classpaths.json"
FIELDS = {"classpath", "auxClasspath", "annotationProcessorPath"}
MAX_ROSTER = 2 * 1024 * 1024


def configuration_paths(selected):
    """Bind scripts, plugin implementation, version catalogs and the selected wrapper."""
    return sorted(name for name in selected if (
        name.endswith((".gradle", ".gradle.kts", "/gradle.properties"))
        or name == "gradle.properties"
        or name in {"gradle/wrapper/gradle-wrapper.properties", "gradle/wrapper/gradle-wrapper.jar"}
        or (name.endswith(".toml") and "/gradle/" in "/" + name)
        or (name.startswith("build-logic/src/main/kotlin/") and name.endswith(".kt"))))


def classpath_identity(root, name):
    """Ignore host/cache prefixes; preserve project paths and complete artifact coordinates."""
    if not isinstance(name, str) or not name:
        return None
    path = Path(name)
    path = path if path.is_absolute() else root / path
    if any(part in {".", ".."} for part in path.parts):
        return None
    parts = path.parts
    if len(parts) >= 7 and parts[-7:-5] == ("modules-2", "files-2.1"):
        coordinates = (parts[-5], parts[-4], parts[-3], parts[-1])
        if any(not value or any(c in value for c in ":/\\\r\n") for value in coordinates):
            return None
        return "module:" + ":".join(coordinates)
    # These identities establish membership only. Artifact authentication remains mandatory;
    # an unsupported Gradle/generated artifact is unavailable, never implicitly trusted here.
    if len(parts) >= 4 and parts[-2] == "generated-gradle-jars":
        match = re.fullmatch(r"gradle-(?:api|test-kit)-([0-9]+(?:\.[0-9]+)+)\.jar", parts[-1])
        if match and parts[-3] == match[1]:
            return "gradle-generated:" + match[1] + ":" + parts[-1]
    for index, part in enumerate(parts[:-2]):
        match = re.fullmatch(r"gradle-([0-9]+(?:\.[0-9]+)+)", part)
        if match and parts[index + 1] == "lib" and path.suffix == ".jar":
            return "gradle:" + match[1] + ":" + "/".join(parts[index + 1:])
    if path.is_relative_to(root):
        relative = path.relative_to(root).as_posix()
        return "project:" + relative if relative and ":" not in relative else None
    return None


def _reviewed_file(root, name, context):
    if name not in context["selected"]:
        raise FileNotFoundError("classpath-authority-not-selected")
    if not (root / name).exists() and not (root / name).is_symlink():
        raise FileNotFoundError("classpath-authority-not-present")
    raw = read_source(root, name, maximum=MAX_ROSTER)
    if context["sourceCommit"] is not None:
        if raw != _git(root, "show", context["sourceCommit"] + ":" + name):
            raise ValueError("classpath-authority-changed")
    return raw


def _validate(value):
    if (type(value) is not dict or set(value) != {"schemaVersion", "kind", "configuration", "tasks"}
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "phase-12-reviewed-classpaths"
            or type(value["configuration"]) is not dict or len(value["configuration"]) > 256
            or type(value["tasks"]) is not dict or len(value["tasks"]) > 512):
        raise ValueError("invalid-classpath-authority")
    if any(not isinstance(name, str) or not isinstance(checksum, str)
           or not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum)
           for name, checksum in value["configuration"].items()):
        raise ValueError("invalid-classpath-authority")
    for task, fields in value["tasks"].items():
        if (not isinstance(task, str) or not task.startswith(":") or len(task) > 256
                or type(fields) is not dict or not fields or not set(fields) <= FIELDS):
            raise ValueError("invalid-classpath-authority")
        for entries in fields.values():
            if entries is None:
                continue
            if (type(entries) is not list or len(entries) > 4096
                    or any(not isinstance(e, str) or len(e) > 1024
                           or not e.startswith(("project:", "module:", "gradle:", "gradle-generated:")) for e in entries)
                    or len(entries) != len(set(entries))):
                raise ValueError("invalid-classpath-authority")
    return value


def _load(root, context):
    if "reviewedClasspaths" not in context:
        value = _validate(parse(_reviewed_file(root, ROSTER, context)))
        configuration = {name: digest(_reviewed_file(root, name, context))
                         for name in configuration_paths(context["selected"])}
        context["reviewedClasspaths"] = value if value["configuration"] == configuration else None
    return context["reviewedClasspaths"]


def membership(record, field, entries, root, context):
    """An authenticated artifact may still be absent, extra, duplicated or in the wrong position."""
    if context is None:
        return "unavailable"
    try:
        value = _load(root, context)
        if value is None:
            return "unavailable"
        expected = value["tasks"].get(record.get("taskPath"), {}).get(field)
        if expected is None:
            return "unavailable"
        if len(entries) != len(expected):
            return "invalid"
        if any(type(entry) is not dict or not isinstance(entry.get("path"), str) for entry in entries):
            return "invalid"
        actual = [classpath_identity(root, entry["path"]) for entry in entries]
        if None in actual:
            return "unavailable"
        return "matched" if actual == expected else "invalid"
    except FileNotFoundError:
        return "unavailable"
    except (OSError, ValueError, KeyError, TypeError):
        return "invalid"


def candidate(root, raw):
    """Prepare a review candidate; committing it is a separate, explicit maintenance action."""
    tasks = parse(raw)
    selected = source_roster(root).paths
    value = _validate({"schemaVersion": 1, "kind": "phase-12-reviewed-classpaths",
                       "configuration": {name: digest(read_source(root, name))
                                         for name in configuration_paths(selected)}, "tasks": tasks})
    result = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(result) > MAX_ROSTER:
        raise ValueError("classpath-authority-exceeds-limit")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare a classpath roster for source review.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    input_path = args.input.absolute()
    raw = read_source(input_path.parent, input_path.name, maximum=MAX_ROSTER)
    with args.output.open("xb") as output:
        output.write(candidate(Path(__file__).resolve().parents[3], raw))
