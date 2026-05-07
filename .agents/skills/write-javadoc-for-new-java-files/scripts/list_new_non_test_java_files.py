#!/usr/bin/env python3
"""List newly added non-test Java files for the current git repository."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path, PurePosixPath

EXCLUDED_TEST_ROOT_NAMES = (
    "test",
    "testFixtures",
    "integrationTest",
    "functionalTest",
)
EXCLUDED_TEST_SUFFIXES = ("Test.java", "Tests.java", "IT.java", "ITCase.java")
DEFAULT_DEVELOP_REFS = ("origin/develop", "develop")


def run_git(repo_root: Path, *args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def git_succeeds(repo_root: Path, *args: str) -> bool:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.returncode == 0


def resolve_default_base_ref(repo_root: Path) -> str:
    branch = run_git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")[0]
    if branch == "develop":
        return "HEAD"

    for develop_ref in DEFAULT_DEVELOP_REFS:
        if git_succeeds(
            repo_root, "rev-parse", "--verify", "--quiet", f"{develop_ref}^{{commit}}"
        ):
            merge_base = run_git(repo_root, "merge-base", "HEAD", develop_ref)
            if merge_base:
                return merge_base[0]

    print(
        "warning: no origin/develop or develop ref found; defaulting --base-ref to HEAD",
        file=sys.stderr,
    )
    return "HEAD"


def normalize_repo_relative(repo_root: Path, raw_path: str) -> PurePosixPath:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            return PurePosixPath(candidate.resolve().relative_to(repo_root.resolve()).as_posix())
        except ValueError as exc:
            raise ValueError(f"limit path is outside the repository: {raw_path}") from exc

    normalized = raw_path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("../"):
        raise ValueError(f"limit path is outside the repository: {raw_path}")
    return PurePosixPath(normalized)


def has_excluded_test_root(path: PurePosixPath) -> bool:
    parts = path.parts
    for index in range(len(parts) - 1):
        if parts[index] == "src" and parts[index + 1] in EXCLUDED_TEST_ROOT_NAMES:
            return True
    return False


def is_non_test_java_file(path: PurePosixPath) -> bool:
    if path.suffix != ".java":
        return False
    if has_excluded_test_root(path):
        return False
    if path.name.endswith(EXCLUDED_TEST_SUFFIXES):
        return False
    return True


def matches_any_limit(path: PurePosixPath, limits: list[PurePosixPath]) -> bool:
    return not limits or any(path == limit or limit in path.parents for limit in limits)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List newly added non-test Java files relative to a git base ref.",
    )
    parser.add_argument(
        "--base-ref",
        default=None,
        help=(
            "Git base ref to compare against. Defaults to HEAD on develop, or the merge base with "
            "origin/develop or develop on other branches."
        ),
    )
    parser.add_argument(
        "--limit",
        action="append",
        default=[],
        help="Optional repo-relative path or subtree to keep in scope. Repeat as needed.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        repo_root = Path(
            run_git(Path.cwd(), "rev-parse", "--show-toplevel")[0]
        ).resolve()
        limit_paths = [normalize_repo_relative(repo_root, raw_limit) for raw_limit in args.limit]
        base_ref = args.base_ref or resolve_default_base_ref(repo_root)
        added_paths = run_git(repo_root, "diff", "--name-only", "--diff-filter=A", base_ref, "--")
        untracked_paths = run_git(repo_root, "ls-files", "--others", "--exclude-standard", "--")
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        message = stderr or str(exc)
        print(message, file=sys.stderr)
        return exc.returncode
    except IndexError:
        print("unable to determine git repository root", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    selected_paths = {
        path
        for raw_path in [*added_paths, *untracked_paths]
        if is_non_test_java_file(path := normalize_repo_relative(repo_root, raw_path))
        and matches_any_limit(path, limit_paths)
    }

    for path in sorted(selected_paths):
        print(path.as_posix())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
