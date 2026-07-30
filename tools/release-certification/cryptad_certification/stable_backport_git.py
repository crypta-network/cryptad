"""Read-only Git inspection for Stable 1.0 backport and release-train evidence.

The module accepts only full hexadecimal object IDs and invokes Git with argument
vectors in one exact, non-shallow repository.  Branch names, tags, commit
messages, trailers, and patch-id equality are deliberately not authorization
sources.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Mapping, Sequence

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BUILD_RE = re.compile(r"^[1-9][0-9]*$")
_REPOSITORY_IDENTITY_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,62})/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$"
)
_OBJECT_LENGTHS = {"sha1": 40, "sha256": 64}
_READ_ONLY_GIT_PREFIX = (
    "git",
    "--no-replace-objects",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
)
_MAX_PATH_LENGTH = 512
_MAX_PATH_COUNT = 1024
_MAX_CANDIDATE_COMMITS = 4096
_GIT_OUTPUT_CHUNK_BYTES = 64 * 1024


class GitInspectionError(ValueError):
    """Raised when Git evidence cannot be authenticated safely."""


@dataclass(frozen=True)
class GitObjectIdentity:
    """Exact repository and commit identity."""

    repository_identity: str
    object_format: str
    commit: str


@dataclass(frozen=True)
class PathChange:
    """One path-level change from a commit diff."""

    status: str
    old_path: str | None
    new_path: str

    @property
    def paths(self) -> tuple[str, ...]:
        """Return every path participating in the change."""

        if self.old_path is None or self.old_path == self.new_path:
            return (self.new_path,)
        return (self.old_path, self.new_path)


@dataclass(frozen=True)
class CommitInspection:
    """Authenticated, bounded evidence for one exact commit."""

    identity: GitObjectIdentity
    tree_oid: str
    tree_digest: str
    diff_digest: str
    parents: tuple[str, ...]
    changes: tuple[PathChange, ...]
    touched_paths: tuple[str, ...]
    is_merge: bool
    is_empty: bool
    contains_binary_patch: bool
    contains_rename_or_copy: bool


@dataclass(frozen=True)
class PatchProvenance:
    """Source-to-candidate provenance with independent authorization evidence."""

    mode: str
    source_commit: str
    candidate_commit: str | None
    candidate_tip: str
    stable_patch_id: str | None
    source_tree_oid: str
    source_tree_digest: str
    source_diff_digest: str
    candidate_tree_oid: str | None
    candidate_tree_digest: str | None
    candidate_diff_digest: str | None
    touched_paths: tuple[str, ...]
    merge_base_commit: str | None
    source_base_commit: str | None
    target_base_commit: str | None
    conflict_paths: tuple[str, ...]
    normalized_diff_evidence_digest: str | None
    reviewer_authorization_digest: str
    focused_test_evidence_ids: tuple[str, ...]
    no_unrelated_feature_change: bool | None


@dataclass(frozen=True)
class BranchRoleEvidence:
    """Exact object-graph evidence for a release lane and branch role."""

    lane: str
    candidate_build: str
    candidate_commit: str
    branch_base: str
    authorized_lineage_commit: str | None
    authenticated_predecessor_commit: str
    predecessor_merge_base: str
    branch_role: str
    base_role: str
    no_fork: bool


@dataclass(frozen=True)
class MergeEvidence:
    """Exact two-parent merge evidence supplemented by protected attestation."""

    merge_commit: str
    first_parent: str
    merged_tip: str
    protected_ref: str
    protected_tip: str
    parent_count: int
    graph_verified: bool
    workflow_attestation_digest: str


class NonAutomaticMergeResolutionError(GitInspectionError):
    """Report an authenticated merge graph whose content needs separate review."""

    def __init__(
        self,
        evidence: MergeEvidence,
        resolution_paths: tuple[str, ...],
    ) -> None:
        super().__init__(
            "reconciliation merge contains a non-automatic content resolution"
        )
        self.evidence = evidence
        self.resolution_paths = resolution_paths


class GitInspector:
    """Inspect one exact repository without fetching or mutating Git state."""

    def __init__(
        self,
        repository_root: Path,
        *,
        expected_repository_identity: str,
        max_output_bytes: int = 8 * 1024 * 1024,
        timeout_seconds: int = 30,
    ) -> None:
        if not isinstance(repository_root, Path) or not repository_root.is_absolute():
            raise GitInspectionError("repository root must be an absolute path")
        if not _REPOSITORY_IDENTITY_RE.fullmatch(expected_repository_identity):
            raise GitInspectionError("repository identity is not canonical")
        if (
            type(max_output_bytes) is not int
            or max_output_bytes < 1024
            or max_output_bytes > 64 * 1024 * 1024
        ):
            raise GitInspectionError("Git output bound is invalid")
        if type(timeout_seconds) is not int or timeout_seconds < 1 or timeout_seconds > 300:
            raise GitInspectionError("Git timeout is invalid")
        try:
            resolved = repository_root.resolve(strict=True)
        except OSError as exc:
            raise GitInspectionError("repository root is unavailable") from exc
        if resolved != repository_root or not resolved.is_dir():
            raise GitInspectionError("repository root must be exact and symlink-free")
        self._root = resolved
        self._repository_identity = expected_repository_identity
        self._max_output_bytes = max_output_bytes
        self._timeout_seconds = timeout_seconds
        self._environment = self._sanitized_environment()
        self._verify_repository_root()
        self._verify_repository_storage()
        object_format = self._run_text(("rev-parse", "--show-object-format")).strip()
        if object_format not in _OBJECT_LENGTHS:
            raise GitInspectionError("repository object format is unsupported")
        self._object_format = object_format
        shallow = self._run_text(("rev-parse", "--is-shallow-repository")).strip()
        if shallow != "false":
            raise GitInspectionError("shallow repositories cannot authenticate ancestry")

    @property
    def repository_identity(self) -> str:
        """Return the protected repository identity bound to this inspector."""

        return self._repository_identity

    @property
    def object_format(self) -> str:
        """Return the repository storage object format."""

        return self._object_format

    def validate_commit_oid(self, object_id: str) -> str:
        """Validate a full canonical object ID and prove it names a commit."""

        if not isinstance(object_id, str):
            raise GitInspectionError("Git object ID must be text")
        expected_length = _OBJECT_LENGTHS[self._object_format]
        if (
            len(object_id) != expected_length
            or object_id.lower() != object_id
            or re.fullmatch(r"[0-9a-f]+", object_id) is None
        ):
            raise GitInspectionError("Git object ID is not a full canonical commit ID")
        object_type = self._run_text(("cat-file", "-t", "--", object_id)).strip()
        if object_type != "commit":
            raise GitInspectionError("Git object is not a commit")
        return object_id

    def inspect_commit(self, object_id: str) -> CommitInspection:
        """Return exact tree, diff, parent, and path evidence for a commit."""

        commit = self.validate_commit_oid(object_id)
        revision_row = self._run_text(("rev-list", "--parents", "-n", "1", commit, "--")).strip()
        revision_parts = revision_row.split()
        if not revision_parts or revision_parts[0] != commit:
            raise GitInspectionError("Git commit parent evidence is malformed")
        parents = tuple(self.validate_commit_oid(parent) for parent in revision_parts[1:])
        tree_oid = self._run_text(("show", "-s", "--format=%T", commit, "--")).strip()
        self._validate_object_id(tree_oid, "tree")
        tree_bytes = self._run(("cat-file", "tree", tree_oid))
        tree_digest = _sha256(tree_bytes)
        diff_bytes = self._commit_diff_bytes(commit, parents)
        changes = self._path_changes(commit, parents)
        touched_paths = tuple(
            sorted({path for change in changes for path in change.paths})
        )
        return CommitInspection(
            identity=GitObjectIdentity(
                repository_identity=self._repository_identity,
                object_format=self._object_format,
                commit=commit,
            ),
            tree_oid=tree_oid,
            tree_digest=tree_digest,
            diff_digest=_sha256(diff_bytes),
            parents=parents,
            changes=changes,
            touched_paths=touched_paths,
            is_merge=len(parents) > 1,
            is_empty=not changes,
            contains_binary_patch=(
                b"GIT binary patch" in diff_bytes or b"Binary files " in diff_bytes
            ),
            contains_rename_or_copy=any(
                change.status.startswith(("R", "C")) for change in changes
            ),
        )

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Return whether one exact commit is an ancestor of another."""

        older = self.validate_commit_oid(ancestor)
        newer = self.validate_commit_oid(descendant)
        result = self._run_result(
            ("merge-base", "--is-ancestor", older, newer),
            allowed_returncodes=(0, 1),
        )
        return result.returncode == 0

    def is_first_parent_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Return whether a commit is on a protected tip's first-parent chain."""

        older = self.validate_commit_oid(ancestor)
        newer = self.validate_commit_oid(descendant)
        if not self.is_ancestor(older, newer):
            return False
        distance_text = self._run_text(
            (
                "rev-list",
                "--first-parent",
                "--count",
                f"{older}..{newer}",
                "--",
            )
        ).strip()
        if not distance_text.isascii() or not distance_text.isdecimal():
            raise GitInspectionError("first-parent distance is malformed")
        reached = self._run_text(
            (
                "rev-parse",
                "--verify",
                f"{newer}~{distance_text}^{{commit}}",
            )
        ).strip()
        return self.validate_commit_oid(reached) == older

    def merge_base(self, left: str, right: str) -> str:
        """Return the unique exact merge base for two commits."""

        left_commit = self.validate_commit_oid(left)
        right_commit = self.validate_commit_oid(right)
        bases = [
            line
            for line in self._run_text(
                ("merge-base", "--all", left_commit, right_commit)
            ).splitlines()
            if line
        ]
        if len(bases) != 1:
            raise GitInspectionError("commits do not have one exact merge base")
        return self.validate_commit_oid(bases[0])

    def stable_patch_id(self, object_id: str) -> str:
        """Return a stable patch ID as supporting identity, never authorization."""

        commit = self.inspect_commit(object_id)
        if commit.is_merge:
            raise GitInspectionError("merge commits do not have single-parent patch provenance")
        if commit.is_empty:
            raise GitInspectionError("empty commits do not have patch provenance")
        patch = self._run(
            (
                "show",
                "--pretty=format:commit %H",
                "--binary",
                "--full-index",
                "--no-color",
                "--no-ext-diff",
                "--find-renames",
                "--find-copies",
                "--find-copies-harder",
                commit.identity.commit,
                "--",
            )
        )
        row = self._run_text(("patch-id", "--stable"), input_bytes=patch).strip()
        parts = row.split()
        if len(parts) != 2 or parts[1] != commit.identity.commit:
            raise GitInspectionError("stable patch identity output is malformed")
        patch_id = parts[0]
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", patch_id) is None:
            raise GitInspectionError("stable patch identity is not canonical")
        return patch_id

    def normalized_patch_digest(self, object_id: str) -> str:
        """Digest exact patch content while normalizing only base-dependent headers."""

        commit = self.inspect_commit(object_id)
        self._require_single_parent_patch(commit, "normalized patch")
        patch = self._run(
            (
                "show",
                "--pretty=format:",
                "--binary",
                "--full-index",
                "--no-color",
                "--no-ext-diff",
                "--find-renames",
                "--find-copies",
                "--find-copies-harder",
                commit.identity.commit,
                "--",
            )
        )
        normalized: list[bytes] = []
        for line in patch.splitlines(keepends=True):
            if line.startswith(b"index "):
                continue
            if line.startswith(b"@@ "):
                line = re.sub(
                    rb"^@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@",
                    b"@@ @@",
                    line,
                    count=1,
                )
            normalized.append(line)
        return _sha256(b"".join(normalized))

    def manual_conflict_evidence_digest(
        self,
        source_commit: str,
        candidate_commit: str,
        conflict_paths: Iterable[str],
    ) -> str:
        """Return the exact normalized source/candidate conflict evidence identity."""

        source_digest = self.normalized_patch_digest(source_commit)
        candidate_digest = self.normalized_patch_digest(candidate_commit)
        paths = _canonical_paths(conflict_paths)
        if not paths:
            raise GitInspectionError("manual conflict evidence requires conflict paths")
        subject = b"\0".join(
            (
                b"stable-1.0-manual-conflict-evidence-v1",
                source_digest.encode("ascii"),
                candidate_digest.encode("ascii"),
                *(path.encode("utf-8") for path in paths),
            )
        )
        return _sha256(subject)

    def verify_inherited(
        self,
        source_commit: str,
        candidate_tip: str,
        authorization_digest: str,
    ) -> PatchProvenance:
        """Verify that the exact accepted source commit is inherited by a candidate."""

        authorization = _require_digest(authorization_digest, "authorization")
        source = self.inspect_commit(source_commit)
        tip = self.validate_commit_oid(candidate_tip)
        if not self.is_ancestor(source.identity.commit, tip):
            raise GitInspectionError("source commit is not inherited by the candidate")
        return PatchProvenance(
            mode="inherited",
            source_commit=source.identity.commit,
            candidate_commit=source.identity.commit,
            candidate_tip=tip,
            stable_patch_id=None,
            source_tree_oid=source.tree_oid,
            source_tree_digest=source.tree_digest,
            source_diff_digest=source.diff_digest,
            candidate_tree_oid=source.tree_oid,
            candidate_tree_digest=source.tree_digest,
            candidate_diff_digest=source.diff_digest,
            touched_paths=source.touched_paths,
            merge_base_commit=source.identity.commit,
            source_base_commit=source.parents[0] if len(source.parents) == 1 else None,
            target_base_commit=source.parents[0] if len(source.parents) == 1 else None,
            conflict_paths=(),
            normalized_diff_evidence_digest=None,
            reviewer_authorization_digest=authorization,
            focused_test_evidence_ids=(),
            no_unrelated_feature_change=True,
        )

    def verify_clean_cherry_pick(
        self,
        source_commit: str,
        candidate_commit: str,
        candidate_tip: str,
        authorization_digest: str,
        allowed_paths: Iterable[str],
    ) -> PatchProvenance:
        """Verify a distinct authorized clean cherry-pick in candidate history."""

        authorization = _require_digest(authorization_digest, "authorization")
        source = self.inspect_commit(source_commit)
        candidate = self.inspect_commit(candidate_commit)
        tip = self.validate_commit_oid(candidate_tip)
        if source.identity.commit == candidate.identity.commit:
            raise GitInspectionError("a clean cherry-pick must use a distinct commit")
        self._require_single_parent_patch(source, "source")
        self._require_single_parent_patch(candidate, "candidate")
        if not self.is_ancestor(candidate.identity.commit, tip):
            raise GitInspectionError("cherry-pick commit is not in candidate history")
        source_patch_id = self.stable_patch_id(source.identity.commit)
        candidate_patch_id = self.stable_patch_id(candidate.identity.commit)
        if source_patch_id != candidate_patch_id:
            raise GitInspectionError("stable patch identities do not match")
        normalized_patch_digest = self.normalized_patch_digest(source.identity.commit)
        if normalized_patch_digest != self.normalized_patch_digest(
            candidate.identity.commit
        ):
            raise GitInspectionError(
                "stable patch identity hides a normalized patch-content mismatch"
            )
        allowed = _canonical_paths(allowed_paths)
        if source.touched_paths != candidate.touched_paths or source.touched_paths != allowed:
            raise GitInspectionError("cherry-pick touched-path scope does not match")
        merge_base = self.merge_base(source.parents[0], candidate.parents[0])
        return PatchProvenance(
            mode="clean-cherry-pick",
            source_commit=source.identity.commit,
            candidate_commit=candidate.identity.commit,
            candidate_tip=tip,
            stable_patch_id=source_patch_id,
            source_tree_oid=source.tree_oid,
            source_tree_digest=source.tree_digest,
            source_diff_digest=source.diff_digest,
            candidate_tree_oid=candidate.tree_oid,
            candidate_tree_digest=candidate.tree_digest,
            candidate_diff_digest=candidate.diff_digest,
            touched_paths=allowed,
            merge_base_commit=merge_base,
            source_base_commit=source.parents[0],
            target_base_commit=candidate.parents[0],
            conflict_paths=(),
            normalized_diff_evidence_digest=normalized_patch_digest,
            reviewer_authorization_digest=authorization,
            focused_test_evidence_ids=(),
            no_unrelated_feature_change=True,
        )

    def verify_manual_conflict_resolution(
        self,
        *,
        source_commit: str,
        candidate_commit: str,
        candidate_tip: str,
        source_base_commit: str,
        target_base_commit: str,
        expected_merge_base_commit: str,
        conflict_paths: Iterable[str],
        allowed_paths: Iterable[str],
        reviewer_authorization_digest: str,
        focused_test_evidence_ids: Iterable[str],
        normalized_diff_evidence_digest: str,
        no_unrelated_feature_change: bool,
    ) -> PatchProvenance:
        """Verify a reviewed conflict resolution without claiming patch equivalence."""

        authorization = _require_digest(
            reviewer_authorization_digest, "reviewer authorization"
        )
        normalized_diff_digest = _require_digest(
            normalized_diff_evidence_digest, "normalized diff evidence"
        )
        source = self.inspect_commit(source_commit)
        candidate = self.inspect_commit(candidate_commit)
        tip = self.validate_commit_oid(candidate_tip)
        source_base = self.validate_commit_oid(source_base_commit)
        target_base = self.validate_commit_oid(target_base_commit)
        expected_merge_base = self.validate_commit_oid(expected_merge_base_commit)
        if source.identity.commit == candidate.identity.commit:
            raise GitInspectionError("a conflict resolution must use a distinct commit")
        self._require_single_parent_patch(source, "source")
        self._require_single_parent_patch(candidate, "candidate")
        if source.parents[0] != source_base or candidate.parents[0] != target_base:
            raise GitInspectionError("conflict-resolution base identity does not match")
        actual_merge_base = self.merge_base(source_base, target_base)
        if actual_merge_base != expected_merge_base:
            raise GitInspectionError("conflict-resolution merge base does not match")
        if not self.is_ancestor(candidate.identity.commit, tip):
            raise GitInspectionError("conflict-resolution commit is not in candidate history")
        allowed = _canonical_paths(allowed_paths)
        if candidate.touched_paths != allowed:
            raise GitInspectionError("conflict-resolution touched-path scope does not match")
        conflicts = _canonical_paths(conflict_paths)
        if not conflicts or not set(conflicts).issubset(candidate.touched_paths):
            raise GitInspectionError("conflict path inventory is missing or out of scope")
        if normalized_diff_digest != self.manual_conflict_evidence_digest(
            source.identity.commit,
            candidate.identity.commit,
            conflicts,
        ):
            raise GitInspectionError(
                "conflict-resolution normalized diff evidence does not match"
            )
        tests = _canonical_evidence_ids(focused_test_evidence_ids)
        if not tests:
            raise GitInspectionError("conflict resolution requires focused tests")
        if no_unrelated_feature_change is not True:
            raise GitInspectionError("conflict resolution contains unreviewed unrelated change")
        return PatchProvenance(
            mode="manual-conflict-resolution",
            source_commit=source.identity.commit,
            candidate_commit=candidate.identity.commit,
            candidate_tip=tip,
            stable_patch_id=None,
            source_tree_oid=source.tree_oid,
            source_tree_digest=source.tree_digest,
            source_diff_digest=source.diff_digest,
            candidate_tree_oid=candidate.tree_oid,
            candidate_tree_digest=candidate.tree_digest,
            candidate_diff_digest=candidate.diff_digest,
            touched_paths=allowed,
            merge_base_commit=expected_merge_base,
            source_base_commit=source_base,
            target_base_commit=target_base,
            conflict_paths=conflicts,
            normalized_diff_evidence_digest=normalized_diff_digest,
            reviewer_authorization_digest=authorization,
            focused_test_evidence_ids=tests,
            no_unrelated_feature_change=True,
        )

    def verify_branch_role(
        self,
        *,
        lane: str,
        candidate_build: str,
        candidate_commit: str,
        branch_base: str,
        authorized_lineage_commit: str | None,
        authenticated_predecessor_commit: str,
    ) -> BranchRoleEvidence:
        """Verify release/hotfix branch role from exact object graph evidence."""

        if lane not in {"routine-maintenance", "security-hotfix"}:
            raise GitInspectionError("release lane is not allowed")
        if not isinstance(candidate_build, str) or not _BUILD_RE.fullmatch(candidate_build):
            raise GitInspectionError("candidate build is not a canonical integer")
        candidate = self.validate_commit_oid(candidate_commit)
        base = self.validate_commit_oid(branch_base)
        predecessor = self.validate_commit_oid(authenticated_predecessor_commit)
        lineage = (
            self.validate_commit_oid(authorized_lineage_commit)
            if authorized_lineage_commit is not None
            else None
        )
        if not self.is_ancestor(base, candidate):
            raise GitInspectionError("candidate does not descend from the exact branch base")
        if not self.is_ancestor(predecessor, candidate):
            raise GitInspectionError("candidate forks from the authenticated predecessor")
        predecessor_merge_base = self.merge_base(predecessor, candidate)
        if predecessor_merge_base != predecessor:
            raise GitInspectionError("candidate predecessor merge base does not match")
        if lane == "routine-maintenance":
            if lineage is None or not self.is_first_parent_ancestor(base, lineage):
                raise GitInspectionError(
                    "routine candidate base is absent from the authorized development "
                    "first-parent lineage"
                )
            lineage_merge_base = self.merge_base(candidate, lineage)
            if lineage_merge_base != base:
                raise GitInspectionError(
                    "routine candidate did not branch from the exact authorized "
                    "development base"
                )
            branch_role = "routine-release-candidate"
            base_role = "canonical-development"
        else:
            if lineage is None:
                raise GitInspectionError(
                    "security hotfix lacks the authenticated protected main lineage"
                )
            if base != lineage:
                raise GitInspectionError(
                    "security hotfix is not based on the exact authenticated protected main tip"
                )
            if not self.is_ancestor(predecessor, lineage):
                raise GitInspectionError(
                    "authenticated protected main does not contain the published predecessor"
                )
            if self.merge_base(predecessor, lineage) != predecessor:
                raise GitInspectionError(
                    "authenticated protected main predecessor merge base does not match"
                )
            branch_role = "security-hotfix-candidate"
            base_role = "authenticated-published-main"
        return BranchRoleEvidence(
            lane=lane,
            candidate_build=candidate_build,
            candidate_commit=candidate,
            branch_base=base,
            authorized_lineage_commit=lineage,
            authenticated_predecessor_commit=predecessor,
            predecessor_merge_base=predecessor_merge_base,
            branch_role=branch_role,
            base_role=base_role,
            no_fork=True,
        )

    def verify_project_build_version(
        self,
        candidate_commit: str,
        expected_build: str,
    ) -> bool:
        """Bind the candidate commit's checked-in integer Gradle version."""

        candidate = self.validate_commit_oid(candidate_commit)
        if not isinstance(expected_build, str) or not _BUILD_RE.fullmatch(
            expected_build
        ):
            raise GitInspectionError("expected project build is not a canonical integer")
        raw_tree_row = self._run(
            ("ls-tree", "-z", candidate, "--", "build.gradle.kts")
        )
        rows = [row for row in raw_tree_row.split(b"\0") if row]
        if len(rows) != 1:
            raise GitInspectionError(
                "candidate does not contain one exact build.gradle.kts blob"
            )
        try:
            metadata, raw_path = rows[0].split(b"\t", 1)
            mode, object_type, raw_oid = metadata.split(b" ", 2)
        except ValueError as exc:
            raise GitInspectionError("candidate project-version tree row is malformed") from exc
        if (
            mode != b"100644"
            or object_type != b"blob"
            or _safe_git_path(raw_path) != "build.gradle.kts"
        ):
            raise GitInspectionError("candidate project-version blob is not canonical")
        blob_oid = _decode_git_text(raw_oid, "project-version object ID")
        self._validate_object_id(blob_oid, "blob")
        source = _decode_git_text(
            self._run(("cat-file", "blob", blob_oid)),
            "build.gradle.kts",
        )
        versions = re.findall(
            r'(?m)^version[ \t]*=[ \t]*"([1-9][0-9]*)"[ \t]*$',
            source,
        )
        if versions != [expected_build]:
            raise GitInspectionError(
                "candidate project version does not match the release-train build"
            )
        return True

    def verify_no_fork(
        self,
        latest_pointer_commit: str,
        supplied_predecessor_commit: str,
        candidate_commit: str,
    ) -> bool:
        """Require the authenticated latest pointer as the immediate release predecessor."""

        latest = self.validate_commit_oid(latest_pointer_commit)
        supplied = self.validate_commit_oid(supplied_predecessor_commit)
        candidate = self.validate_commit_oid(candidate_commit)
        if supplied != latest:
            raise GitInspectionError("supplied predecessor is not the latest authenticated pointer")
        if not self.is_ancestor(latest, candidate):
            raise GitInspectionError("candidate creates a parallel Stable publication fork")
        if self.merge_base(latest, candidate) != latest:
            raise GitInspectionError("candidate does not preserve the predecessor chain")
        return True

    def candidate_commits(self, predecessor_commit: str, candidate_commit: str) -> tuple[str, ...]:
        """Return the bounded deterministic candidate coverage range."""

        predecessor = self.validate_commit_oid(predecessor_commit)
        candidate = self.validate_commit_oid(candidate_commit)
        if not self.is_ancestor(predecessor, candidate):
            raise GitInspectionError("candidate coverage range forks from its predecessor")
        rows = [
            line
            for line in self._run_text(
                (
                    "rev-list",
                    "--reverse",
                    "--topo-order",
                    candidate,
                    f"^{predecessor}",
                    "--",
                )
            ).splitlines()
            if line
        ]
        if len(rows) > _MAX_CANDIDATE_COMMITS:
            raise GitInspectionError("candidate coverage range exceeds the policy bound")
        return tuple(self.validate_commit_oid(row) for row in rows)

    def merge_resolution_paths(self, merge_commit: str) -> tuple[str, ...]:
        """Return paths changed by a non-automatic merge result.

        Combined diffs omit a path when the merge result matches either parent,
        which can hide a conflict resolution that discards the other parent's
        work.  This method first reproduces Git's automatic merge tree.  A merge
        is context-only only when that exact tree matches the recorded merge;
        otherwise the result is the union of paths changed from every parent.
        """

        merge = self.inspect_commit(merge_commit)
        if len(merge.parents) != 2:
            raise GitInspectionError(
                "merge-resolution evidence requires an exact two-parent merge"
            )
        with tempfile.TemporaryDirectory(
            prefix="cryptad-stable-merge-tree-"
        ) as temporary_directory:
            temporary_root = Path(temporary_directory).resolve(strict=True)
            isolated_git_directory = temporary_root / "git"
            isolated_object_directory = temporary_root / "objects"
            _initialize_isolated_git_directory(
                isolated_git_directory, self._object_format
            )
            isolated_object_directory.mkdir()
            isolated_environment = {
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(
                    self._object_directory
                ),
                "GIT_DIR": str(isolated_git_directory),
                "GIT_OBJECT_DIRECTORY": str(isolated_object_directory),
            }
            automatic = self._run_result(
                (
                    "merge-tree",
                    "--write-tree",
                    "--no-messages",
                    merge.parents[0],
                    merge.parents[1],
                ),
                allowed_returncodes=(0, 1),
                environment_overrides=isolated_environment,
            )
            if automatic.returncode == 0:
                lines = automatic.stdout.splitlines()
                if len(lines) != 1:
                    raise GitInspectionError(
                        "automatic merge-tree identity is malformed"
                    )
                automatic_tree = self._validate_object_id(
                    _decode_git_text(
                        lines[0], "automatic merge-tree identity"
                    ),
                    "tree",
                    environment_overrides=isolated_environment,
                )
                if automatic_tree == merge.tree_oid:
                    return ()
        path_set: set[str] = set()
        for parent in merge.parents:
            raw = self._run(
                (
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "-z",
                    "-r",
                    parent,
                    merge.identity.commit,
                    "--",
                )
            )
            tokens = raw.split(b"\0")
            if tokens and tokens[-1] == b"":
                tokens.pop()
            path_set.update(_safe_git_path(token) for token in tokens)
        paths = tuple(sorted(path_set))
        if not paths:
            raise GitInspectionError(
                "non-automatic merge result lacks path-level resolution evidence"
            )
        if len(paths) > _MAX_PATH_COUNT:
            raise GitInspectionError(
                "merge-resolution path inventory exceeds the policy bound"
            )
        return paths

    def verify_no_ff_merge(
        self,
        *,
        merge_commit: str,
        first_parent: str,
        merged_tip: str,
        protected_ref: str,
        protected_tip: str,
        expected_protected_ref: str,
        workflow_attestation_digest: str,
    ) -> MergeEvidence:
        """Verify an exact two-parent no-fast-forward merge and protected attestation."""

        merge = self.inspect_commit(merge_commit)
        expected_first = self.validate_commit_oid(first_parent)
        expected_merged = self.validate_commit_oid(merged_tip)
        expected_tip = self.validate_commit_oid(protected_tip)
        self.inspect_commit(expected_tip)
        if (
            protected_ref != expected_protected_ref
            or protected_ref not in {"refs/heads/main", "refs/heads/develop"}
        ):
            raise GitInspectionError("reconciliation protected branch role does not match")
        if len(merge.parents) != 2:
            raise GitInspectionError("reconciliation commit is not a two-parent merge")
        if merge.parents != (expected_first, expected_merged):
            raise GitInspectionError("reconciliation merge parent identities do not match")
        if not self.is_ancestor(expected_merged, merge.identity.commit):
            raise GitInspectionError("reconciliation merge does not contain the merged tip")
        if not self.is_ancestor(merge.identity.commit, expected_tip):
            raise GitInspectionError(
                "reconciliation merge is not reachable from the protected branch tip"
            )
        if not self.is_first_parent_ancestor(
            merge.identity.commit, expected_tip
        ):
            raise GitInspectionError(
                "reconciliation merge is not on the protected branch first-parent chain"
            )
        attestation = self.reconciliation_attestation_digest(
            protected_ref=protected_ref,
            protected_tip=expected_tip,
            merge_commit=merge.identity.commit,
            first_parent=expected_first,
            merged_tip=expected_merged,
        )
        if workflow_attestation_digest != attestation:
            raise GitInspectionError(
                "reconciliation protected-workflow attestation is inconsistent"
            )
        evidence = MergeEvidence(
            merge_commit=merge.identity.commit,
            first_parent=expected_first,
            merged_tip=expected_merged,
            protected_ref=protected_ref,
            protected_tip=expected_tip,
            parent_count=2,
            graph_verified=True,
            workflow_attestation_digest=attestation,
        )
        resolution_paths = self.merge_resolution_paths(merge.identity.commit)
        if resolution_paths:
            raise NonAutomaticMergeResolutionError(evidence, resolution_paths)
        return evidence

    def reconciliation_attestation_digest(
        self,
        *,
        protected_ref: str,
        protected_tip: str,
        merge_commit: str,
        first_parent: str,
        merged_tip: str,
    ) -> str:
        """Digest the exact protected branch and merge graph attested by CI."""

        subject = {
            "firstParent": first_parent,
            "mergeCommit": merge_commit,
            "mergedTip": merged_tip,
            "protectedRef": protected_ref,
            "protectedTip": protected_tip,
            "repositoryIdentity": self._repository_identity,
        }
        canonical = json.dumps(
            subject,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"

    def _verify_repository_root(self) -> None:
        inside = self._run_text(("rev-parse", "--is-inside-work-tree")).strip()
        if inside != "true":
            raise GitInspectionError("repository root is not a Git work tree")
        top_level_text = self._run_text(("rev-parse", "--show-toplevel")).strip()
        try:
            top_level = Path(top_level_text).resolve(strict=True)
        except OSError as exc:
            raise GitInspectionError("Git top-level path is unavailable") from exc
        if top_level != self._root:
            raise GitInspectionError("repository root does not match the exact Git top level")

    def _verify_repository_storage(self) -> None:
        git_directory_text = self._run_text(("rev-parse", "--absolute-git-dir")).strip()
        try:
            git_directory = Path(git_directory_text).resolve(strict=True)
            expected = (self._root / ".git").resolve(strict=True)
        except OSError as exc:
            raise GitInspectionError("Git object database is unavailable") from exc
        if (
            git_directory != expected
            or not git_directory.is_dir()
            or (self._root / ".git").is_symlink()
        ):
            raise GitInspectionError("Git object database is not confined to the repository")
        for relative in (Path("info/grafts"), Path("objects/info/alternates")):
            target = git_directory / relative
            if target.exists() or target.is_symlink():
                raise GitInspectionError("Git object substitution metadata is not allowed")
        object_directory_path = git_directory / "objects"
        try:
            if object_directory_path.is_symlink():
                raise GitInspectionError(
                    "Git object database is not confined to the repository"
                )
            object_directory = object_directory_path.resolve(strict=True)
        except OSError as exc:
            raise GitInspectionError("Git object database is unavailable") from exc
        if (
            object_directory != object_directory_path
            or not object_directory.is_dir()
        ):
            raise GitInspectionError(
                "Git object database is not confined to the repository"
            )
        _verify_object_database_entries(object_directory)
        self._object_directory = object_directory

    def _validate_object_id(
        self,
        object_id: str,
        expected_type: str,
        *,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> str:
        expected_length = _OBJECT_LENGTHS[self._object_format]
        if (
            len(object_id) != expected_length
            or object_id.lower() != object_id
            or re.fullmatch(r"[0-9a-f]+", object_id) is None
        ):
            raise GitInspectionError("Git object ID is not canonical")
        actual_type = self._run_text(
            ("cat-file", "-t", "--", object_id),
            environment_overrides=environment_overrides,
        ).strip()
        if actual_type != expected_type:
            raise GitInspectionError("Git object type does not match")
        return object_id

    def _commit_diff_bytes(self, commit: str, parents: Sequence[str]) -> bytes:
        prefix = (
            "diff-tree",
            "--no-commit-id",
            "-r",
            "-p",
            "--binary",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--find-renames",
            "--find-copies",
            "--find-copies-harder",
        )
        if parents:
            return self._run((*prefix, parents[0], commit, "--"))
        return self._run((*prefix, "--root", commit, "--"))

    def _path_changes(self, commit: str, parents: Sequence[str]) -> tuple[PathChange, ...]:
        prefix = (
            "diff-tree",
            "--no-commit-id",
            "-r",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            "--find-copies-harder",
        )
        if parents:
            raw = self._run((*prefix, parents[0], commit, "--"))
        else:
            raw = self._run((*prefix, "--root", commit, "--"))
        tokens = raw.split(b"\0")
        if tokens and tokens[-1] == b"":
            tokens.pop()
        changes: list[PathChange] = []
        index = 0
        while index < len(tokens):
            status = _decode_git_text(tokens[index], "path status")
            index += 1
            if re.fullmatch(r"[ACDMRTUXB][0-9]{0,3}", status) is None:
                raise GitInspectionError("Git path status is malformed")
            if status.startswith(("R", "C")):
                if index + 1 >= len(tokens):
                    raise GitInspectionError("Git rename/copy evidence is truncated")
                old_path = _safe_git_path(tokens[index])
                new_path = _safe_git_path(tokens[index + 1])
                index += 2
            else:
                if index >= len(tokens):
                    raise GitInspectionError("Git path evidence is truncated")
                old_path = None
                new_path = _safe_git_path(tokens[index])
                index += 1
            changes.append(PathChange(status=status, old_path=old_path, new_path=new_path))
            if len(changes) > _MAX_PATH_COUNT:
                raise GitInspectionError("Git touched-path inventory exceeds the policy bound")
        return tuple(changes)

    def _require_single_parent_patch(
        self, commit: CommitInspection, label: str
    ) -> None:
        if len(commit.parents) != 1:
            raise GitInspectionError(f"{label} commit is not a non-merge patch commit")
        if commit.is_empty:
            raise GitInspectionError(f"{label} commit is empty")

    def _run_text(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> str:
        raw = self._run(
            arguments,
            input_bytes=input_bytes,
            environment_overrides=environment_overrides,
        )
        return _decode_git_text(raw, "Git command output")

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> bytes:
        return self._run_result(
            arguments,
            input_bytes=input_bytes,
            environment_overrides=environment_overrides,
        ).stdout

    def _run_result(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        allowed_returncodes: Sequence[int] = (0,),
        environment_overrides: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        if not arguments or not all(isinstance(argument, str) for argument in arguments):
            raise GitInspectionError("Git argument vector is invalid")
        command = (*_READ_ONLY_GIT_PREFIX, *arguments)
        environment = dict(self._environment)
        if environment_overrides is not None:
            allowed_overrides = {
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_DIR",
                "GIT_OBJECT_DIRECTORY",
            }
            if (
                set(environment_overrides) - allowed_overrides
                or not all(
                    isinstance(value, str) and value
                    for value in environment_overrides.values()
                )
            ):
                raise GitInspectionError(
                    "Git inspection environment override is invalid"
                )
            environment.update(environment_overrides)
        try:
            process = subprocess.Popen(
                command,
                cwd=self._root,
                env=environment,
                stdin=(
                    subprocess.PIPE
                    if input_bytes is not None
                    else subprocess.DEVNULL
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            stdout, stderr, returncode = _communicate_bounded(
                process,
                input_bytes=input_bytes,
                maximum_bytes=self._max_output_bytes,
                timeout_seconds=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitInspectionError("bounded Git inspection failed") from exc
        if returncode not in allowed_returncodes:
            raise GitInspectionError("Git evidence command rejected the supplied identity")
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        environment: dict[str, str] = {}
        for name in (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TMPDIR",
            "TMP",
            "TEMP",
        ):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        environment.update(
            {
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
            }
        )
        return environment


def _initialize_isolated_git_directory(
    git_directory: Path, object_format: str
) -> None:
    """Create minimal trusted repository metadata for merge-tree inspection."""

    if object_format not in _OBJECT_LENGTHS:
        raise GitInspectionError("Git object format is unsupported")
    (git_directory / "objects" / "info").mkdir(parents=True)
    (git_directory / "objects" / "pack").mkdir()
    (git_directory / "refs" / "heads").mkdir(parents=True)
    (git_directory / "HEAD").write_text(
        "ref: refs/heads/main\n", encoding="utf-8"
    )
    repository_format_version = "1" if object_format == "sha256" else "0"
    config = (
        "[core]\n"
        f"\trepositoryformatversion = {repository_format_version}\n"
        "\tfilemode = true\n"
        "\tbare = true\n"
        "\tlogallrefupdates = false\n"
    )
    if object_format == "sha256":
        config += "[extensions]\n\tobjectformat = sha256\n"
    (git_directory / "config").write_text(config, encoding="utf-8")


def _verify_object_database_entries(object_directory: Path) -> None:
    pending = [object_directory]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise GitInspectionError(
                            "Git object database is not confined to the repository"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif not entry.is_file(follow_symlinks=False):
                        raise GitInspectionError(
                            "Git object database contains an unsupported entry"
                        )
    except GitInspectionError:
        raise
    except OSError as exc:
        raise GitInspectionError("Git object database is unavailable") from exc


def _communicate_bounded(
    process: subprocess.Popen[bytes],
    *,
    input_bytes: bytes | None,
    maximum_bytes: int,
    timeout_seconds: int,
) -> tuple[bytes, bytes, int]:
    if process.stdout is None or process.stderr is None:
        _kill_process(process)
        raise GitInspectionError("bounded Git inspection failed")
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    failures: list[BaseException] = []
    failure_lock = threading.Lock()

    def fail(exc: BaseException) -> None:
        with failure_lock:
            failures.append(exc)
        _kill_process(process)

    def drain(stream: BinaryIO, output: bytearray) -> None:
        try:
            while True:
                chunk = stream.read(_GIT_OUTPUT_CHUNK_BYTES)
                if not chunk:
                    return
                if len(output) + len(chunk) > maximum_bytes:
                    overflow.set()
                    _kill_process(process)
                    return
                output.extend(chunk)
        except (OSError, ValueError) as exc:
            if not overflow.is_set():
                fail(exc)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def feed(stream: BinaryIO, content: bytes) -> None:
        try:
            remaining = memoryview(content)
            while remaining:
                written = stream.write(remaining)
                if written is None or written <= 0:
                    raise OSError("Git input pipe rejected bounded input")
                remaining = remaining[written:]
        except (BrokenPipeError, OSError, ValueError) as exc:
            if not overflow.is_set():
                fail(exc)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout),
            name="stable-backport-git-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr),
            name="stable-backport-git-stderr",
            daemon=True,
        ),
    ]
    if input_bytes is not None:
        if process.stdin is None:
            _kill_process(process)
            raise GitInspectionError("bounded Git inspection failed")
        threads.append(
            threading.Thread(
                target=feed,
                args=(process.stdin, input_bytes),
                name="stable-backport-git-stdin",
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _kill_process(process)
        process.wait()
        for thread in threads:
            thread.join()
        raise
    for thread in threads:
        thread.join()
    if overflow.is_set():
        raise GitInspectionError("Git command output exceeds the policy bound")
    if failures:
        raise GitInspectionError("bounded Git inspection failed") from failures[0]
    return bytes(stdout), bytes(stderr), returncode


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass


def _decode_git_text(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise GitInspectionError(f"{label} is not canonical UTF-8") from exc


def _safe_git_path(raw: bytes) -> str:
    path = _decode_git_text(raw, "Git path")
    if len(path) > _MAX_PATH_LENGTH:
        raise GitInspectionError("Git path exceeds the policy bound")
    pure = PurePosixPath(path)
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in path)
        or any(character in "<>`" for character in path)
    ):
        raise GitInspectionError("Git path is unsafe for release evidence")
    return path


def _canonical_paths(paths: Iterable[str]) -> tuple[str, ...]:
    try:
        rows = tuple(paths)
    except TypeError as exc:
        raise GitInspectionError("path inventory is not iterable") from exc
    if len(rows) > _MAX_PATH_COUNT:
        raise GitInspectionError("path inventory exceeds the policy bound")
    canonical = tuple(sorted({_safe_git_path(path.encode("utf-8")) for path in rows}))
    if len(canonical) != len(rows):
        raise GitInspectionError("path inventory is not unique")
    return canonical


def _canonical_evidence_ids(evidence_ids: Iterable[str]) -> tuple[str, ...]:
    try:
        rows = tuple(evidence_ids)
    except TypeError as exc:
        raise GitInspectionError("evidence inventory is not iterable") from exc
    if len(rows) > 128:
        raise GitInspectionError("evidence inventory exceeds the policy bound")
    for row in rows:
        if (
            not isinstance(row, str)
            or len(row) > 128
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", row) is None
        ):
            raise GitInspectionError("evidence identity is not canonical")
    canonical = tuple(sorted(set(rows)))
    if len(canonical) != len(rows):
        raise GitInspectionError("evidence inventory is not unique")
    return canonical


def _require_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise GitInspectionError(f"{label} digest is not canonical")
    return value


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()
