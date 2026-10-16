"""Per-provider original admission, with external responses substituted only at the API boundary."""
import copy
from contextlib import contextmanager
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from cryptad_certification import phase_12_ci as ci
from cryptad_certification import phase_12_classpaths as classpaths
from .test_active_source import windows_source_metadata
from .test_phase_12_ci import OriginalAPI, AS_OF, SHA, SOURCE, encoded, xml as _legacy_xml


RUNTIME = {"javaVersion": "25.0.4", "javaVendor": "temurin", "javaArch": "amd64",
           "filesystem": "ext4", "provider": "linux"}


@contextmanager
def without_unix_open_flags():
    """Exercise portable reads on the host with the Windows flag availability."""
    saved = {name: getattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK") if hasattr(os, name)}
    try:
        for name in saved:
            delattr(os, name)
        yield
    finally:
        for name, value in saved.items():
            setattr(os, name, value)


def xml(kind, module="."):
    raw = _legacy_xml(kind, module)
    if kind.startswith("spotbugs"):
        return raw.replace(b'<FindBugsSummary total_bugs="0" total_classes="1"/>',
            b'<FindBugsSummary total_bugs="0" total_classes="1"><PackageStats package="network.crypta" total_types="1">'
            b'<ClassStats class="network.crypta.Example"/></PackageStats></FindBugsSummary>')
    return raw


def errorprone_inputs():
    policy = {"enabled": True, "allErrorsAsWarnings": True, "disableAllChecks": False,
        "disableAllWarnings": False, "allSuggestionsAsWarnings": False, "allDisabledChecksAsWarnings": False,
        "disableWarningsInGeneratedCode": False, "ignoreUnknownCheckNames": False, "ignoreSuppressionAnnotations": False,
        "compilingTestOnlyCode": False, "excludedPaths": None, "checks": {}, "checkOptions": {}, "extraArgs": [],
        "compilerArgumentProviders": ["net.ltgt.gradle.errorprone.ErrorPronePlugin$ErrorProneCompilerArgumentProvider"],
        "forkJvmArgumentProviders": ["net.ltgt.gradle.errorprone.ErrorPronePlugin$ErrorProneJvmArgumentProvider"],
        "forkJvmArguments": [], "errorproneArgumentProviders": 0, "argumentFiles": []}
    return {"analyzerConfiguration": policy, "incremental": False, "classpath": [],
        "compilerArguments": ["-Xlint:deprecation", "-Xlint:unchecked", "-Xmaxwarns", "10000", "-Xmaxerrs", "10000"]}


class NativeAPI(OriginalAPI):
    def __init__(self):
        super().__init__()
        self.complete_reports()
        self.values = {}
        self.attested = set()
        jobs = self.responses["actions/runs/1/attempts/2/jobs?per_page=100"]
        linux = next(job for job in jobs["jobs"] if job["name"] == "build / build")
        for index, lane in enumerate(ci.LANES):
            job = copy.deepcopy(linux)
            if index:
                job.update(id=800 + index, name=ci.LANES[lane][3],
                           check_run_url=f"https://api.github.com/repos/{ci.REPOSITORY}/check-runs/{800 + index}")
                job["steps"] = [row for row in job["steps"] if row["name"] not in ci.CI_STEPS["build / build"]]
                job["steps"].append({"name": "Run native Java verification", "conclusion": "success"})
                jobs["jobs"].append(job)
                self.responses[f"actions/jobs/{job['id']}/logs"] = self.responses[f"actions/jobs/{linux['id']}/logs"]
                self.responses[f"check-runs/{job['id']}"] = {"id": job["id"], "head_sha": SHA,
                    "name": job["name"], "app": {"slug": "github-actions"}, "conclusion": "success", "output": {"annotations_count": 0}}
                self.responses[f"check-runs/{job['id']}/annotations?per_page=100"] = []
            rows = []
            source_counts = ci._v2_source_counts(ci.ROOT)
            for module, kind in ci._v2_rows():
                count = source_counts[module, kind]
                execution = {"outcome": "executed" if count else "no-source",
                    "startedAt": "2026-09-10T11:04:00Z", "completedAt": "2026-09-10T11:06:00Z",
                    "sourceFiles": count, "inputClasses": int(bool(count)) if not kind.startswith("errorprone") else 0,
                    "filtered": False, "analysisEnabled": kind.startswith("errorprone"),
                    "sourceCoverage": "matched",
                    "toolchain": {"javaVersion": "25.0.4+7-LTS", "javaVendor": "temurin", "javaArch": "arm64" if lane == "macos-arm64" else "amd64"}}
                reports = [ci._xml_facts_v2(xml(kind, module), kind, module, lane)] if count else []
                rows.append({"module": module, "kind": kind, "execution": execution,
                             "reportState": "observed" if count else "absent", "reports": reports})
            self.values[lane] = {**copy.deepcopy(self.report_value), "schemaVersion": 2, "sourceClass": "committed-source",
                "producerDigest": ci._producer_identity(),
                "lane": lane, "provider": {"os": ci.LANES[lane][0], "arch": ci.LANES[lane][1], "runner": ci.LANES[lane][2],
                    "ImageOS": {"linux-amd64": "ubuntu24", "macos-arm64": "macos26-arm64", "windows-amd64": "win25"}[lane],
                    "ImageVersion": "20261012.1.0"}, "runtime": {**RUNTIME, "javaArch": "arm64" if lane == "macos-arm64" else "amd64",
                    "provider": {"linux-amd64": "linux", "macos-arm64": "macos", "windows-amd64": "windows"}[lane]},
                "fullSelection": True, "rows": rows}
        jobs["total_count"] = len(jobs["jobs"])
        self.replace_native_reports()

    def replace_native_reports(self):
        artifacts = []
        self.attested = set()
        for index, (lane, value) in enumerate(self.values.items()):
            raw = encoded(value)
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                item = zipfile.ZipInfo(ci.REPORT_FILE)
                item.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(item, raw)
            data, artifact_id = content.getvalue(), 900 + index
            artifacts.append({"id": artifact_id, "name": f"phase-12-ci-reports-1-2-{lane}", "expired": False,
                "workflow_run": {"id": 1, "head_sha": SHA}, "created_at": "2026-09-10T11:10:13Z",
                "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()})
            self.responses[f"actions/artifacts/{artifact_id}/zip"] = data
            self.attested.add(raw)
        self.responses["actions/runs/1/artifacts?per_page=100"] = {"total_count": len(artifacts), "artifacts": artifacts}

    def attest(self, raw, run, workflow_source, signer):
        if raw not in self.attested:
            raise ValueError("external-attestation-mismatch")


class NativeCITests(unittest.TestCase):
    def setUp(self):
        self.api = NativeAPI()

    def test_private_collector_rejects_hardlinked_report_despite_complete_java_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / 'target.xml'
            target.write_bytes(xml('junit'))
            report = root / 'TEST-linked.xml'
            os.link(target, report)
            record = {'reportObservation': 'complete', 'reportFiles': [{
                'path': report.name, 'size': report.stat().st_size,
                'sha256': ci.digest(target.read_bytes())}]}
            self.assertEqual('matched', ci._private_report_roster(record, [report], root)[0])
            with self.assertRaises(ValueError):
                ci._read_report(report)

    def verify(self):
        with patch.object(ci, "_GitHub", return_value=self.api), patch.object(ci, "_source_clean", return_value=True):
            return ci.verify(encoded(self.api.selection), SOURCE, AS_OF, collect_original=True)

    def test_complete_original_graph_has_reachable_success_without_replacing_verifier(self):
        result = self.verify()
        self.assertEqual("executed-pass", result["ci"])
        self.assertEqual("complete", result["supportedPlatforms"])
        self.assertEqual([], result["blockers"])

    def test_missing_platform_cannot_be_replaced_by_linux(self):
        del self.api.values["macos-arm64"]
        self.api.replace_native_reports()
        result = self.verify()
        self.assertNotEqual("executed-pass", result["ci"])
        self.assertIn("original-ci-supported-platform-results-incomplete", result["blockers"])

    def test_reuse_filtered_absence_failed_and_future_execution_are_not_fresh_pass(self):
        for mutation in ("up-to-date", "from-cache", "skipped", "failed", "incomplete", "not-observed", "filtered", "future", "no-source"):
            self.api = NativeAPI()
            row = next(row for row in self.api.values["linux-amd64"]["rows"] if row["execution"]["sourceFiles"])
            task = row["execution"]
            if mutation == "filtered":
                task["filtered"] = True
            elif mutation == "future":
                task["completedAt"] = "2026-09-11T11:06:00Z"
            elif mutation == "no-source":
                task.update(outcome="no-source", sourceFiles=0, inputClasses=0)
                row.update(reports=[], reportState="absent")
            elif mutation == "not-observed":
                task.update(outcome=mutation, startedAt=None, completedAt=None)
            else:
                task["outcome"] = mutation
            self.api.replace_native_reports()
            with self.subTest(mutation=mutation):
                self.assertNotEqual("executed-pass", self.verify()["ci"])

    def test_report_clock_copied_after_task_does_not_prove_execution(self):
        for observed in ("2026-09-09T11:05:00Z", "2026-09-10T11:10:00Z"):
            row = next(row for row in self.api.values["linux-amd64"]["rows"] if row["reports"])
            row["reports"][0]["executedAt"] = observed
            self.api.replace_native_reports()
            self.assertIn("original-ci-report-execution-outside-selected-task", self.verify()["blockers"])

    def test_wrong_lane_architecture_attempt_and_source_substitutions_reject(self):
        for field, replacement in (("lane", "windows-amd64"), ("sourceTree", "f" * 40), ("runAttempt", 9),
                                   ("provider", {**self.api.values["linux-amd64"]["provider"], "arch": "ARM64"})):
            self.api = NativeAPI()
            self.api.values["linux-amd64"][field] = replacement
            self.api.replace_native_reports()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()

    def test_daemon_identity_cannot_substitute_for_missing_or_other_architecture_toolchain(self):
        for toolchain in (None, {"javaVersion": "25.0.4", "javaVendor": "temurin", "javaArch": "arm64"}):
            self.api = NativeAPI()
            row = next(row for row in self.api.values["linux-amd64"]["rows"] if row["execution"]["sourceFiles"])
            row["execution"]["toolchain"] = toolchain
            self.api.replace_native_reports()
            self.assertIn("original-ci-task-toolchain-unavailable-or-mismatched", self.verify()["blockers"])

    def test_invalid_exact_source_coverage_remains_blocking_despite_matching_counts(self):
        for coverage in ("invalid", "unavailable"):
            self.api = NativeAPI()
            row = next(row for row in self.api.values["linux-amd64"]["rows"] if row["execution"]["sourceFiles"])
            row["execution"]["sourceCoverage"] = coverage
            self.api.replace_native_reports()
            with self.subTest(coverage=coverage):
                self.assertIn("original-ci-exact-source-set-coverage-unproven", self.verify()["blockers"])

    def test_source_free_analyzer_cannot_accept_stale_classes_as_a_new_source_cohort(self):
        row = next(row for row in self.api.values["linux-amd64"]["rows"]
                   if row["kind"] == "spotbugs-main" and not row["execution"]["sourceFiles"])
        row["execution"].update(outcome="executed", inputClasses=1)
        row.update(reportState="observed", reports=[ci._xml_facts_v2(xml(row["kind"], row["module"]), row["kind"], row["module"], "linux-amd64")])
        self.api.replace_native_reports()

        self.assertIn("original-ci-source-free-stale-classes-observed", self.verify()["blockers"])

    def test_actual_sonar_failure_is_not_hidden_by_successful_no_token_build(self):
        self.api.responses[f"commits/{SHA}/check-runs?filter=latest&per_page=100"] = {
            "total_count": 1, "check_runs": [{"id": 1234, "name": "SonarCloud Code Analysis", "head_sha": SHA,
                "app": {"slug": "sonarqubecloud"}, "status": "completed", "conclusion": "failure",
                "started_at": "2026-09-10T11:00:00Z", "completed_at": "2026-09-10T11:08:00Z",
                "output": {"summary": "private-canary"}}]}

        result = self.verify()

        self.assertNotEqual("executed-pass", result["ci"])
        self.assertIn("original-sonarcloud-check-failed", result["blockers"])
        self.assertEqual("failure", result["externalAnalyzers"]["checks"][0]["conclusion"])
        self.assertNotIn("private-canary", json.dumps(result))

    def test_expected_paths_bind_module_source_set_generated_successor_and_kotlin_test_ownership(self):
        selected = (
            "src/main/java/network/crypta/node/Version.java",
            "src/test/java/network/crypta/RootTest.java",
            "src/test/kotlin/network/crypta/RootKotlinTest.kt",
            "interop-wire/src/main/java/network/crypta/node/Version.java",
            "platform-api/src/main/java/network/crypta/platform/api/Active.java",
            "platform-api/src/main/java/network/crypta/platform/api/.stversions/Tracked.java",
            "build-logic/src/test/kotlin/cryptad/RecorderTest.kt",
        )

        paths = ci._v2_source_paths(ci.ROOT, selected_paths=selected)

        self.assertEqual({"build/tmp/compileVersion/network/crypta/node/Version.java"}, paths[".", "errorprone-main"])
        self.assertEqual({"interop-wire/build/tmp/compileVersion/network/crypta/node/Version.java"}, paths["interop-wire", "spotbugs-main"])
        self.assertEqual(set(selected[1:3]), paths[".", "junit"])
        self.assertEqual({selected[1]}, paths[".", "errorprone-test"])
        self.assertEqual(set(selected[4:6]), paths["platform-api", "errorprone-main"])
        self.assertEqual({selected[6]}, paths["build-logic", "junit"])
        self.assertEqual(set(), paths["foundation-fs", "junit"])

    def test_private_source_coverage_rejects_same_count_substitutions_duplicates_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            expected = "platform-api/src/main/java/Expected.java"
            other_module = "platform-apphost/src/main/java/Other.java"
            for name in (expected, other_module):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"class Example {}")
            commitment = "sha256:" + hashlib.sha256(b"class Example {}").hexdigest()
            record = {"sourceFiles": [{"path": expected, "digest": commitment}]}
            self.assertEqual("matched", ci._private_source_coverage(record, {expected}, root, {}))
            record["sourceFiles"][0]["path"] = other_module
            self.assertEqual("invalid", ci._private_source_coverage(record, {expected}, root, {}))
            record["sourceFiles"] = [{"path": expected, "digest": commitment}] * 2
            self.assertEqual("invalid", ci._private_source_coverage(record, {expected}, root, {}))
            record["sourceFiles"] = [{"path": expected, "digest": commitment}]
            (root / expected).write_bytes(b"class Changed {}")
            self.assertEqual("invalid", ci._private_source_coverage(record, {expected}, root, {}))
            self.assertEqual("unavailable", ci._private_source_coverage(None, {expected}, root, {}))

    def test_errorprone_diagnostics_must_complete_with_exact_observed_source_count(self):
        complete = b'<errorproneReport compilerCompleted="true" diagnosticsComplete="true" sourceFiles="2"/>'
        self.assertTrue(ci._errorprone_completed(complete, 2))
        for raw in (complete.replace(b'diagnosticsComplete="true"', b'diagnosticsComplete="false"'),
                    complete.replace(b' diagnosticsComplete="true"', b''),
                    complete.replace(b'compilerCompleted="true"', b'compilerCompleted="false"'),
                    complete.replace(b'sourceFiles="2"', b'sourceFiles="1"')):
            with self.subTest(raw=raw):
                self.assertFalse(ci._errorprone_completed(raw, 2))

    def test_exact_platform_applicability_preserves_every_skip_and_rejects_new_names(self):
        case = next(iter(ci.PLATFORM_NA))
        raw = (f'<testsuite tests="1" errors="0" failures="0" skipped="1" timestamp="2026-09-10T11:05:00Z">'
               f'<testcase classname="{case[1]}" name="{case[2]}"><skipped message="private-canary"/></testcase></testsuite>').encode()
        facts = ci._xml_facts_v2(raw, "junit", case[0], "linux-amd64")
        self.assertEqual(1, facts["counts"]["skipped"])
        self.assertEqual({"platformNotApplicable": 1, "unownedSkipped": 0, "rules": [ci.PLATFORM_RULE_IDS[case]]}, facts["applicability"])
        self.assertNotIn("private-canary", json.dumps(facts))
        self.assertEqual(1, ci._xml_facts_v2(raw.replace(case[2].encode(), b"new-test()"), "junit", case[0], "linux-amd64")["applicability"]["unownedSkipped"])
        self.assertEqual(1, ci._xml_facts_v2(raw, "junit", case[0], "windows-amd64")["applicability"]["unownedSkipped"])

    def test_each_fixed_platform_branch_is_narrow_and_parameterized_method_identity_is_required(self):
        for case, lanes in ci.PLATFORM_NA.items():
            raw = (f'<testsuite tests="1" failures="0" errors="0" skipped="1" timestamp="2026-09-10T11:05:00Z">'
                   f'<testcase classname="{case[1]}" name="{case[2]}"><skipped/></testcase></testsuite>').encode()
            for lane in ci.LANES:
                with self.subTest(case=case, lane=lane):
                    facts = ci._xml_facts_v2(raw, "junit", case[0], lane)
                    self.assertEqual(1, facts["counts"]["skipped"])
                    self.assertEqual(int(lane in lanes), facts["applicability"]["platformNotApplicable"])
                    self.assertEqual(int(lane not in lanes), facts["applicability"]["unownedSkipped"])
        raw = (b'<testsuite tests="1" failures="0" errors="0" skipped="1" timestamp="2026-09-10T11:05:00Z">'
               b'<testcase classname="network.crypta.crypt.EncryptedRandomAccessBufferTest" name="[1] CHACHA_128">'
               b'<skipped/></testcase></testsuite>')
        self.assertEqual(1, ci._xml_facts_v2(raw, "junit", ".", "linux-amd64")["applicability"]["unownedSkipped"])

    def test_runtime_projection_never_exports_private_environment_text(self):
        private = {key: "private-canary" for key in ("javaVersion", "javaVendor", "javaArch", "filesystem", "provider")}
        self.assertIsNone(ci._runtime_projection(private))
        private["javaVersion"] = "25.0.4"
        self.assertNotIn("private-canary", json.dumps(ci._runtime_projection(private)))

    def test_duplicate_approved_platform_skip_cannot_expand_declared_scope(self):
        case = next(iter(ci.PLATFORM_NA))
        node = f'<testcase classname="{case[1]}" name="{case[2]}"><skipped/></testcase>'
        raw = ('<testsuite tests="2" errors="0" failures="0" skipped="2" timestamp="2026-09-10T11:05:00Z">'
               + node + node + '</testsuite>').encode()
        with self.assertRaises(ValueError):
            ci._xml_facts_v2(raw, "junit", case[0], "linux-amd64")

    def test_early_build_failure_has_safe_unavailable_observation_without_fabricated_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            # No commit is created and no contributor identity is changed. Source metadata is an
            # isolated external-boundary response, while retention and projection run unchanged.
            from cryptad_certification.active_source import SourceRoster
            selected = SourceRoster((), SHA, SOURCE["tree"], "committed-source")
            start = root / "start.json"
            start.write_bytes(encoded({"startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}))
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": ci.REPOSITORY, "GITHUB_JOB": "build",
                "GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "private-canary", "ImageVersion": "private-canary"}
            with patch.object(ci, "ROOT", root), patch("cryptad_certification.active_source.source_roster", return_value=selected), \
                 patch.object(ci, "_producer_identity", return_value="sha256:" + "c" * 64), patch.dict(os.environ, environment):
                result = ci.retain_reports_v2(root / "public", start, "linux-amd64")
            self.assertIsNone(result["runtime"])
            self.assertFalse(result["fullSelection"])
            self.assertTrue(all(row["execution"]["outcome"] == "not-observed" for row in result["rows"]))
            self.assertNotIn("private-canary", (root / "public" / ci.REPORT_FILE).read_text())
            self.assertEqual([ci.REPORT_FILE], [path.name for path in (root / "public").iterdir()])


class PrivateEvidenceBoundaryTests(unittest.TestCase):
    def test_windows_retention_reads_external_start_clock_without_unix_open_flags(self):
        from cryptad_certification.active_source import SourceRoster
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary).resolve()
            root = private / "checkout"
            root.mkdir()
            selected = SourceRoster((), SHA, SOURCE["tree"], "committed-source")
            start = private / "start.json"
            start.write_bytes(encoded({"startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}))
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": ci.REPOSITORY, "GITHUB_JOB": "build",
                "GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2",
                "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "ImageOS": "win2025", "ImageVersion": "20260910.1.0"}
            with patch.object(ci, "ROOT", root), patch("cryptad_certification.active_source.source_roster", return_value=selected), \
                 patch.object(ci, "_producer_identity", return_value="sha256:" + "c" * 64), \
                 patch.dict(os.environ, environment), without_unix_open_flags(), windows_source_metadata():
                result = ci.retain_reports_v2(private / "public", start, "windows-amd64")
            self.assertEqual("windows-amd64", result["lane"])
            self.assertEqual(211, len(result["rows"]))
            self.assertEqual(result, json.loads((private / "public" / ci.REPORT_FILE).read_bytes()))
            self.assertFalse(result["fullSelection"])

    def test_current_producer_identity_preserves_both_schema_digests_without_unix_open_flags(self):
        expected = {schema: ci._producer_identity(schema) for schema in (1, 2)}
        with without_unix_open_flags(), windows_source_metadata():
            for schema in (1, 2):
                with self.subTest(schema=schema):
                    self.assertEqual(expected[schema], ci._producer_identity(schema))

    def test_source_clean_uses_bounded_selected_source_and_rejects_exports_or_working_bytes(self):
        from cryptad_certification.active_source import SourceRoster
        for source_class in ("committed-source", "working-source", "source-export"):
            selected = SourceRoster((), SHA, SOURCE["tree"], source_class)
            with self.subTest(source_class=source_class), \
                 patch("cryptad_certification.active_source.source_roster", return_value=selected) as roster, \
                 patch.object(ci.subprocess, "run", side_effect=AssertionError("unbounded Git invocation")), \
                 patch.dict(os.environ, {"GIT_DIR": "private-canary", "GIT_WORK_TREE": "private-canary", "GIT_INDEX_FILE": "private-canary"}):
                self.assertEqual(source_class == "committed-source", ci._source_clean(SOURCE))
                roster.assert_called_once_with(ci.ROOT)
        with patch("cryptad_certification.active_source.source_roster", return_value=SourceRoster((), "0" * 40, SOURCE["tree"], "committed-source")), self.assertRaises(ValueError):
            ci._source_clean(SOURCE)

    def test_completed_report_roster_rejects_post_edits_copies_insertions_and_deletions(self):
        from cryptad_certification.active_source import SourceRoster
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "settings.gradle.kts").write_bytes((ci.ROOT / "settings.gradle.kts").read_bytes())
            source_path = "src/test/java/network/crypta/ExampleTest.java"
            class_path = "build/classes/java/test/network/crypta/ExampleTest.class"
            report_path = "build/test-results/test/TEST-example.xml"
            for path, raw in ((source_path, b"source"), (class_path, b"class"), (report_path, xml("junit"))):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            fingerprint = lambda path: {"path": path, "digest": ci.digest((root / path).read_bytes())}
            classes = [fingerprint(class_path)]
            report_raw = (root / report_path).read_bytes()
            record = {"taskPath": ":test", "outcome": "executed", "startedAt": 1789038240000,
                "completedAt": 1789038360000, "sourceFiles": [fingerprint(source_path)], "inputClasses": 1,
                "filtered": False, "errorProneEnabled": False, "toolchain": None,
                "inputs": {"testClasses": classes, "candidateClasses": classes},
                "reportObservation": "complete", "reportFiles": [{"path": report_path,
                    "sha256": ci.digest(report_raw), "size": len(report_raw)}]}
            private = root / "build/phase12/task-evidence.json"
            private.parent.mkdir(parents=True)
            private.write_bytes(encoded({"schemaVersion": 1, "kind": "phase-12-private-gradle-task-evidence",
                "generatedAt": 1789038360001, "runtime": {}, "requestedTasks": ["build", "errorproneReport"], "tasks": [record]}))
            start = root / "start.json"
            start.write_bytes(encoded({"startedAt": "2026-09-10T11:04:00Z"}))
            selected = SourceRoster((source_path,), SHA, SOURCE["tree"], "committed-source")
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": ci.REPOSITORY, "GITHUB_JOB": "build",
                "GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20261012.1.0"}
            inserted = root / "build/test-results/test/TEST-inserted.xml"
            edited = ci.ET.fromstring(report_raw)
            edited.remove(edited.find("testcase"))
            edited.set("tests", "0")
            edited_raw = ci.ET.tostring(edited)
            self.assertEqual(0, ci._xml_facts_v2(edited_raw, "junit", ".", "linux-amd64")["counts"]["tests"])
            mutations = {"original": report_raw, "post-edited": edited_raw,
                "copied-valid": report_raw.replace(b"11:05:00", b"11:05:01"), "deleted": None, "inserted": report_raw}
            for name, raw in mutations.items():
                inserted.unlink(missing_ok=True)
                (root / report_path).unlink(missing_ok=True)
                if raw is not None:
                    (root / report_path).write_bytes(raw)
                if name == "inserted":
                    inserted.write_bytes(report_raw)
                with self.subTest(mutation=name), patch.object(ci, "ROOT", root), \
                     patch("cryptad_certification.active_source.source_roster", return_value=selected), \
                     patch.object(ci, "_producer_identity", return_value="sha256:" + "c" * 64), \
                     patch.object(ci, "_v2_rows", return_value=[(".", "junit")]), patch.dict(os.environ, environment):
                    result = ci.retain_reports_v2(root / name, start, "linux-amd64")
                row = result["rows"][0]
                self.assertEqual("unavailable", row["execution"]["sourceCoverage"])
                self.assertEqual("observed" if name == "original" else "invalid", row["reportState"])
                self.assertNotIn(ci.digest(report_raw), (root / name / ci.REPORT_FILE).read_text())

    def test_spotbugs_requires_all_owning_classes_with_original_bytes_and_native_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            rows = []
            for name in ("Example.class", "Example$Nested.class"):
                path = "foundation-fs/build/classes/java/main/network/crypta/" + name
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(name.encode())
                rows.append({"path": path, "digest": ci.digest(name.encode())})
            record = {"inputClasses": 2, "inputs": {"ownedClasses": rows, "classes": rows}}
            self.assertEqual("unavailable", ci._private_spotbugs_coverage(record, "foundation-fs", "spotbugs-main", root, {}))
            self.assertEqual({"network.crypta.Example", "network.crypta.Example$Nested"},
                             ci._spotbugs_class_names(record, "foundation-fs", "spotbugs-main"))
            for actual in (rows[:1], rows + rows[:1], [{"path": "foreign/build/classes/java/main/Foreign.class", "digest": rows[0]["digest"]}]):
                record["inputs"]["classes"] = actual
                record["inputClasses"] = len(actual)
                self.assertEqual("invalid", ci._private_spotbugs_coverage(record, "foundation-fs", "spotbugs-main", root, {}))
            record["inputs"]["classes"], record["inputClasses"] = rows, 2
            (root / rows[0]["path"]).write_bytes(b"changed")
            self.assertEqual("invalid", ci._private_spotbugs_coverage(record, "foundation-fs", "spotbugs-main", root, {}))
        raw = xml("spotbugs-main")
        ci._xml_facts_v2(raw, "spotbugs-main", ".", "linux-amd64", expected_classes={"network.crypta.Example"})
        for changed in (raw.replace(b'total_classes="1"', b'total_classes="2"'),
                        raw.replace(b'total_types="1"', b'total_types="2"'),
                        raw.replace(b'<ClassStats class="network.crypta.Example"/>', b'<ClassStats class="network.crypta.Example"/>' * 2)):
            with self.assertRaises(ValueError):
                ci._xml_facts_v2(changed, "spotbugs-main", ".", "linux-amd64")
        with self.assertRaises(ValueError):
            ci._xml_facts_v2(raw, "spotbugs-main", ".", "linux-amd64", expected_classes={"foreign.Class"})

    def test_spotbugs_suppression_inputs_must_equal_the_reviewed_source_owned_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = "build-logic/spotbugs-exclude.xml"
            target = root / path
            target.parent.mkdir(parents=True)
            target.write_bytes(b"reviewed-filter")
            policy = {"effort": None, "reportLevel": None, "extraArgs": [], "jvmArgs": [], "pluginJarFiles": []}
            original = {"analyzerConfiguration": policy, "auxClasspath": [], "excludeFilter": [{"path": path, "digest": ci.digest(b"reviewed-filter")}],
                        **{name: [] for name in ("includeFilter", "baseline", "onlyAnalyze", "visitors", "omitVisitors", "chooseVisitors")}}
            self.assertEqual("unavailable", ci._private_analyzer_configuration({"inputs": original}, "spotbugs-main", root, {}))
            for classpath in (None, [{"path": "unobserved.jar", "kind": "file", "size": 0, "digest": ci.digest(b"")}]):
                changed = {**original, "auxClasspath": classpath}
                self.assertNotEqual("matched", ci._private_analyzer_configuration({"inputs": changed}, "spotbugs-main", root, {}))
            for name in ("includeFilter", "baseline", "onlyAnalyze", "visitors", "omitVisitors", "chooseVisitors", "excludeFilter"):
                changed = copy.deepcopy(original)
                changed[name] = [{"path": "private-canary", "digest": ci.digest(b"private-canary")}]
                with self.subTest(field=name):
                    self.assertEqual("invalid", ci._private_analyzer_configuration({"inputs": changed}, "spotbugs-main", root, {}))
            for name, value in (("extraArgs", ["-onlyAnalyze", "private-canary"]), ("jvmArgs", ["-Dfindbugs.private-canary=true"]),
                                ("pluginJarFiles", [{"path": "private-canary"}]), ("effort", "MIN"), ("reportLevel", "HIGH")):
                changed = copy.deepcopy(original)
                changed["analyzerConfiguration"][name] = value
                with self.subTest(field=name):
                    self.assertEqual("invalid", ci._private_analyzer_configuration({"inputs": changed}, "spotbugs-main", root, {}))
            target.write_bytes(b"post-edited-filter")
            self.assertEqual("invalid", ci._private_analyzer_configuration({"inputs": original}, "spotbugs-main", root, {}))

    def test_errorprone_disable_filters_arguments_and_providers_cannot_claim_full_analysis(self):
        original = errorprone_inputs()
        self.assertEqual("unavailable", ci._private_analyzer_configuration({"inputs": original}, "errorprone-main", ci.ROOT, {}))
        for classpath in (None, [{"path": "unobserved.jar", "kind": "file", "size": 0, "digest": ci.digest(b"")}]):
            changed = {**original, "classpath": classpath}
            self.assertNotEqual("matched", ci._private_analyzer_configuration({"inputs": changed}, "errorprone-main", ci.ROOT, {}))
        for name, value in (("enabled", False), ("disableAllChecks", True), ("disableAllWarnings", True),
                            ("disableWarningsInGeneratedCode", True), ("excludedPaths", ".*"),
                            ("checks", {"ReferenceEquality": "OFF"}), ("checkOptions", {"private-canary": "true"}),
                            ("extraArgs", ["-XepDisableAllChecks"]), ("errorproneArgumentProviders", 1),
                            ("argumentFiles", [{"path": "private-canary"}]), ("compilerArgumentProviders", []),
                            ("forkJvmArgumentProviders", ["private-canary"]), ("forkJvmArguments", ["-Dprivate-canary=true"]),
                            ("enabled", 1), ("errorproneArgumentProviders", False)):
            changed = copy.deepcopy(original)
            changed["analyzerConfiguration"][name] = value
            with self.subTest(field=name, value=value):
                self.assertEqual("invalid", ci._private_analyzer_configuration({"inputs": changed}, "errorprone-main", ci.ROOT, {}))
        for name, value in (("incremental", True), ("compilerArguments", original["compilerArguments"] + ["-XepDisableAllChecks"])):
            changed = {**original, name: value}
            self.assertEqual("invalid", ci._private_analyzer_configuration({"inputs": changed}, "errorprone-main", ci.ROOT, {}))

    def test_actual_repository_settings_with_raw_regex_accepts_the_fixed_module_cohort(self):
        ci._module_cohort(ci.ROOT)
        self.assertEqual({name.replace("/", ":") for name in ci.MODULES if name != "."},
                         ci._settings_modules((ci.ROOT / "settings.gradle.kts").read_text()))

    def test_raw_settings_strings_consume_three_four_and_five_quote_closing_runs(self):
        for quotes in (3, 4, 5):
            text = 'val pattern = """raw include("ignored") body' + '"' * quotes + '\ninclude("known")\n'
            with self.subTest(quotes=quotes):
                self.assertEqual({"known"}, ci._settings_modules(text))
                with self.assertRaises(ValueError):
                    ci._settings_modules(text + 'include(computedModules)')

    def test_plain_and_nested_includes_bind_the_entire_fixed_module_roster(self):
        names = [name.replace("/", ":") for name in ci.MODULES if name != "."]
        settings = "include(\n" + ",\n".join(json.dumps(name) for name in names) + ",\n)\nincludeBuild(\"build-logic\")\n"
        self.assertEqual(set(names), ci._settings_modules(settings))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "settings.gradle.kts"
            path.write_text(settings)
            ci._module_cohort(root)
            for extra in ('include("new-module")', 'include("apps:new-module")'):
                path.write_text(settings + extra)
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    ci._module_cohort(root)

    def test_computed_or_unknown_include_syntax_cannot_hide_a_module(self):
        prefix = 'includeBuild("build-logic")\n'
        for statement in ('include(modules)', 'include(*modules.toTypedArray())',
                          'include("known" + suffix)', 'includeFlat("known")',
                          'settings.include("known")', 'includeBuild(":build-logic")'):
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                ci._settings_modules(prefix + statement)
        self.assertEqual({"known", "apps:nested"}, ci._settings_modules(
            prefix + '/* include("ignored") */ include(":known", "apps:nested",)\n'
            + 'val example = "include(\\\"also-ignored\\\")"\n'))

    def test_debian_toolchain_runtime_suffix_is_vendor_owned_bounded_and_preserved(self):
        version = "25.0.4.1+1-1-deb13u1-Debian"
        raw = {"javaVersion": version, "javaVendor": "Debian", "javaArch": "x86_64"}
        projected = ci._toolchain_projection(raw)
        self.assertEqual({"javaVersion": version, "javaVendor": "debian", "javaArch": "amd64"}, projected)
        ci._toolchain_facts(projected)
        self.assertIsNone(ci._toolchain_projection({**raw, "javaVendor": "Eclipse Adoptium"}))
        for invalid in (version + "-private-canary", version.replace("deb13u1", "deb13uprivate-canary"),
                        version.replace("+1-1-", "+1--"), version.replace("Debian", "private-canary")):
            with self.subTest(version=invalid):
                self.assertIsNone(ci._toolchain_projection({**raw, "javaVersion": invalid}))

    def test_unexpected_observed_task_paths_are_outside_the_fixed_primary_cohort(self):
        self.assertTrue(ci._observed_task_cohort({":test": {}, ":platform-api:compileJava": {}, ":build-logic:test": {}}))
        for unexpected in (":new-module:compileJava", ":apps:new-module:test", ":build-logic:customCompile", ":customTest"):
            with self.subTest(path=unexpected):
                self.assertFalse(ci._observed_task_cohort({":test": {}, unexpected: {}}))

    def test_unexpected_private_task_is_exportable_without_its_name_or_full_selection_claim(self):
        from cryptad_certification.active_source import SourceRoster
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "settings.gradle.kts").write_bytes((ci.ROOT / "settings.gradle.kts").read_bytes())
            selected = SourceRoster((), SHA, SOURCE["tree"], "committed-source")
            start = root / "start.json"
            start.write_bytes(encoded({"startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}))
            private = root / "build/phase12/task-evidence.json"
            private.parent.mkdir(parents=True)
            private.write_bytes(encoded({"schemaVersion": 1, "kind": "phase-12-private-gradle-task-evidence",
                "generatedAt": 1, "runtime": {}, "requestedTasks": ["build", "errorproneReport"],
                "tasks": [{"taskPath": ":private-canary:compileJava", "outcome": "executed"}]}))
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": ci.REPOSITORY, "GITHUB_JOB": "build",
                "GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20261012.1.0"}
            with patch.object(ci, "ROOT", root), patch("cryptad_certification.active_source.source_roster", return_value=selected), \
                 patch.object(ci, "_producer_identity", return_value="sha256:" + "c" * 64), patch.dict(os.environ, environment):
                result = ci.retain_reports_v2(root / "public", start, "linux-amd64")
            self.assertFalse(result["fullSelection"])
            self.assertNotIn("private-canary", (root / "public" / ci.REPORT_FILE).read_text())

    def test_fixed_external_get_endpoint_uses_bounded_transport_without_credential_or_network_fixture(self):
        client = object.__new__(ci._GitHub)
        client.calls, client.environment = 0, {}
        calls = []
        def run(command, **options):
            calls.append((command, options))
            return b'{"total_count":0,"check_runs":[]}'
        endpoint = f"commits/{SHA}/check-runs?filter=latest&per_page=100"
        with patch.dict("sys.modules", {"bounded_process": SimpleNamespace(run=run)}):
            self.assertEqual({"total_count": 0, "check_runs": []}, client.get(endpoint))
            with self.assertRaises(ValueError):
                client.get(endpoint.replace("filter=latest", "filter=all"))
        self.assertEqual(1, len(calls))
        self.assertEqual("GET", calls[0][0][3])
        self.assertEqual(ci.MAX_JSON, calls[0][1]["output_limit"])

    def test_provider_image_family_cannot_substitute_for_another_native_lane(self):
        for lane, spec in ci.LANES.items():
            wrong_image = "win25" if lane != "windows-amd64" else "ubuntu24"
            provider = {"os": spec[0], "arch": spec[1], "runner": spec[2], "ImageOS": wrong_image,
                        "ImageVersion": "20261012.1.0"}
            with self.subTest(lane=lane), self.assertRaises(ValueError):
                ci._provider_facts(provider, lane)

    def test_report_budget_exhaustion_stops_reads_and_retains_fixed_invalid_observations(self):
        from cryptad_certification.active_source import SourceRoster
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = SourceRoster((), SHA, SOURCE["tree"], "committed-source")
            start = root / "start.json"
            start.write_bytes(encoded({"startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}))
            reports = [root / "one.xml", root / "two.xml"]
            for path in reports:
                path.write_bytes(b"private-canary")
            reads = []
            def read_report(path):
                reads.append(path)
                return xml("junit")
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": ci.REPOSITORY, "GITHUB_JOB": "build",
                "GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2",
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20261012.1.0"}
            with patch.object(ci, "ROOT", root), patch("cryptad_certification.active_source.source_roster", return_value=selected), \
                 patch.object(ci, "_producer_identity", return_value="sha256:" + "c" * 64), \
                 patch.object(ci, "_v2_rows", return_value=[(".", "junit"), (".", "spotbugs-main")]), \
                 patch.object(ci, "_report_paths", return_value=reports), patch.object(ci, "_read_report", side_effect=read_report), \
                 patch.object(ci, "MAX_REPORT_BYTES", 1), patch.dict(os.environ, environment):
                result = ci.retain_reports_v2(root / "public", start, "linux-amd64")
            self.assertEqual([reports[0]], reads)
            self.assertEqual(["invalid", "invalid"], [row["reportState"] for row in result["rows"]])
            self.assertNotIn("private-canary", (root / "public" / ci.REPORT_FILE).read_text())

    def test_utf16_dtd_reports_reject_with_and_without_bom(self):
        document = ('<?xml version="1.0"?><!DOCTYPE testsuite [<!ENTITY zero "0">]>'
                    '<testsuite tests="1" errors="&zero;" failures="0" skipped="0" timestamp="2026-09-10T11:05:00Z">'
                    '<testcase name="case"/></testsuite>')
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                ci._xml_facts(document.encode(encoding), "junit", ".")

    def test_report_directory_enumeration_is_bounded_before_materializing_the_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "build/test-results/test"
            directory.mkdir(parents=True)
            for name in ("TEST-a.xml", "TEST-b.xml", "TEST-c.xml"):
                (directory / name).write_text("unused")
            with patch.object(ci, "MAX_REPORTS", 2), self.assertRaises(ValueError):
                ci._report_paths(root, ".", "junit")

    def test_candidate_spec_narrowing_or_changed_class_bytes_cannot_match_full_test_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            names = ["build/classes/java/test/network/crypta/FirstTest.class",
                     "build/classes/java/test/network/crypta/sub/SecondTest.class",
                     "build/classes/java/test/network/crypta/FirstTest$NestedTest.class",
                     "build/classes/java/test/network/crypta/Helper.class"]
            rows = []
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"class-bytes")
                rows.append({"path": name, "digest": "sha256:" + hashlib.sha256(b"class-bytes").hexdigest()})
            record = {"inputClasses": 2, "inputs": {"testClasses": rows, "candidateClasses": rows[:2]}}
            self.assertEqual("unavailable", ci._private_test_coverage(record, ".", root, {}))
            record["inputs"]["candidateClasses"] = rows[:1]
            record["inputClasses"] = 1
            self.assertEqual("invalid", ci._private_test_coverage(record, ".", root, {}))
            record["inputs"]["candidateClasses"] = rows[:2]
            record["inputClasses"] = 2
            (root / names[0]).write_bytes(b"changed-class-bytes")
            self.assertEqual("invalid", ci._private_test_coverage(record, ".", root, {}))

    def test_included_build_default_candidates_require_every_observed_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            rows = []
            for name in ("ExampleTest.class", "ExampleTest$Helper.class"):
                relative = "build-logic/build/classes/kotlin/test/cryptad/" + name
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"class-bytes")
                rows.append({"path": relative, "digest": "sha256:" + hashlib.sha256(b"class-bytes").hexdigest()})
            record = {"inputClasses": 2, "inputs": {"testClasses": rows, "candidateClasses": rows}}
            self.assertEqual("unavailable", ci._private_test_coverage(record, "build-logic", root, {}))
            record["inputs"]["candidateClasses"] = rows[:1]
            record["inputClasses"] = 1
            self.assertEqual("invalid", ci._private_test_coverage(record, "build-logic", root, {}))

    def test_external_latest_check_list_requires_complete_unambiguous_source_and_clocks(self):
        check = {"id": 1234, "name": "SonarCloud Code Analysis", "head_sha": SHA,
                 "app": {"slug": "sonarqubecloud"}, "status": "completed", "conclusion": "failure",
                 "started_at": "2026-09-10T11:00:00Z", "completed_at": "2026-09-10T11:08:00Z"}
        evaluation = ci._time(AS_OF)
        mutations = [
            {"total_count": 101, "check_runs": []},
            {"total_count": 2, "check_runs": [check]},
            {"total_count": 2, "check_runs": [check, {**check, "id": 1235}]},
            {"total_count": 1, "check_runs": [{**check, "head_sha": "f" * 40}]},
            {"total_count": 1, "check_runs": [{**check, "completed_at": "2026-09-11T11:08:00Z"}]},
            {"total_count": 1, "check_runs": [{**check, "app": {"slug": "untrusted"}}]},
        ]
        for value in mutations:
            client = SimpleNamespace(get=lambda suffix: value)
            facts, gaps = ci._external_checks(client, SOURCE, evaluation)
            self.assertEqual("unavailable", facts["state"])
            self.assertTrue(gaps)

    def test_successful_codeql_checks_are_observations_without_invented_workflow_authority(self):
        value = {"total_count": 1, "check_runs": [{"id": 1234, "name": "Analyze (python)", "head_sha": SHA,
            "app": {"slug": "github-actions"}, "status": "completed", "conclusion": "success",
            "started_at": "2026-09-10T11:00:00Z", "completed_at": "2026-09-10T11:08:00Z"}]}
        requested = []
        def get(suffix):
            requested.append(suffix)
            return value
        facts, gaps = ci._external_checks(SimpleNamespace(get=get), SOURCE, ci._time(AS_OF))
        self.assertEqual([f"commits/{SHA}/check-runs?filter=latest&per_page=100"], requested)
        self.assertEqual([], gaps)
        self.assertEqual("unverified", facts["checks"][0]["disposition"])
        self.assertEqual("original-check-only", facts["checks"][0]["provenance"])


class ClasspathEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "repo"
        self.root.mkdir()
        self.source = self.write("sample/src/test/java/network/crypta/ExampleTest.java", b"reviewed-source")
        self.resource = self.write("sample/src/test/resources/config.properties", b"reviewed-resource")
        self.classes = self.root / "sample/build/classes/java/test"
        self.class_file = self.write("sample/build/classes/java/test/network/crypta/ExampleTest.class", b"compiled-source")
        self.resources = self.root / "sample/build/resources/test"
        self.resource_file = self.write("sample/build/resources/test/config.properties", b"reviewed-resource")
        self.dependency = self.root.parent / "cache/modules-2/files-2.1/fixture/dependency/1/hash/dependency.jar"
        self.dependency.parent.mkdir(parents=True)
        self.dependency.write_bytes(b"verified-dependency")
        self.metadata = self.write("gradle/verification-metadata.xml", (
            '<verification-metadata><components><component group="fixture" name="dependency" version="1">'
            '<artifact name="dependency.jar"><sha256 value="' + hashlib.sha256(self.dependency.read_bytes()).hexdigest() +
            '"/></artifact></component></components></verification-metadata>').encode())
        self.compiler = self.producer(":sample:compileTestJava", "java-compile", [self.source], self.classes)
        self.compiler["inputs"]["classpath"] = []
        self.copier = self.producer(":sample:processTestResources", "resources", [self.resource], self.resources)
        self.record = {"taskPath": ":sample:test", "startedAt": 3, "inputClasses": 1, "inputs": {
            "testClasses": [self.file(self.class_file)], "candidateClasses": [self.file(self.class_file)],
            "classpath": [self.snapshot(self.classes), self.snapshot(self.resources), self.file(self.dependency)]}}
        self.producers = [self.compiler, self.copier]
        expected = ["project:sample/build/classes/java/test", "project:sample/build/resources/test",
                    "module:fixture:dependency:1:dependency.jar"]
        self.rosters = {":sample:test": {"classpath": expected.copy()},
                        ":sample:compileJava": {"classpath": expected.copy()},
                        ":sample:compileTestJava": {"classpath": []},
                        ":sample:spotbugsTest": {"auxClasspath": expected.copy()}}
        self.authority = self.write(classpaths.ROSTER, b"")
        self.write_roster()

    def write_roster(self, configuration=None):
        self.authority.write_text(json.dumps({"schemaVersion": 1, "kind": "phase-12-reviewed-classpaths",
            "configuration": configuration or {}, "tasks": self.rosters}))

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def name(self, path):
        return path.relative_to(self.root).as_posix() if path.is_relative_to(self.root) else str(path)

    def file(self, path):
        raw = path.read_bytes()
        return {"path": self.name(path), "kind": "file", "size": len(raw), "digest": ci.digest(raw)}

    def snapshot(self, path):
        return {"path": self.name(path), "kind": "directory", "files": [
            self.file(p) for p in sorted(path.rglob("*")) if p.is_file()]}

    def producer(self, task, kind, sources, output):
        return {"taskPath": task, "startedAt": 1, "completedAt": 2, "outcome": "executed",
                "outputObservation": "complete", "sourceFiles": [self.file(p) for p in sources],
                "inputs": {"kind": kind}, "producedOutputs": [self.snapshot(output)]}

    def context(self):
        return ci._classpath_context(self.producers,
            {("sample", "errorprone-test"): {self.name(self.source)}},
            [self.name(p) for p in (self.source, self.resource, self.metadata, self.authority)])

    def coverage(self, record=None, field="classpath"):
        return ci._private_classpath_coverage(record or self.record, field, self.root, {}, self.context())

    def test_complete_runtime_classpath_requires_fresh_sources_resources_and_verified_jars(self):
        self.assertEqual("matched", self.coverage())
        self.assertEqual("matched", ci._private_test_coverage(self.record, "sample", self.root, {}, self.context()))
        omitted = copy.deepcopy(self.record)
        omitted["inputs"]["classpath"] = omitted["inputs"]["classpath"][1:]
        self.assertEqual("invalid", ci._private_test_coverage(omitted, "sample", self.root, {}, self.context()))

    def test_analyzed_classes_require_their_own_fresh_compiler_outputs(self):
        rows = [self.file(self.class_file)]
        record = {"startedAt": 3, "inputClasses": 1, "inputs": {"ownedClasses": rows, "classes": rows}}
        self.assertEqual("matched", ci._private_spotbugs_coverage(record, "sample", "spotbugs-test", self.root, {}, self.context()))
        self.compiler["outcome"] = "from-cache"
        self.assertEqual("unavailable", ci._private_spotbugs_coverage(record, "sample", "spotbugs-test", self.root, {}, self.context()))

    def test_project_outputs_cannot_be_relabelled_under_another_source_set(self):
        self.compiler["taskPath"] = ":sample:compileJava"
        self.assertEqual("invalid", self.coverage())

    def test_generated_java_needs_an_authenticated_generator(self):
        generated = self.write("sample/build/generated/Generated.java", b"class Generated {}")
        self.compiler["sourceFiles"] = [self.file(generated)]
        context = self.context()
        context["sources"]["sample", "errorprone-test"] = {self.name(generated)}
        self.assertEqual("unavailable", ci._private_classpath_coverage(self.record, "classpath", self.root, {}, context))

    def test_pgp_dependency_verification_obeys_reviewed_scopes_and_checks_captured_bytes(self):
        fingerprint = "A" * 40
        self.metadata.write_text('<verification-metadata><configuration><trusted-keys><trusted-key id="' + fingerprint +
            '" group="fixture" name="dependency" version="1"/></trusted-keys></configuration></verification-metadata>')
        keyring = self.write("gradle/verification-keyring.gpg", b"fixture-public-keyring")
        cached = self.root.parent / "cache/modules-2/files-2.1/fixture/dependency/1/hash/dependency.jar"
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(b"signed-artifact-bytes")
        signature = cached.parent.parent / "signature/dependency.jar.asc"
        signature.parent.mkdir()
        signature.write_bytes(b"fixture-signature")
        context = ci._classpath_context([], {}, [self.name(self.metadata), self.name(keyring)])
        status = ("[GNUPG:] VALIDSIG " + fingerprint + " 2026-01-01 1 0 4 0 1 8 00 " + fingerprint + "\n").encode()
        def verify(command, **_):
            self.assertEqual(b"signed-artifact-bytes", Path(command[-1]).read_bytes())
            self.assertEqual(b"fixture-signature", Path(command[-2]).read_bytes())
            return SimpleNamespace(returncode=0, stdout=status)
        with patch.object(ci.shutil, "which", return_value="gpgv"), patch.object(ci.subprocess, "run", side_effect=verify):
            self.assertEqual("matched", ci._verified_dependency({}, cached, cached.read_bytes(), self.root, context))
        wrong = ci._classpath_context([], {}, [self.name(self.metadata), self.name(keyring)])
        with patch.object(ci.shutil, "which", return_value="gpgv"), patch.object(ci.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"BAD SIGNATURE")):
            self.assertEqual("invalid", ci._verified_dependency({}, cached, cached.read_bytes(), self.root, wrong))
        missing = ci._classpath_context([], {}, [self.name(self.metadata), self.name(keyring)])
        with patch.object(ci.shutil, "which", return_value=None):
            self.assertEqual("unavailable", ci._verified_dependency({}, cached, cached.read_bytes(), self.root, missing))
        missing_key = ci._classpath_context([], {}, [self.name(self.metadata), self.name(keyring)])
        with patch.object(ci.shutil, "which", return_value="gpgv"), patch.object(ci.subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout=b"[GNUPG:] NO_PUBKEY ABCD\n")):
            for _ in range(2):
                self.assertEqual("unavailable", ci._verified_dependency({}, cached, cached.read_bytes(), self.root, missing_key))

    def test_changed_main_test_resource_or_dependency_bytes_are_invalid(self):
        for path in (self.class_file, self.resource_file, self.dependency):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(b"unreviewed-execution-input")
                self.assertEqual("invalid", self.coverage())
                path.write_bytes(original)
        injected = self.write("sample/build/resources/test/unlisted.txt", b"injected")
        self.assertEqual("invalid", self.coverage())
        injected.unlink()
        self.resource_file.unlink()
        self.assertEqual("invalid", self.coverage())

    def test_recaptured_modified_dependency_cannot_replace_the_reviewed_verification_digest(self):
        self.dependency.write_bytes(b"changed-before-execution")
        self.record["inputs"]["classpath"][-1] = self.file(self.dependency)
        self.assertEqual("invalid", self.coverage())

    def test_reused_failed_late_or_wrong_source_project_outputs_cannot_match(self):
        for outcome in ("up-to-date", "from-cache", "skipped", "failed", "no-source"):
            with self.subTest(outcome=outcome):
                self.compiler["outcome"] = outcome
                self.assertNotEqual("matched", self.coverage())
        self.compiler["outcome"] = "executed"
        self.compiler["completedAt"] = 4
        self.assertEqual("unavailable", self.coverage())
        self.compiler["completedAt"] = 2
        self.compiler["sourceFiles"] = []
        self.assertEqual("invalid", self.coverage())

    def test_missing_unsupported_and_malformed_classpaths_never_match(self):
        for value in (None, [{"path": "../outside", "kind": "directory", "files": []}],
                      self.record["inputs"]["classpath"] * 2):
            changed = copy.deepcopy(self.record)
            changed["inputs"]["classpath"] = value
            self.assertNotEqual("matched", self.coverage(changed))
        self.producers = []
        self.assertEqual("unavailable", self.coverage())

    def test_compiler_and_spotbugs_classpaths_use_the_same_origin_and_byte_validation(self):
        for field in ("classpath", "auxClasspath"):
            task = ":sample:compileJava" if field == "classpath" else ":sample:spotbugsTest"
            record = {"taskPath": task, "startedAt": 3, "inputs": {field: copy.deepcopy(self.record["inputs"]["classpath"])}}
            self.assertEqual("matched", self.coverage(record, field))
            self.resource_file.write_bytes(b"stale-processed-resource")
            self.assertEqual("invalid", self.coverage(record, field))
            self.resource_file.write_bytes(b"reviewed-resource")

    def test_project_jar_inputs_must_chain_to_fresh_producer_outputs(self):
        jar = self.write("sample/build/libs/sample.jar", b"fresh-project-archive")
        producer = {"taskPath": ":sample:jar", "startedAt": 3, "completedAt": 4, "outcome": "executed",
                    "outputObservation": "complete", "sourceFiles": [self.file(self.class_file), self.file(self.resource_file)],
                    "inputs": {"kind": "jar"}, "producedOutputs": [self.file(jar)]}
        self.producers.append(producer)
        self.rosters[":sample:test"] = {"classpath": ["project:sample/build/libs/sample.jar"]}
        self.write_roster()
        record = {"taskPath": ":sample:test", "startedAt": 5, "inputs": {"classpath": [self.file(jar)]}}
        self.assertEqual("matched", self.coverage(record))
        self.copier["outcome"] = "up-to-date"
        self.assertEqual("unavailable", self.coverage(record))

    def test_empty_removed_reordered_or_added_approved_entries_cannot_match(self):
        extra = self.root.parent / "cache/modules-2/files-2.1/fixture/extra/1/hash/extra.jar"
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b"also-approved")
        component = ('<component group="fixture" name="extra" version="1"><artifact name="extra.jar">'
                     '<sha256 value="' + hashlib.sha256(extra.read_bytes()).hexdigest() + '"/></artifact></component>')
        self.metadata.write_text(self.metadata.read_text().replace('</components>', component + '</components>'))
        self.assertEqual("matched", ci._verified_dependency({}, extra, extra.read_bytes(), self.root, self.context()))
        original = self.record["inputs"]["classpath"]
        for field, task in (("classpath", ":sample:test"), ("classpath", ":sample:compileJava"),
                            ("auxClasspath", ":sample:spotbugsTest")):
            for changed in ([], original[:-1], original[1:], list(reversed(original)),
                            original + [self.file(extra)], original + original[:1]):
                with self.subTest(field=field, task=task, entries=len(changed)):
                    record = {"taskPath": task, "startedAt": 3, "inputs": {field: changed, "expectedClasspath": changed}}
                    self.assertEqual("invalid", self.coverage(record, field))

    def test_empty_classpath_requires_an_explicit_reviewed_empty_roster(self):
        self.assertEqual("matched", self.coverage(self.compiler))
        self.assertEqual("unavailable", ci._private_classpath_coverage(self.compiler, "classpath", self.root, {}))
        self.compiler["taskPath"] = ":sample:unknown"
        self.assertEqual("unavailable", self.coverage(self.compiler))

    def test_analyzer_configuration_consumers_require_the_reviewed_ordered_membership(self):
        filter_path = "build-logic/spotbugs-exclude-test.xml"
        self.write(filter_path, b"reviewed-filter")
        spotbugs = {"analyzerConfiguration": {"effort": None, "reportLevel": None,
                    "extraArgs": [], "jvmArgs": [], "pluginJarFiles": []},
                    "excludeFilter": [{"path": filter_path, "digest": ci.digest(b"reviewed-filter")}],
                    **{name: [] for name in ("includeFilter", "baseline", "onlyAnalyze", "visitors", "omitVisitors", "chooseVisitors")}}
        for kind, task, field, inputs in (("errorprone-main", ":sample:compileJava", "classpath", errorprone_inputs()),
                                          ("spotbugs-test", ":sample:spotbugsTest", "auxClasspath", spotbugs)):
            original = self.record["inputs"]["classpath"]
            for entries, status in ((original, "matched"), ([], "invalid"), (list(reversed(original)), "invalid")):
                with self.subTest(kind=kind, expected=status):
                    record = {"taskPath": task, "startedAt": 3, "inputs": {**inputs, field: entries}}
                    self.assertEqual(status, ci._private_analyzer_configuration(record, kind, self.root, {}, self.context()))

    def test_missing_unselected_or_stale_authority_cannot_grant_coverage(self):
        context = self.context()
        context["selected"].remove(classpaths.ROSTER)
        self.assertEqual("unavailable", ci._private_classpath_coverage(self.record, "classpath", self.root, {}, context))
        script = self.write("build.gradle.kts", b"dependencies {}")
        self.write_roster({"build.gradle.kts": ci.digest(script.read_bytes())})
        context = self.context()
        context["selected"].add("build.gradle.kts")
        self.assertEqual("matched", ci._private_classpath_coverage(self.record, "classpath", self.root, {}, context))
        script.write_bytes(b"dependencies { altered() }")
        context = self.context()
        context["selected"].add("build.gradle.kts")
        self.assertEqual("unavailable", ci._private_classpath_coverage(self.record, "classpath", self.root, {}, context))
        self.authority.unlink()
        self.assertEqual("unavailable", self.coverage())

    def test_private_observation_cannot_replace_committed_authority(self):
        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=self.root, stderr=subprocess.PIPE, text=True).strip()
        git("init", "--quiet")
        git("config", "user.name", "Source fixture")
        git("config", "user.email", "fixture@example.invalid")
        git("add", "--", self.name(self.source), self.name(self.resource), self.name(self.metadata), classpaths.ROSTER)
        git("commit", "--quiet", "-m", "fixture: reviewed classpaths")
        commit = git("rev-parse", "HEAD")
        context = self.context()
        context["sourceCommit"] = commit
        self.assertEqual("matched", ci._private_classpath_coverage(self.record, "classpath", self.root, {}, context))
        self.rosters[":sample:test"]["classpath"] = []
        self.write_roster()
        record = {"taskPath": ":sample:test", "inputs": {"classpath": [], "expectedClasspath": []}}
        context = self.context()
        context["sourceCommit"] = commit
        self.assertEqual("invalid", ci._private_classpath_coverage(record, "classpath", self.root, {}, context))

    def test_duplicate_authority_entries_are_invalid_and_unknown_profiles_are_unavailable(self):
        self.rosters[":sample:test"]["classpath"] *= 2
        self.write_roster()
        self.assertEqual("invalid", self.coverage())
        self.rosters[":sample:test"]["classpath"] = None
        self.write_roster()
        self.assertEqual("unavailable", self.coverage())

    def version_fixture(self):
        template_name = "interop-wire/src/main/java/network/crypta/node/Version.java"
        script_names = ["build.gradle.kts", "interop-wire/build.gradle.kts"]
        paths = [self.write(name, (ci.ROOT / name).read_bytes()) for name in script_names + [template_name]]
        self.rosters[":interop-wire:compileJava"] = {"classpath": []}
        self.rosters[":interop-wire:test"] = {"classpath": ["project:interop-wire/build/classes/java/main"]}
        selected = [self.name(p) for p in (self.source, self.resource, self.metadata, self.authority, *paths)]
        self.write_roster({name: ci.digest((self.root / name).read_bytes())
                           for name in classpaths.configuration_paths(selected)})
        def git(*args):
            return subprocess.run(["git", "-c", "user.name=Source fixture", "-c",
                "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
                cwd=self.root, check=True, capture_output=True, timeout=15).stdout.decode().strip()
        git("init", "--quiet")
        git("add", "--", *selected)
        git("commit", "--quiet", "-m", "fixture: version source authority")
        commit = git("rev-parse", "HEAD")
        version = ci.re.findall(rb'(?m)^version = "([0-9]+)"$', (self.root / "build.gradle.kts").read_bytes())[0]
        raw = (self.root / template_name).read_bytes().replace(b"@build_number@", version).replace(b"@git_rev@", commit[:10].encode())
        generated = self.write("interop-wire/build/tmp/compileVersion/network/crypta/node/Version.java", raw)
        record = {"taskPath": ":interop-wire:compileJava", "outcome": "executed",
                  "sourceFiles": [self.file(generated)], "inputs": {"kind": "java-compile", "classpath": []}}
        context = ci._classpath_context([], {("interop-wire", "errorprone-main"): {self.name(generated)}}, selected, commit)
        return generated, raw, record, context

    def test_generated_version_is_authenticated_from_committed_template_and_properties(self):
        generated, raw, record, context = self.version_fixture()
        classes = self.root / "interop-wire/build/classes/java/main"
        self.write("interop-wire/build/classes/java/main/network/crypta/node/Version.class", b"compiled-version")
        record.update(startedAt=1, completedAt=2, outputObservation="complete", producedOutputs=[self.snapshot(classes)])
        context = ci._classpath_context([record], context["sources"], context["selected"], context["sourceCommit"])
        consumer = {"taskPath": ":interop-wire:test", "startedAt": 3, "inputs": {"classpath": [self.snapshot(classes)]}}
        for output in (raw, raw.replace(b"\n", b"\r\n")):
            generated.write_bytes(output)
            record["sourceFiles"] = [self.file(generated)]
            self.assertEqual("matched", ci._classpath_producer_inputs(record, self.root, {}, context))
            expected = {self.name(generated)}
            self.assertEqual("matched", ci._private_compiler_sources(record, expected, self.root, {}, context))
            context["status"].clear()
            self.assertEqual("matched", ci._private_classpath_coverage(consumer, "classpath", self.root, {}, context))

    def test_generated_version_cannot_authenticate_tampering_or_unbound_inputs(self):
        generated, raw, record, context = self.version_fixture()
        mutations = [raw + b"// injected source\n", raw.replace(b'GIT_REVISION = "', b'GIT_REVISION = "f'),
                     raw.replace(b'BUILD_NUMBER_STRING = "', b'BUILD_NUMBER_STRING = "9')]
        for output in mutations:
            with self.subTest(mutation=mutations.index(output)):
                generated.write_bytes(output)
                record["sourceFiles"] = [self.file(generated)]
                self.assertEqual("invalid", ci._classpath_producer_inputs(record, self.root, {}, context))
        generated.write_bytes(raw)
        record["sourceFiles"] = [self.file(generated)]
        template = self.root / "interop-wire/src/main/java/network/crypta/node/Version.java"
        template.write_bytes(template.read_bytes() + b"// uncommitted template\n")
        self.assertEqual("invalid", ci._classpath_producer_inputs(record, self.root, {}, context))
        context["sourceCommit"] = None
        self.assertEqual("unavailable", ci._classpath_producer_inputs(record, self.root, {}, context))
        context["sources"][("interop-wire", "errorprone-main")].add("interop-wire/build/generated/Other.java")
        self.assertEqual("unavailable", ci._classpath_producer_inputs(record, self.root, {}, context))

    def test_checked_in_roster_includes_bootstrap_compiler_and_test_classpaths(self):
        value = classpaths._validate(ci.parse((ci.ROOT / classpaths.ROSTER).read_bytes()))
        for task in ("compileJava", "compileTestJava", "compileKotlin", "compileTestKotlin", "test"):
            with self.subTest(task=task):
                self.assertIsInstance(value["tasks"][":build-logic:" + task]["classpath"], list)

    def test_bootstrap_classpath_membership_is_explicit_and_preserves_gradle_artifact_boundaries(self):
        entries = ["project:build-logic/build/classes/kotlin/test", "gradle-generated:9.7.1:gradle-api-9.7.1.jar",
                   "gradle:9.7.1:lib/groovy-4.0.28.jar"]
        paths = ["build-logic/build/classes/kotlin/test",
                 str(self.root.parent / "cache/caches/9.7.1/generated-gradle-jars/gradle-api-9.7.1.jar"),
                 str(self.root.parent / "wrapper/dists/gradle-9.7.1-bin/hash/gradle-9.7.1/lib/groovy-4.0.28.jar")]
        self.rosters[":build-logic:test"] = {"classpath": entries}
        self.write_roster()
        record = {"taskPath": ":build-logic:test"}
        actual = [{"path": path} for path in paths]
        self.assertEqual("matched", classpaths.membership(record, "classpath", actual, self.root, self.context()))
        for changed in ([], actual[:-1], list(reversed(actual)), actual + actual[:1]):
            self.assertEqual("invalid", classpaths.membership(record, "classpath", changed, self.root, self.context()))
        # Membership alone grants no artifact-byte/provenance exemption.
        metadata = self.write("build-logic/gradle/verification-metadata.xml", self.metadata.read_bytes())
        context = self.context()
        context["selected"].add(self.name(metadata))
        self.assertEqual("unavailable", ci._verified_dependency(record, Path(paths[1]), b"unverified", self.root, context))

    def test_cache_location_changes_preserve_coordinates_without_admitting_wrong_artifacts(self):
        relative = "modules-2/files-2.1/fixture/dependency/1/other-hash/dependency.jar"
        relocated = self.root.parent / "different-home" / relative
        self.assertEqual("module:fixture:dependency:1:dependency.jar",
                         classpaths.classpath_identity(self.root, str(relocated)))
        self.assertIsNone(classpaths.classpath_identity(self.root, str(self.root / "../outside.jar")))


if __name__ == "__main__":
    unittest.main()
