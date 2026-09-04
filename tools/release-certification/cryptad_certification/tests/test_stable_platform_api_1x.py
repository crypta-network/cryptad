"""Focused tests for Platform API 1.x compatibility operations."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptad_certification.cli import build_parser
from cryptad_certification.engines import stable_platform_api_1x as api1x
from cryptad_certification.io import read_json, write_json
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.tests.support import workspace_root


ZERO = api1x.ZERO_DIGEST
SOURCE = "a" * 40


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _binding(path: Path) -> dict[str, object]:
    return {"fileName": path.name, "digest": _digest(path), "size": path.stat().st_size}


def _seal(value: dict[str, object], field: str) -> None:
    value[field] = api1x._semantic_digest(value, field)


class Api1xFixture:
    """Create a deterministic fixture-only complete authority input."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir()
        self.snapshot22 = self._snapshot(22)
        self.snapshot23 = self._snapshot(23)
        self.baseline_registry = self._baseline_registry()
        self.previous_deprecation, self.deprecation = self._deprecation()
        self.previous_history, self.history = self._history()
        self.history_subjects, history_errors = api1x._history_snapshot_subjects(
            self.ledger_value, self.evidence
        )
        if history_errors:
            raise AssertionError(history_errors)
        self.app_subject_inventory = self._app_subject_inventory()
        self.matrix = self._matrix()
        self.contract = self._contract()
        self.contract_path = root / "execution.json"
        write_json(self.contract_path, self.contract)

    def _snapshot(self, version: int) -> Path:
        path = self.evidence / f"contract-{version}.json"
        snapshot = read_json(
            workspace_root()
            / "docs/platform-api/contracts/platform-api-1.0-baseline.json"
        )
        snapshot["contract"]["contractVersion"] = version
        snapshot["contract"]["compatibilityWindow"]["currentContractVersion"] = version
        write_json(path, snapshot)
        return path

    def _baseline_registry(self) -> dict[str, object]:
        contract = read_json(self.snapshot23)["contract"]
        endpoint_descriptors = {
            f"{endpoint['method']} {endpoint['routeTemplate']}": endpoint
            for endpoint in contract["endpoints"]
        }
        definition: dict[str, object] = {
            "id": "1.0",
            "predecessorId": None,
            "capabilities": contract["stableBaseline"]["capabilities"],
            "endpoints": [
                api1x._snapshot_endpoint_semantics(endpoint_descriptors[identity])
                for identity in contract["stableBaseline"]["endpoints"]
            ],
            "sourceArtifactDigest": api1x.FROZEN_1_0_ARTIFACT_DIGEST,
            "proposalDigest": None,
            "reviewDigest": None,
            "documentationDigest": None,
            "firstCompleteContractVersion": 19,
            "definitionDigest": "0" * 64,
        }
        definition["definitionDigest"] = api1x._baseline_definition_digest(definition)
        if definition["definitionDigest"] != api1x.FROZEN_1_0_DEFINITION_DIGEST:
            raise AssertionError("fixture does not project the exact frozen 1.0 definition")
        lineage: dict[str, object] = {
            "id": "1.0",
            "definitionDigest": definition["definitionDigest"],
            "status": "active",
            "evidenceKind": "imported-frozen-baseline",
            "evidenceDigest": api1x.FROZEN_1_0_ARTIFACT_DIGEST,
            "activationRelease": None,
            "activationBuild": None,
            "supportStartedRelease": None,
            "supportEndedRelease": None,
            "previousLineageDigest": None,
            "lineageDigest": "0" * 64,
        }
        lineage["lineageDigest"] = api1x._baseline_lineage_digest(lineage)
        if lineage["lineageDigest"] != api1x.FROZEN_1_0_LINEAGE_DIGEST:
            raise AssertionError("fixture does not import the exact frozen 1.0 lineage")
        registry: dict[str, object] = {
            "schemaVersion": 1,
            "definitions": [definition],
            "lineage": [lineage],
            "registryDigest": "0" * 64,
        }
        registry["registryDigest"] = api1x._baseline_registry_digest(registry)
        path = self.evidence / "baseline-registry.json"
        self.baseline_registry_value = {"baselineRegistry": registry}
        write_json(path, self.baseline_registry_value)
        previous_path = self.evidence / "previous-baseline-registry.json"
        write_json(previous_path, self.baseline_registry_value)
        self.previous_baseline_registry = _binding(previous_path)
        return _binding(path)

    def _record(
        self,
        version: int,
        snapshot: Path,
        predecessor: str | None,
        status: str,
        deprecation_digest: str,
    ) -> dict[str, object]:
        return {
            "recordId": f"fixture-{'import' if predecessor is None else 'release'}-{version}",
            "releaseId": f"fixture-release-{version}",
            "buildVersion": version,
            "sourceCommit": SOURCE,
            "sourceRef": "refs/heads/fixture-platform-api-1x",
            "releaseRootDigest": "sha256:" + ("1" if version == 23 else "8") * 64,
            "urlApiVersion": "v1",
            "contractVersion": version,
            "contractSnapshot": _binding(snapshot),
            "baselineRegistryDigest": api1x._record_baseline_registry_digest(
                self.baseline_registry_value
            ),
            "compatibilityWindowDigest": api1x._digest_bytes(
                api1x._canonical_bytes(read_json(snapshot)["contract"]["compatibilityWindow"])
            ),
            "deprecationLedgerDigest": deprecation_digest,
            "appMatrixDigest": None,
            "predecessorRecordDigest": predecessor,
            "provenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
                "workflowCommit": SOURCE,
                "runId": 1,
                "runAttempt": 1,
                "artifactName": "fixture-history",
                "artifactDigest": "sha256:" + "5" * 64,
                "environment": "stable-1-0-platform-api-1x-fixture",
                "conclusion": "success",
            },
            "generatedAt": f"2026-0{'8-31' if version == 22 else '9-01'}T00:00:00Z",
            "publishedAt": None,
            "recordStatus": status,
            "fixtureOnly": True,
            "selfDigest": ZERO,
        }

    def _history(self) -> tuple[dict[str, object], dict[str, object]]:
        imported = self._record(
            22,
            self.snapshot22,
            None,
            "imported",
            self.previous_deprecation_value["ledgerDigest"],
        )
        _seal(imported, "selfDigest")
        previous: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-history-ledger",
            "repositoryIdentity": "github.com/crypta-network/cryptad",
            "records": [imported],
            "oldestSupportedRecordDigest": imported["selfDigest"],
            "headRecordDigest": imported["selfDigest"],
            "ledgerDigest": ZERO,
        }
        _seal(previous, "ledgerDigest")
        previous_path = self.evidence / "previous-history.json"
        write_json(previous_path, previous)
        successor = self._record(
            23,
            self.snapshot23,
            imported["selfDigest"],
            "candidate",
            self.deprecation_value["ledgerDigest"],
        )
        _seal(successor, "selfDigest")
        ledger = copy.deepcopy(previous)
        ledger["records"].append(successor)
        ledger["headRecordDigest"] = successor["selfDigest"]
        _seal(ledger, "ledgerDigest")
        self.previous_ledger_value = previous
        self.ledger_value = ledger
        path = self.evidence / "history.json"
        write_json(path, ledger)
        return _binding(previous_path), _binding(path)

    def _deprecation(self) -> tuple[dict[str, object], dict[str, object]]:
        previous: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-deprecation-ledger",
            "entries": [],
            "predecessorLedgerDigest": None,
            "ledgerDigest": ZERO,
        }
        _seal(previous, "ledgerDigest")
        previous_path = self.evidence / "previous-deprecations.json"
        write_json(previous_path, previous)
        ledger = copy.deepcopy(previous)
        ledger["predecessorLedgerDigest"] = previous["ledgerDigest"]
        _seal(ledger, "ledgerDigest")
        path = self.evidence / "deprecations.json"
        write_json(path, ledger)
        self.previous_deprecation_value = previous
        self.deprecation_value = ledger
        return _binding(previous_path), _binding(path)

    def _matrix(self) -> dict[str, object]:
        matrix: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-app-compatibility-matrix",
            "releaseId": "fixture-release-23",
            "sourceCommit": SOURCE,
            "staticOnly": True,
            "requiredAppIds": ["fixture-app"],
            "rows": [
                {
                    "appId": "fixture-app",
                    "appVersion": "1.0.0",
                    "bundleDigest": "sha256:" + "6" * 64,
                    "manifestDigest": "sha256:" + "7" * 64,
                    "publisherId": None,
                    "catalogId": None,
                    "reviewDigest": None,
                    "targetStability": "stable",
                    "targetBaseline": "1.0",
                    "minimumContractVersion": 19,
                    "maximumTestedContractVersion": 23,
                    "requiredCapabilities": [],
                    "optionalCapabilities": [],
                    "experimentalCapabilitiesAccepted": False,
                    "sourceAuthority": "fixture",
                    "fixtureOnly": True,
                    "requiredForRelease": True,
                    "evaluations": [
                        {
                            "releaseRole": "candidate",
                            "releaseId": "fixture-release-23",
                            "contractVersion": 23,
                            "baselineId": "1.0",
                            "verdict": "compatible",
                            "staticVerified": True,
                            "runtimeObserved": False,
                            "findingCodes": [],
                        }
                    ],
                }
            ],
            "appSubjectsDigest": ZERO,
            "matrixDigest": ZERO,
        }
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")
        self.matrix_value = matrix
        path = self.evidence / "matrix.json"
        write_json(path, matrix)
        return _binding(path)

    def _app_subject_inventory(self) -> dict[str, object]:
        row = {
            "appId": "fixture-app",
            "appVersion": "1.0.0",
            "bundleDigest": "sha256:" + "6" * 64,
            "manifestDigest": "sha256:" + "7" * 64,
            "publisherId": None,
            "catalogId": None,
            "reviewDigest": None,
            "targetStability": "stable",
            "targetBaseline": "1.0",
            "minimumContractVersion": 19,
            "maximumTestedContractVersion": 23,
            "requiredCapabilities": [],
            "optionalCapabilities": [],
            "experimentalCapabilitiesAccepted": False,
            "sourceAuthority": "fixture",
            "sourceAuthorityRoot": None,
            "sourceEvidenceDigest": None,
            "fixtureOnly": True,
            "requiredForRelease": True,
            "subjectDigest": ZERO,
        }
        _seal(row, "subjectDigest")
        inventory: dict[str, object] = {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-app-subject-inventory",
            "releaseId": "fixture-release-23",
            "sourceCommit": SOURCE,
            "authorityRoots": {name: ZERO for name in api1x.AUTHORITY_SCHEMAS},
            "requiredAppIds": ["fixture-app"],
            "subjects": [row],
            "fixtureOnly": True,
            "inventoryDigest": ZERO,
        }
        _seal(inventory, "inventoryDigest")
        self.app_subject_inventory_value = inventory
        path = self.evidence / "app-subject-inventory.json"
        write_json(path, inventory)
        return _binding(path)

    def _contract(self) -> dict[str, object]:
        policy = workspace_root() / "tools/release-certification" / api1x.POLICY_FILE
        empty_authority = {
            "summaryDigest": ZERO,
            "artifactDigest": ZERO,
            "operational": False,
            "provenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
                "workflowCommit": SOURCE,
                "runId": 1,
                "runAttempt": 1,
                "artifactName": "fixture-authority",
                "artifactDigest": ZERO,
                "environment": "stable-1-0-platform-api-1x-fixture",
                "conclusion": "success"
            },
            "summary": None,
        }
        names = tuple(api1x.AUTHORITY_SCHEMAS)
        return {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-compatibility-execution",
            "executionId": "fixture-platform-api-1x",
            "repository": {
                "identity": "github.com/crypta-network/cryptad",
                "sourceCommit": SOURCE,
                "sourceRef": "refs/heads/fixture-platform-api-1x",
            },
            "release": {
                "releaseId": "fixture-release-23",
                "buildVersion": 23,
                "releaseRootDigest": "sha256:" + "1" * 64,
            },
            "evaluationTime": "2026-09-01T00:02:00Z",
            "requestedState": "fixture-verification-complete",
            "fixtureOnly": True,
            "selfTest": True,
            "policyDigest": _digest(policy),
            "urlApiVersion": "v1",
            "contractVersion": 23,
            "activeStableBaselines": ["1.0"],
            "previousHistoryAuthority": None,
            "supportLifecycleAuthority": None,
            "runtimeObservationAuthority": None,
            "authorityRoots": {name: ZERO for name in names},
            "authorities": {name: copy.deepcopy(empty_authority) for name in names},
            "evidence": {
                "historyLedger": self.history,
                "previousHistoryLedger": self.previous_history,
                "previousBaselineRegistry": self.previous_baseline_registry,
                "selectedRcFreeze": None,
                "baselineRegistry": self.baseline_registry,
                "baselineProposal": None,
                "graduationRecords": [],
                "deprecationLedger": self.deprecation,
                "previousDeprecationLedger": self.previous_deprecation,
                "appSubjectInventory": self.app_subject_inventory,
                "appMatrix": self.matrix,
                "runtimeObservation": None,
                "supportLifecycleDescriptor": None,
            },
        }

    def rewrite_contract(self) -> None:
        write_json(self.contract_path, self.contract)


class StablePlatformApi1xTest(unittest.TestCase):
    """Covers history, lifecycle, matrix, and fixture trust boundaries."""

    def setUp(self) -> None:
        build = workspace_root() / "build"
        build.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=build)
        self.root = Path(self.temporary.name)
        self.fixture = Api1xFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _registry_with_future_baseline(
        self, status: str, evidence_kind: str
    ) -> dict[str, object]:
        envelope = copy.deepcopy(self.fixture.baseline_registry_value)
        registry = envelope["baselineRegistry"]
        frozen = registry["definitions"][0]
        future: dict[str, object] = {
            "id": "1.1",
            "predecessorId": "1.0",
            "capabilities": sorted([*frozen["capabilities"], "future.read"]),
            "endpoints": sorted(
                [
                    *copy.deepcopy(frozen["endpoints"]),
                    {
                        "id": "GET /future",
                        "routeFamily": "future",
                        "actionLabel": "future.read",
                        "requiredCapabilities": ["future.read"],
                        "hostOperatorBypassAllowed": False,
                        "appProcessPrincipalsAllowed": True,
                        "appBrowserPrincipalsAllowed": True,
                    },
                ],
                key=lambda endpoint: endpoint["id"],
            ),
            "sourceArtifactDigest": "2" * 64,
            "proposalDigest": "3" * 64,
            "reviewDigest": None,
            "documentationDigest": None,
            "firstCompleteContractVersion": 24,
            "definitionDigest": "0" * 64,
        }
        future["definitionDigest"] = api1x._baseline_definition_digest(future)
        lineage: dict[str, object] = {
            "id": "1.1",
            "definitionDigest": future["definitionDigest"],
            "status": status,
            "evidenceKind": evidence_kind,
            "evidenceDigest": "4" * 64,
            "activationRelease": None,
            "activationBuild": None,
            "supportStartedRelease": None,
            "supportEndedRelease": None,
            "previousLineageDigest": None,
            "lineageDigest": "0" * 64,
        }
        lineage["lineageDigest"] = api1x._baseline_lineage_digest(lineage)
        registry["definitions"].append(future)
        registry["lineage"].append(lineage)
        registry["registryDigest"] = api1x._baseline_registry_digest(registry)
        return envelope

    def test_parser_whenCommandSelected_expectAllClosedModes(self) -> None:
        parser = build_parser()
        for mode in api1x.MODES:
            parsed = parser.parse_args([
                "stable-platform-api-1x", "--mode", mode,
                "--execution-contract", str(self.fixture.contract_path),
            ])
            self.assertEqual(mode, parsed.mode)

    def test_contracts_whenLoaded_expectClosedSchemasAndExactPolicyDigest(self) -> None:
        schemas = workspace_root() / "tools/release-certification/schemas"
        for name in (
            api1x.EXECUTION_SCHEMA, api1x.SNAPSHOT_SCHEMA, api1x.BASELINE_REGISTRY_SCHEMA,
            api1x.HISTORY_SCHEMA,
            api1x.PROPOSAL_SCHEMA,
            api1x.GRADUATION_SCHEMA, api1x.DEPRECATION_SCHEMA,
            api1x.APP_SUBJECT_INVENTORY_SCHEMA, api1x.MATRIX_SCHEMA,
            api1x.RUNTIME_SCHEMA, api1x.SUMMARY_SCHEMA,
        ):
            with self.subTest(schema=name):
                value = json.loads((schemas / name).read_text(encoding="utf-8"))
                self.assertFalse(value["additionalProperties"])
                self.assertEqual("https://json-schema.org/draft/2020-12/schema", value["$schema"])
        example = read_json(
            workspace_root()
            / "tools/release-certification/manifests/platform-api-1.x-compatibility.example.json"
        )
        self.assertEqual([], validate_schema(example, api1x.EXECUTION_SCHEMA))
        policy = workspace_root() / "tools/release-certification" / api1x.POLICY_FILE
        self.assertEqual(_digest(policy), example["policyDigest"])

    def test_checkedInSnapshots_whenValidated_expectRealEnvelopeShapeAccepted(self) -> None:
        contracts = workspace_root() / "docs/platform-api/contracts"

        for name in (
            "platform-api-1.0-baseline.json",
            "previous-production-beta-contract.json",
        ):
            with self.subTest(snapshot=name):
                snapshot = read_json(contracts / name)
                self.assertEqual(
                    [], validate_schema(snapshot, api1x.SNAPSHOT_SCHEMA)
                )
                self.assertEqual([], api1x.scan_value(snapshot))

    def test_closeout_whenFixtureEvidenceValid_expectFixtureOnlyCompletion(self) -> None:
        output = self.root / "out"

        result = api1x.run(
            workspace_root(), self.fixture.contract_path, "closeout", output, self.fixture.evidence
        )

        self.assertEqual(0, result)
        summary = read_json(output / api1x.SUMMARY_FILE)
        self.assertEqual("fixture-verification-complete", summary["state"])
        self.assertFalse(summary["operational"])
        self.assertEqual(
            api1x._record_baseline_registry_digest(
                self.fixture.baseline_registry_value
            ),
            summary["baselineRegistryDigest"],
        )
        self.assertEqual(
            self.fixture.baseline_registry["digest"],
            summary["baselineRegistryArtifactDigest"],
        )
        self.assertNotEqual(ZERO, summary["summaryDigest"])

    def test_preflight_whenFixtureRequestsOperationalState_expectBlocked(self) -> None:
        self.fixture.contract["requestedState"] = "operational-1x-compatibility-complete"
        self.fixture.rewrite_contract()

        result = api1x.run(
            workspace_root(), self.fixture.contract_path, "preflight", self.root / "out", None
        )

        self.assertEqual(1, result)
        summary = read_json(self.root / "out" / api1x.SUMMARY_FILE)
        self.assertEqual("blocked", summary["state"])
        self.assertFalse(summary["operational"])

    def test_history_whenContractVersionReusedWithChangedSnapshot_expectFinding(self) -> None:
        ledger = read_json(self.fixture.evidence / "history.json")
        predecessor = ledger["records"][-1]
        changed = copy.deepcopy(predecessor)
        changed["recordId"] = "fixture-second-release"
        changed["releaseId"] = "fixture-second-release"
        changed["buildVersion"] = 24
        changed["contractSnapshot"]["digest"] = "sha256:" + "9" * 64
        changed["predecessorRecordDigest"] = predecessor["selfDigest"]
        changed["recordStatus"] = "candidate"
        _seal(changed, "selfDigest")
        ledger["records"].append(changed)
        ledger["headRecordDigest"] = changed["selfDigest"]
        _seal(ledger, "ledgerDigest")

        findings = api1x._history_errors(
            ledger,
            self.fixture.evidence,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            self.fixture.baseline_registry,
            True,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertTrue(any("without advancing contract version" in item for item in findings))

    def test_history_whenSuccessorGenerationDoesNotFollowPredecessor_expectFinding(self) -> None:
        predecessor_time = self.fixture.ledger_value["records"][0]["generatedAt"]
        for generated_at in ("2026-08-30T23:59:59Z", predecessor_time):
            with self.subTest(generated_at=generated_at):
                ledger = copy.deepcopy(self.fixture.ledger_value)
                successor = ledger["records"][-1]
                successor["generatedAt"] = generated_at
                _seal(successor, "selfDigest")
                ledger["headRecordDigest"] = successor["selfDigest"]
                _seal(ledger, "ledgerDigest")

                findings = api1x._history_errors(
                    ledger,
                    self.fixture.evidence,
                    self.fixture.contract,
                    self.fixture.baseline_registry_value,
                    self.fixture.baseline_registry,
                    True,
                    api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
                    api1x._policy(workspace_root())[0],
                )

                self.assertIn(
                    "history record 1 generatedAt does not follow its predecessor",
                    findings,
                )

    def test_history_whenPublicationPredatesGeneration_expectFinding(self) -> None:
        for published_at, expected in (
            ("2026-08-31T23:59:59Z", True),
            ("2026-09-01T00:00:00Z", False),
        ):
            with self.subTest(published_at=published_at):
                ledger = copy.deepcopy(self.fixture.ledger_value)
                successor = ledger["records"][-1]
                successor["publishedAt"] = published_at
                _seal(successor, "selfDigest")
                ledger["headRecordDigest"] = successor["selfDigest"]
                _seal(ledger, "ledgerDigest")

                findings = api1x._history_errors(
                    ledger,
                    self.fixture.evidence,
                    self.fixture.contract,
                    self.fixture.baseline_registry_value,
                    self.fixture.baseline_registry,
                    True,
                    api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
                    api1x._policy(workspace_root())[0],
                )

                finding = "history record 1 publication predates its generation"
                self.assertEqual(expected, finding in findings)

    def test_history_whenProductionImportedGenesisLacksReleaseReceipt_expectBlocked(self) -> None:
        record = copy.deepcopy(self.fixture.ledger_value["records"][0])
        record["fixtureOnly"] = False
        _seal(record, "selfDigest")
        ledger = {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-history-ledger",
            "repositoryIdentity": "github.com/crypta-network/cryptad",
            "records": [record],
            "oldestSupportedRecordDigest": record["selfDigest"],
            "headRecordDigest": record["selfDigest"],
            "ledgerDigest": ZERO,
        }
        _seal(ledger, "ledgerDigest")
        contract = copy.deepcopy(self.fixture.contract)
        contract["fixtureOnly"] = False
        contract["selfTest"] = False
        contract["contractVersion"] = 22
        contract["release"] = {
            "releaseId": record["releaseId"],
            "buildVersion": record["buildVersion"],
            "releaseRootDigest": record["releaseRootDigest"],
        }
        policy = api1x._policy(workspace_root())[0]

        findings = api1x._history_errors(
            ledger,
            self.fixture.evidence,
            contract,
            self.fixture.baseline_registry_value,
            self.fixture.baseline_registry,
            False,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            policy,
        )
        findings.extend(api1x._history_extension_errors(ledger, None, False))
        findings.extend(
            api1x._previous_history_authority_errors(
                contract, ledger, None, self.fixture.evidence, False, policy
            )
        )
        findings.extend(
            api1x._current_history_authority_errors(
                contract, ledger, None, None, None, None
            )
        )

        self.assertIn(
            "current history requires the authenticated selected RC freeze", findings
        )

    def test_currentHistoryAuthority_whenSelectedRcAndReceiptMatch_expectAccepted(self) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        ledger = copy.deepcopy(self.fixture.ledger_value)
        head = ledger["records"][-1]
        protected_provenance = copy.deepcopy(
            contract["authorities"]["protectedRelease"]["provenance"]
        )
        head["provenance"] = protected_provenance
        freeze = {
            "candidate": {
                "releaseId": head["releaseId"],
                "buildVersion": str(head["buildVersion"]),
                "sourceCommit": head["sourceCommit"],
                "sourceRef": head["sourceRef"],
            },
            "platformApi": {
                "baselineName": "1.0",
                "baselineDigest": "sha256:" + api1x.FROZEN_1_0_ARTIFACT_DIGEST,
                "currentContractVersion": head["contractVersion"],
                "currentContractDigest": head["contractSnapshot"]["digest"],
            },
            "contentDigest": ZERO,
        }
        freeze_content = copy.deepcopy(freeze)
        freeze_content.pop("contentDigest")
        freeze["contentDigest"] = api1x._digest_bytes(
            api1x._canonical_bytes(freeze_content)
        )
        selected = {
            "runId": "10",
            "runAttempt": "1",
            "artifactName": "stable-1-0-rc-fixture",
            "artifactDigest": "sha256:" + "a" * 64,
            "freezeDigest": freeze["contentDigest"],
            "productDigest": head["releaseRootDigest"],
        }
        protected = {
            "dispatchPackage": {
                "gaValidation": {"selectedRc": copy.deepcopy(selected)},
                "gaPublication": {"selectedRc": copy.deepcopy(selected)},
            }
        }
        freeze_file_digest = "sha256:" + "b" * 64
        independent_selected = {
            **selected,
            "runAttempt": 1,
            "workflowPath": ".github/workflows/stable-1.0-rc-release.yml",
            "workflowCommit": contract["repository"]["sourceCommit"],
            "freezeFileDigest": freeze_file_digest,
        }

        findings = api1x._current_history_authority_errors(
            contract,
            ledger,
            freeze,
            {"digest": freeze_file_digest},
            protected,
            {"selectedRc": independent_selected},
        )

        self.assertEqual([], findings)

        ledger["records"][-1]["provenance"]["artifactName"] = "substituted"
        findings = api1x._current_history_authority_errors(
            contract,
            ledger,
            freeze,
            {"digest": freeze_file_digest},
            protected,
            {"selectedRc": independent_selected},
        )
        self.assertIn(
            "current history provenance differs from its authenticated release receipt",
            findings,
        )

    def test_history_whenMultipleRecordsHaveNoAuthenticatedPrefix_expectBlocked(self) -> None:
        policy = api1x._policy(workspace_root())[0]

        extension = api1x._history_extension_errors(
            self.fixture.ledger_value, None, False
        )
        authority = api1x._previous_history_authority_errors(
            self.fixture.contract,
            self.fixture.ledger_value,
            None,
            self.fixture.evidence,
            False,
            policy,
        )

        self.assertTrue(any("authenticated previous ledger" in item for item in extension))
        self.assertTrue(any("protected previous" in item for item in authority))

    def test_history_whenAuthenticatedPrefixIsRewritten_expectBlocked(self) -> None:
        changed = copy.deepcopy(self.fixture.ledger_value)
        changed["records"][0]["releaseId"] = "rewritten-release"

        findings = api1x._history_extension_errors(
            changed, self.fixture.previous_ledger_value, False
        )

        self.assertIn("history ledger rewrites the authenticated predecessor prefix", findings)

    def test_history_whenNestedSnapshotSubjectDiffers_expectBoundedFindings(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)
        snapshot["contract"]["contractVersion"] = 22
        snapshot["contract"]["compatibilityWindow"]["currentContractVersion"] = 21
        write_json(self.fixture.snapshot23, snapshot)
        ledger = copy.deepcopy(self.fixture.ledger_value)
        ledger["records"][-1]["contractSnapshot"] = _binding(self.fixture.snapshot23)
        _seal(ledger["records"][-1], "selfDigest")
        ledger["headRecordDigest"] = ledger["records"][-1]["selfDigest"]
        _seal(ledger, "ledgerDigest")

        findings = api1x._history_errors(
            ledger,
            self.fixture.evidence,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            self.fixture.baseline_registry,
            True,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertTrue(any("contract version differs from its snapshot" in item for item in findings))
        self.assertTrue(any("compatibility window differs" in item for item in findings))

    def test_history_whenRegistryBindingDiffers_expectSubjectFinding(self) -> None:
        ledger = copy.deepcopy(self.fixture.ledger_value)
        ledger["records"][-1]["baselineRegistryDigest"] = "sha256:" + "9" * 64
        _seal(ledger["records"][-1], "selfDigest")
        ledger["headRecordDigest"] = ledger["records"][-1]["selfDigest"]
        _seal(ledger, "ledgerDigest")

        findings = api1x._history_errors(
            ledger,
            self.fixture.evidence,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            self.fixture.baseline_registry,
            True,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertIn(
            "history ledger head differs from the accepted baseline registry", findings
        )

    def test_baselineRegistry_whenLifecycleDigestIsRewritten_expectFinding(self) -> None:
        registry = read_json(self.fixture.evidence / "baseline-registry.json")
        registry["baselineRegistry"]["lineage"][0]["evidenceDigest"] = "9" * 64

        findings = api1x._baseline_registry_errors(
            registry, self.fixture.contract, True
        )

        self.assertTrue(any("lineage 0 self digest is invalid" in item for item in findings))

    def test_baselineRegistry_whenPreActivationCoordinatesAreClaimed_expectFinding(
        self,
    ) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        item = registry["baselineRegistry"]["lineage"][-1]
        item["activationRelease"] = "not-activated"
        item["activationBuild"] = 24
        item["supportStartedRelease"] = "not-supported"
        item["lineageDigest"] = api1x._baseline_lineage_digest(item)
        registry["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            registry["baselineRegistry"]
        )

        findings = api1x._baseline_registry_errors(
            registry, self.fixture.contract, True
        )

        self.assertTrue(any("before activation" in item for item in findings))

    def test_baselineRegistry_whenAuthenticatedPredecessorIsRewritten_expectBlocked(
        self,
    ) -> None:
        previous = self._registry_with_future_baseline("proposed", "fixture")
        current = copy.deepcopy(previous)
        definition = current["baselineRegistry"]["definitions"][-1]
        definition["reviewDigest"] = "9" * 64
        definition["definitionDigest"] = api1x._baseline_definition_digest(definition)
        lineage = current["baselineRegistry"]["lineage"][-1]
        lineage["definitionDigest"] = definition["definitionDigest"]
        lineage["lineageDigest"] = api1x._baseline_lineage_digest(lineage)
        current["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            current["baselineRegistry"]
        )

        findings = api1x._baseline_registry_extension_errors(
            current, previous, self.fixture.previous_ledger_value
        )

        self.assertIn(
            "baseline registry rewrites the authenticated definition prefix", findings
        )
        self.assertIn(
            "baseline registry rewrites the authenticated lifecycle prefix", findings
        )

    def test_baselineRegistry_whenFutureBaselineStartsActiveWithFixture_expectBlocked(self) -> None:
        registry = self._registry_with_future_baseline("active", "fixture")
        contract = copy.deepcopy(self.fixture.contract)
        contract["activeStableBaselines"] = ["1.0", "1.1"]

        findings = api1x._baseline_registry_errors(registry, contract, True)

        self.assertTrue(any("does not begin at proposed" in item for item in findings))
        self.assertTrue(any("fixture evidence establishes" in item for item in findings))

    def test_baselineRegistry_whenFutureFixtureIsProposed_expectAccepted(self) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")

        findings = api1x._baseline_registry_errors(
            registry, self.fixture.contract, True
        )

        self.assertEqual([], findings)

    def test_baselineRegistry_whenFutureProtectedLineageClaimsActivation_expectBlocked(self) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        lineage = registry["baselineRegistry"]["lineage"]
        previous = lineage[-1]
        for status in ("candidate", "reviewed", "documented", "active"):
            item = copy.deepcopy(previous)
            item["status"] = status
            item["previousLineageDigest"] = previous["lineageDigest"]
            if status == "active":
                item["evidenceKind"] = "protected-release"
                item["activationRelease"] = "future-release"
                item["activationBuild"] = 24
                item["supportStartedRelease"] = "future-release"
            item["lineageDigest"] = api1x._baseline_lineage_digest(item)
            lineage.append(item)
            previous = item
        registry["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            registry["baselineRegistry"]
        )
        contract = copy.deepcopy(self.fixture.contract)
        contract["contractVersion"] = 24
        contract["activeStableBaselines"] = ["1.0", "1.1"]

        findings = api1x._baseline_registry_errors(
            registry,
            contract,
            False,
            api1x._policy(workspace_root())[0],
        )

        self.assertTrue(any("authenticated activation authority" in item for item in findings))
        self.assertTrue(any("authenticated activation set" in item for item in findings))

    def test_baselineRegistry_whenDeprecationRewritesActivationCoordinates_expectBlocked(
        self,
    ) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        lineage = registry["baselineRegistry"]["lineage"]
        previous = lineage[-1]
        for status in ("candidate", "reviewed", "documented", "active", "deprecated"):
            item = copy.deepcopy(previous)
            item["status"] = status
            item["previousLineageDigest"] = previous["lineageDigest"]
            if status in {"active", "deprecated"}:
                item["evidenceKind"] = "protected-release"
                item["activationRelease"] = (
                    "rewritten-release" if status == "deprecated" else "activation-release"
                )
                item["activationBuild"] = 24
                item["supportStartedRelease"] = "activation-release"
            item["lineageDigest"] = api1x._baseline_lineage_digest(item)
            lineage.append(item)
            previous = item
        registry["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            registry["baselineRegistry"]
        )
        contract = copy.deepcopy(self.fixture.contract)
        contract["contractVersion"] = 24
        contract["activeStableBaselines"] = ["1.0", "1.1"]
        policy = copy.deepcopy(api1x._policy(workspace_root())[0])
        policy["operationallyActivatableBaselines"] = ["1.0", "1.1"]

        findings = api1x._baseline_registry_errors(
            registry,
            contract,
            False,
            policy,
        )

        self.assertTrue(any("immutable activation coordinates" in item for item in findings))

    def test_baselineRegistry_whenFrozenImportInventsActivationCoordinates_expectBlocked(
        self,
    ) -> None:
        registry = copy.deepcopy(self.fixture.baseline_registry_value)
        lineage = registry["baselineRegistry"]["lineage"]
        imported = lineage[0]
        deprecated = copy.deepcopy(imported)
        deprecated.update(
            {
                "status": "deprecated",
                "evidenceKind": "protected-release",
                "evidenceDigest": "9" * 64,
                "activationRelease": "invented-activation-release",
                "activationBuild": 24,
                "supportStartedRelease": "invented-support-start",
                "previousLineageDigest": imported["lineageDigest"],
            }
        )
        deprecated["lineageDigest"] = api1x._baseline_lineage_digest(deprecated)
        lineage.append(deprecated)
        registry["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            registry["baselineRegistry"]
        )

        findings = api1x._baseline_registry_errors(
            registry,
            self.fixture.contract,
            False,
            api1x._policy(workspace_root())[0],
        )

        self.assertTrue(any("immutable activation coordinates" in item for item in findings))

    def test_baselineRegistry_whenEndOfSupportErasesActivationCoordinates_expectBlocked(
        self,
    ) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        lineage = registry["baselineRegistry"]["lineage"]
        previous = lineage[-1]
        for status in (
            "candidate",
            "reviewed",
            "documented",
            "active",
            "deprecated",
            "end-of-support",
        ):
            item = copy.deepcopy(previous)
            item["status"] = status
            item["previousLineageDigest"] = previous["lineageDigest"]
            if status in {"active", "deprecated"}:
                item["evidenceKind"] = "protected-release"
                item["activationRelease"] = "activation-release"
                item["activationBuild"] = 24
                item["supportStartedRelease"] = "activation-release"
            if status == "end-of-support":
                item["evidenceKind"] = "protected-release"
                item["activationRelease"] = None
                item["activationBuild"] = None
                item["supportStartedRelease"] = None
                item["supportEndedRelease"] = "support-ended-release"
            item["lineageDigest"] = api1x._baseline_lineage_digest(item)
            lineage.append(item)
            previous = item
        registry["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            registry["baselineRegistry"]
        )
        contract = copy.deepcopy(self.fixture.contract)
        contract["contractVersion"] = 24
        contract["activeStableBaselines"] = ["1.0"]
        policy = copy.deepcopy(api1x._policy(workspace_root())[0])
        policy["operationallyActivatableBaselines"] = ["1.0", "1.1"]

        findings = api1x._baseline_registry_errors(
            registry,
            contract,
            False,
            policy,
        )

        self.assertTrue(any("immutable activation coordinates" in item for item in findings))

    def test_baselineRegistry_whenFutureChangesInheritedEndpoint_expectBlocked(self) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        future = registry["baselineRegistry"]["definitions"][1]
        future["endpoints"][0]["actionLabel"] = "changed.action"
        future["definitionDigest"] = api1x._baseline_definition_digest(future)
        lineage = registry["baselineRegistry"]["lineage"][1]
        lineage["definitionDigest"] = future["definitionDigest"]
        lineage["lineageDigest"] = api1x._baseline_lineage_digest(lineage)
        registry["baselineRegistry"]["registryDigest"] = api1x._baseline_registry_digest(
            registry["baselineRegistry"]
        )

        findings = api1x._baseline_registry_errors(
            registry, self.fixture.contract, True
        )

        self.assertTrue(any("changes inherited endpoint semantics" in item for item in findings))

    def test_baselineRegistry_whenBranchOmitsSupportedIntermediateMembers_expectBlocked(self) -> None:
        envelope = self._registry_with_future_baseline("proposed", "fixture")
        registry = envelope["baselineRegistry"]
        previous = registry["lineage"][-1]
        for index, status in enumerate(
            ("candidate", "reviewed", "documented", "active"), start=5
        ):
            item = copy.deepcopy(previous)
            item["status"] = status
            item["evidenceDigest"] = str(index) * 64
            item["previousLineageDigest"] = previous["lineageDigest"]
            if status == "active":
                item["evidenceKind"] = "protected-release"
                item["activationRelease"] = "fixture-release-24"
                item["activationBuild"] = 24
                item["supportStartedRelease"] = "fixture-release-24"
            item["lineageDigest"] = api1x._baseline_lineage_digest(item)
            registry["lineage"].append(item)
            previous = item
        frozen = registry["definitions"][0]
        branched = copy.deepcopy(frozen)
        branched.update(
            {
                "id": "1.2",
                "predecessorId": "1.0",
                "sourceArtifactDigest": "9" * 64,
                "proposalDigest": "a" * 64,
                "firstCompleteContractVersion": 25,
            }
        )
        branched["definitionDigest"] = api1x._baseline_definition_digest(branched)
        registry["definitions"].append(branched)
        proposed = {
            "id": "1.2",
            "definitionDigest": branched["definitionDigest"],
            "status": "proposed",
            "evidenceKind": "fixture",
            "evidenceDigest": "b" * 64,
            "activationRelease": None,
            "activationBuild": None,
            "supportStartedRelease": None,
            "supportEndedRelease": None,
            "previousLineageDigest": None,
            "lineageDigest": "0" * 64,
        }
        proposed["lineageDigest"] = api1x._baseline_lineage_digest(proposed)
        registry["lineage"].append(proposed)
        registry["registryDigest"] = api1x._baseline_registry_digest(registry)
        contract = copy.deepcopy(self.fixture.contract)
        contract["contractVersion"] = 24
        contract["activeStableBaselines"] = ["1.0", "1.1"]
        policy = copy.deepcopy(api1x._policy(workspace_root())[0])
        policy["operationallyActivatableBaselines"] = ["1.0", "1.1"]

        findings = api1x._baseline_registry_errors(
            envelope, contract, True, policy
        )

        self.assertTrue(
            any("omits a supported predecessor capability" in item for item in findings)
        )
        self.assertTrue(
            any("omits a supported predecessor endpoint" in item for item in findings)
        )

    def test_history_whenFrozenEndpointSemanticsChange_expectBlockedAfterReseal(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)
        target = next(
            endpoint
            for endpoint in snapshot["contract"]["endpoints"]
            if endpoint["method"] == "GET" and endpoint["routeTemplate"] == "/queue"
        )
        target["actionLabel"] = "changed.action"
        write_json(self.fixture.snapshot23, snapshot)
        ledger = copy.deepcopy(self.fixture.ledger_value)
        ledger["records"][-1]["contractSnapshot"] = _binding(self.fixture.snapshot23)
        _seal(ledger["records"][-1], "selfDigest")
        ledger["headRecordDigest"] = ledger["records"][-1]["selfDigest"]
        _seal(ledger, "ledgerDigest")

        findings = api1x._history_errors(
            ledger,
            self.fixture.evidence,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            self.fixture.baseline_registry,
            True,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertTrue(any("baseline endpoint semantics changed" in item for item in findings))

    def test_snapshotBaseline_whenFrozenDescriptorsDrift_expectBoundedFindings(self) -> None:
        base = read_json(self.fixture.snapshot23)["contract"]
        mutations = (
            (
                "missing capability",
                lambda contract: contract["capabilities"].pop(
                    next(
                        index
                        for index, descriptor in enumerate(contract["capabilities"])
                        if descriptor["name"] == "queue.read"
                    )
                ),
                "baseline capability descriptor is missing",
            ),
            (
                "restricted capability",
                lambda contract: next(
                    descriptor
                    for descriptor in contract["capabilities"]
                    if descriptor["name"] == "queue.read"
                ).update({"stability": "operator-only", "audience": "operator-only"}),
                "baseline capability descriptor is restricted",
            ),
            (
                "missing endpoint",
                lambda contract: contract["endpoints"].pop(
                    next(
                        index
                        for index, descriptor in enumerate(contract["endpoints"])
                        if descriptor["method"] == "GET"
                        and descriptor["routeTemplate"] == "/queue"
                    )
                ),
                "baseline endpoint descriptor is missing",
            ),
            (
                "frozen membership",
                lambda contract: next(
                    descriptor
                    for descriptor in contract["endpoints"]
                    if descriptor["method"] == "GET"
                    and descriptor["routeTemplate"] == "/queue"
                ).update({"stableBaselineMember": False}),
                "frozen 1.0 endpoint membership changed",
            ),
            (
                "duplicate endpoint",
                lambda contract: contract["endpoints"].append(
                    copy.deepcopy(
                        next(
                            descriptor
                            for descriptor in contract["endpoints"]
                            if descriptor["method"] == "GET"
                            and descriptor["routeTemplate"] == "/queue"
                        )
                    )
                ),
                "duplicates endpoint descriptor",
            ),
        )
        for name, mutate, expected in mutations:
            with self.subTest(mutation=name):
                contract = copy.deepcopy(base)
                mutate(contract)

                findings = api1x._snapshot_baseline_errors(
                    contract, self.fixture.baseline_registry_value, "snapshot"
                )

                self.assertTrue(any(expected in item for item in findings), findings)

    def test_snapshotBaseline_whenEndpointAuthorizationSemanticsChange_expectBlocked(self) -> None:
        base = read_json(self.fixture.snapshot23)["contract"]
        mutations = (
            ("routeFamily", "changed-family"),
            ("actionLabel", "changed.action"),
            ("requiredCapabilities", []),
            ("hostOperatorBypassAllowed", False),
            ("appProcessPrincipalsAllowed", False),
            ("appBrowserPrincipalsAllowed", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                contract = copy.deepcopy(base)
                target = next(
                    descriptor
                    for descriptor in contract["endpoints"]
                    if descriptor["method"] == "GET"
                    and descriptor["routeTemplate"] == "/queue"
                )
                target[field] = value

                findings = api1x._snapshot_baseline_errors(
                    contract, self.fixture.baseline_registry_value, "snapshot"
                )

                self.assertTrue(
                    any("baseline endpoint semantics changed" in item for item in findings),
                    findings,
                )

    def test_snapshotBaseline_whenSupportedDefinitionIsNewerThanHead_expectBlocked(self) -> None:
        registry = self._registry_with_future_baseline("active", "fixture")
        snapshot = read_json(self.fixture.snapshot23)["contract"]

        findings = api1x._snapshot_baseline_errors(
            snapshot,
            registry,
            "history head",
            require_supported_complete=True,
        )

        self.assertTrue(
            any("before its complete contract version" in item for item in findings),
            findings,
        )

    def test_snapshotBaseline_whenMembersAppearAfterCompleteVersion_expectBlocked(self) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        target = registry["baselineRegistry"]["definitions"][1]
        target["firstCompleteContractVersion"] = 23
        snapshot = read_json(self.fixture.snapshot23)["contract"]
        snapshot["contractVersion"] = 24
        snapshot["capabilities"].append(
            {
                "name": "future.read",
                "stability": "experimental",
                "audience": "app",
                "stableBaselineMember": False,
                "stableBaseline": None,
                "sinceContractVersion": 24,
                "deprecation": None,
                "description": "Fixture future capability.",
            }
        )
        snapshot["endpoints"].append(
            {
                "routeFamily": "future",
                "method": "GET",
                "routeTemplate": "/future",
                "actionLabel": "future.read",
                "requiredCapabilities": ["future.read"],
                "hostOperatorBypassAllowed": False,
                "appProcessPrincipalsAllowed": True,
                "appBrowserPrincipalsAllowed": True,
                "stability": "experimental",
                "audience": "app",
                "stableBaselineMember": False,
                "stableBaseline": None,
                "sinceContractVersion": 24,
                "deprecation": None,
                "description": "Fixture future endpoint.",
            }
        )

        findings = api1x._snapshot_baseline_errors(snapshot, registry, "candidate snapshot")

        self.assertIn(
            "candidate snapshot baseline capability future.read was introduced after its claimed complete contract version",
            findings,
        )
        self.assertIn(
            "candidate snapshot baseline endpoint GET /future was introduced after its claimed complete contract version",
            findings,
        )

    def test_snapshot_whenNestedApiVersionChanges_expectClosedSchemaRejection(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)
        snapshot["contract"]["apiVersion"] = "v2"

        findings = validate_schema(snapshot, api1x.SNAPSHOT_SCHEMA)

        self.assertTrue(any("apiVersion" in item for item in findings))

    def test_snapshot_whenVersion24CarriesRegistrySummary_expectSchemaAndSubjectAccepted(
        self,
    ) -> None:
        snapshot = read_json(self.fixture.snapshot23)
        contract = snapshot["contract"]
        contract["contractVersion"] = 24
        contract["compatibilityWindow"]["currentContractVersion"] = 24
        registry = self.fixture.baseline_registry_value["baselineRegistry"]
        contract["baselineRegistrySummary"] = {
            "schemaVersion": 1,
            "registryDigest": registry["registryDigest"],
            "supportedBaselines": [
                {
                    "id": "1.0",
                    "status": "active",
                    "definitionDigest": registry["definitions"][0]["definitionDigest"],
                }
            ],
        }

        schema_findings = validate_schema(snapshot, api1x.SNAPSHOT_SCHEMA)
        subject_findings = api1x._snapshot_baseline_errors(
            contract,
            self.fixture.baseline_registry_value,
            "version 24 snapshot",
            require_supported_complete=True,
        )

        self.assertEqual([], schema_findings)
        self.assertEqual([], subject_findings)

    def test_snapshot_whenRegistrySummaryDiffers_expectSubjectFinding(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)
        contract = snapshot["contract"]
        contract["contractVersion"] = 24
        contract["compatibilityWindow"]["currentContractVersion"] = 24
        registry = self.fixture.baseline_registry_value["baselineRegistry"]
        contract["baselineRegistrySummary"] = {
            "schemaVersion": 1,
            "registryDigest": "9" * 64,
            "supportedBaselines": [
                {
                    "id": "1.0",
                    "status": "active",
                    "definitionDigest": registry["definitions"][0]["definitionDigest"],
                }
            ],
        }

        findings = api1x._snapshot_baseline_errors(
            contract,
            self.fixture.baseline_registry_value,
            "version 24 snapshot",
            require_supported_complete=True,
        )

        self.assertIn(
            "version 24 snapshot baseline registry summary differs from the accepted registry",
            findings,
        )

    def test_snapshot_whenHistoricalRegistrySummaryDiffers_expectImmutableProjectionAccepted(
        self,
    ) -> None:
        snapshot = read_json(self.fixture.snapshot23)["contract"]
        snapshot["contractVersion"] = 24
        snapshot["compatibilityWindow"]["currentContractVersion"] = 24
        definition = self.fixture.baseline_registry_value["baselineRegistry"]["definitions"][0]
        snapshot["baselineRegistrySummary"] = {
            "schemaVersion": 1,
            "registryDigest": "9" * 64,
            "supportedBaselines": [
                {
                    "id": "1.0",
                    "status": "active",
                    "definitionDigest": definition["definitionDigest"],
                }
            ],
        }

        findings = api1x._snapshot_baseline_errors(
            snapshot,
            self.fixture.baseline_registry_value,
            "historical snapshot",
            require_current_registry_summary=False,
        )

        self.assertEqual([], findings)

    def test_history_whenSnapshotRegistryDigestDiffersFromRecord_expectFinding(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)
        contract = snapshot["contract"]
        contract["contractVersion"] = 24
        contract["compatibilityWindow"]["currentContractVersion"] = 24
        registry = self.fixture.baseline_registry_value["baselineRegistry"]
        contract["baselineRegistrySummary"] = api1x._expected_baseline_registry_summary(registry)
        write_json(self.fixture.snapshot23, snapshot)
        ledger = copy.deepcopy(self.fixture.ledger_value)
        head = ledger["records"][-1]
        head["contractVersion"] = 24
        head["contractSnapshot"] = _binding(self.fixture.snapshot23)
        head["baselineRegistryDigest"] = "sha256:" + "9" * 64
        head["compatibilityWindowDigest"] = api1x._digest_bytes(
            api1x._canonical_bytes(contract["compatibilityWindow"])
        )
        _seal(head, "selfDigest")
        ledger["headRecordDigest"] = head["selfDigest"]
        _seal(ledger, "ledgerDigest")

        findings = api1x._history_errors(
            ledger,
            self.fixture.evidence,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            self.fixture.baseline_registry,
            True,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertIn(
            "history record 1 baseline-registry digest differs from its snapshot summary",
            findings,
        )

    def test_proposal_whenRemovalClaimed_expectIncompatibleFinding(self) -> None:
        proposal = {
            "targetBaselineId": "1.1",
            "predecessorBaselineId": "1.0",
            "sourceCommit": SOURCE,
            "releaseId": "fixture-release-23",
            "targetContractVersion": 23,
            "claimedRemovals": ["capability:stable.read"],
            "predecessorMembers": ["capability:stable.read"],
            "candidateMembers": [],
            "lifecycleState": "candidate",
            "proposalDigest": ZERO,
            "fixtureOnly": True,
            "reviewProvenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
                "workflowCommit": SOURCE,
            },
        }
        for name, digit in zip(
            (
                "compatibilityAnalysisDigest", "rationaleDigest", "securityReviewDigest",
                "documentationDigest", "testEvidenceDigest", "appMatrixDigest",
            ),
            "123456",
            strict=True,
        ):
            proposal[name] = "sha256:" + digit * 64
        _seal(proposal, "proposalDigest")

        policy, _digest_value = api1x._policy(workspace_root())
        findings = api1x._proposal_errors(
            proposal,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            True,
            policy,
        )

        self.assertTrue(any("cannot claim removals" in item for item in findings))
        self.assertTrue(any("not monotonic" in item for item in findings))

    def test_proposal_whenTargetContractDiffers_expectSubjectFinding(self) -> None:
        proposal = {
            "targetBaselineId": "1.1",
            "predecessorBaselineId": "1.0",
            "sourceCommit": SOURCE,
            "releaseId": "fixture-release-23",
            "targetContractVersion": 24,
            "claimedRemovals": [],
            "predecessorMembers": [],
            "candidateMembers": [],
            "lifecycleState": "candidate",
            "proposalDigest": ZERO,
            "fixtureOnly": True,
            "reviewProvenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
                "workflowCommit": SOURCE,
            },
        }
        for name in (
            "compatibilityAnalysisDigest", "rationaleDigest", "securityReviewDigest",
            "documentationDigest", "testEvidenceDigest", "appMatrixDigest",
        ):
            proposal[name] = "sha256:" + "1" * 64
        _seal(proposal, "proposalDigest")

        findings = api1x._proposal_errors(
            proposal,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            True,
            api1x._policy(workspace_root())[0],
        )

        self.assertIn(
            "proposal target contract version differs from the execution contract", findings
        )

    def test_proposal_whenMembersOmitAcceptedPredecessor_expectRegistryFinding(self) -> None:
        registry = self._registry_with_future_baseline("proposed", "fixture")
        target = registry["baselineRegistry"]["definitions"][1]
        target["firstCompleteContractVersion"] = 23
        proposal = {
            "targetBaselineId": "1.1",
            "predecessorBaselineId": "1.0",
            "sourceCommit": SOURCE,
            "releaseId": "fixture-release-23",
            "targetContractVersion": 23,
            "predecessorMembers": [],
            "candidateMembers": [],
            "additions": [],
            "claimedRemovals": [],
            "lifecycleState": "proposed",
            "decision": "pending",
            "proposalDigest": ZERO,
            "fixtureOnly": True,
            "reviewProvenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
                "workflowCommit": SOURCE,
            },
        }
        for name in (
            "compatibilityAnalysisDigest", "rationaleDigest", "securityReviewDigest",
            "documentationDigest", "testEvidenceDigest", "appMatrixDigest",
        ):
            proposal[name] = "sha256:" + "1" * 64
        _seal(proposal, "proposalDigest")
        target["proposalDigest"] = proposal["proposalDigest"].removeprefix("sha256:")

        findings = api1x._proposal_errors(
            proposal,
            self.fixture.contract,
            registry,
            True,
            api1x._policy(workspace_root())[0],
        )

        self.assertIn(
            "proposal predecessor membership differs from the accepted registry", findings
        )
        self.assertIn(
            "proposal candidate membership differs from the target definition", findings
        )

    def test_proposalPresence_whenFutureDefinitionHasNoProposal_expectBlocked(self) -> None:
        policy = api1x._policy(workspace_root())[0]

        frozen_findings = api1x._proposal_presence_errors(
            None, self.fixture.baseline_registry_value, policy
        )
        future_findings = api1x._proposal_presence_errors(
            None,
            self._registry_with_future_baseline("proposed", "fixture"),
            policy,
        )

        self.assertEqual([], frozen_findings)
        self.assertIn(
            "a nonterminal future baseline definition requires exact proposal evidence",
            future_findings,
        )

    def test_graduation_whenOperatorEndpointSelfDeclaresAppAudience_expectBlocked(self) -> None:
        identity = "endpoint:GET:/app-services/audit"
        record = {
            "descriptorKind": "endpoint",
            "descriptorIdentity": identity,
            "descriptorAudience": "app",
            "sourceContractVersion": 23,
            "sourceCommit": SOURCE,
            "descriptorDigest": "sha256:" + "1" * 64,
            "targetBaselineId": "1.1",
            "requiredCapabilities": [],
            "allowedPrincipals": ["app-process"],
            "auditAction": "forged.action",
            "behaviorContractDigest": "sha256:" + "2" * 64,
            "securityReviewDigest": "sha256:" + "3" * 64,
            "compatibilityReviewDigest": "sha256:" + "4" * 64,
            "documentationDigest": "sha256:" + "5" * 64,
            "testEvidenceDigest": "sha256:" + "6" * 64,
            "appEvidenceDigest": "sha256:" + "7" * 64,
            "observationWindow": {
                "firstObservedAt": "2026-08-31T00:00:00Z",
                "lastObservedAt": "2026-09-01T00:00:00Z",
                "contractVersions": [23],
            },
            "decision": "approved",
            "recordDigest": ZERO,
            "fixtureOnly": True,
            "reviewProvenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
                "workflowCommit": SOURCE,
            },
        }
        record["observationWindow"]["firstObservedAt"] = "2099-01-01T00:00:00Z"
        record["observationWindow"]["lastObservedAt"] = "2099-01-02T00:00:00Z"
        _seal(record, "recordDigest")
        proposal = {"targetBaselineId": "1.1", "additions": [identity]}

        findings = api1x._graduation_errors(
            [record],
            proposal,
            self.fixture.contract,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
            True,
            datetime(2026, 9, 1, 0, 2, tzinfo=timezone.utc),
            api1x._policy(workspace_root())[0],
        )

        self.assertTrue(any("not experimental app-facing" in item for item in findings))
        self.assertTrue(any("descriptor audience differs" in item for item in findings))
        self.assertTrue(any("descriptor digest differs" in item for item in findings))
        self.assertTrue(any("allowed principals differ" in item for item in findings))
        self.assertTrue(any("audit action differs" in item for item in findings))
        self.assertTrue(any("observation window is future-dated" in item for item in findings))

    def test_deprecation_whenClockResets_expectFinding(self) -> None:
        row = {
            "descriptorKind": "endpoint",
            "descriptorIdentity": "endpoint:GET:/api/v1/example",
            "firstDeprecatedContractVersion": 20,
            "firstAuthenticatedReleaseId": "fixture-release-20",
            "firstAuthenticatedBuildVersion": 20,
            "firstObservedAt": "2026-01-01T00:00:00Z",
            "scheduledRemovalContractVersion": 24,
            "scheduledRemovalBaseline": "1.1",
            "supportedBaselineMemberships": ["1.0"],
            "requiredAppDependencies": [],
            "state": "deprecated",
            "critical": False,
            "predecessorTimelineDigest": None,
            "timelineDigest": ZERO,
        }
        _seal(row, "timelineDigest")
        prior = {"entries": [row], "ledgerDigest": "sha256:" + "1" * 64}
        changed = copy.deepcopy(row)
        changed["firstDeprecatedContractVersion"] = 22
        changed["predecessorTimelineDigest"] = row["timelineDigest"]
        _seal(changed, "timelineDigest")
        current = {
            "entries": [changed],
            "predecessorLedgerDigest": prior["ledgerDigest"],
            "ledgerDigest": ZERO,
        }
        _seal(current, "ledgerDigest")

        findings = api1x._deprecation_errors(current, prior, 23)

        self.assertTrue(any("contract clock changed" in item for item in findings))

    def test_deprecationHistory_whenHeadBindsAnotherLedger_expectFinding(self) -> None:
        current = copy.deepcopy(self.fixture.deprecation_value)
        current["ledgerDigest"] = "sha256:" + "9" * 64

        findings = api1x._deprecation_history_binding_errors(
            current,
            self.fixture.previous_deprecation_value,
            self.fixture.ledger_value,
            self.fixture.previous_ledger_value,
        )

        self.assertIn("history head differs from the accepted deprecation ledger", findings)

    def test_deprecationHistory_whenSuccessorOmitsPreviousLedger_expectFinding(self) -> None:
        findings = api1x._deprecation_history_binding_errors(
            self.fixture.deprecation_value,
            None,
            self.fixture.ledger_value,
            self.fixture.previous_ledger_value,
        )

        self.assertIn(
            "successor history requires the authenticated previous deprecation ledger",
            findings,
        )

    def test_deprecation_whenNewTimelineBackdatesNoticeAndStartsRemoved_expectBlocked(self) -> None:
        row = {
            "descriptorKind": "capability",
            "descriptorIdentity": "capability:queue.read",
            "firstDeprecatedContractVersion": 20,
            "firstAuthenticatedReleaseId": "forged-release",
            "firstAuthenticatedBuildVersion": 999,
            "firstObservedAt": "2020-01-01T00:00:00Z",
            "scheduledRemovalContractVersion": 24,
            "scheduledRemovalBaseline": "1.1",
            "replacementDescriptor": None,
            "replacementDocumentationDigest": None,
            "supportedBaselineMemberships": ["1.0"],
            "requiredAppDependencies": [],
            "lifecyclePrerequisitesDigest": "sha256:" + "1" * 64,
            "state": "removed",
            "critical": True,
            "predecessorTimelineDigest": None,
            "timelineDigest": ZERO,
        }
        _seal(row, "timelineDigest")
        ledger = {
            "entries": [row],
            "predecessorLedgerDigest": self.fixture.previous_deprecation_value[
                "ledgerDigest"
            ],
            "ledgerDigest": ZERO,
        }
        _seal(ledger, "ledgerDigest")
        subjects = copy.deepcopy(self.fixture.history_subjects)
        descriptor = next(
            item
            for item in subjects[-1][1]["capabilities"]
            if item["name"] == "queue.read"
        )
        descriptor["deprecation"] = {
            "deprecatedSinceContractVersion": 20,
            "removalContractVersion": 24,
            "note": "fixture notice",
        }

        findings = api1x._deprecation_errors(
            ledger,
            self.fixture.previous_deprecation_value,
            23,
            subjects,
        )

        self.assertTrue(any("starts in an invalid state" in item for item in findings))
        self.assertTrue(any("contract clock is not history-derived" in item for item in findings))
        self.assertTrue(any("first release is not history-derived" in item for item in findings))
        self.assertTrue(any("first notice time is not history-derived" in item for item in findings))
        self.assertIn(
            "descriptor removal precedes its scheduled contract version for capability:queue.read",
            findings,
        )

    def test_deprecationRemoval_whenCurrentContractEqualsSchedule_expectClockAccepted(
        self,
    ) -> None:
        row = {
            "descriptorKind": "capability",
            "descriptorIdentity": "capability:queue.read",
            "firstDeprecatedContractVersion": 21,
            "firstAuthenticatedReleaseId": "fixture-release-21",
            "firstAuthenticatedBuildVersion": 21,
            "firstObservedAt": "2026-01-01T00:00:00Z",
            "scheduledRemovalContractVersion": 23,
            "scheduledRemovalBaseline": "1.1",
            "replacementDescriptor": None,
            "replacementDocumentationDigest": None,
            "supportedBaselineMemberships": [],
            "requiredAppDependencies": [],
            "lifecyclePrerequisitesDigest": "sha256:" + "1" * 64,
            "state": "removed",
            "critical": False,
            "predecessorTimelineDigest": None,
            "timelineDigest": ZERO,
        }
        _seal(row, "timelineDigest")
        ledger = {
            "entries": [row],
            "predecessorLedgerDigest": None,
            "ledgerDigest": ZERO,
        }
        _seal(ledger, "ledgerDigest")

        findings = api1x._deprecation_errors(ledger, None, 23)

        self.assertNotIn(
            "descriptor removal precedes its scheduled contract version for capability:queue.read",
            findings,
        )

    def test_deprecationRemoval_whenProducerClearsDerivedBlockers_expectBlocked(self) -> None:
        row = {
            "descriptorKind": "capability",
            "descriptorIdentity": "capability:queue.read",
            "firstDeprecatedContractVersion": 20,
            "firstAuthenticatedReleaseId": "fixture-release-20",
            "firstAuthenticatedBuildVersion": 20,
            "firstObservedAt": "2026-01-01T00:00:00Z",
            "scheduledRemovalContractVersion": 23,
            "scheduledRemovalBaseline": "1.1",
            "replacementDescriptor": None,
            "replacementDocumentationDigest": None,
            "supportedBaselineMemberships": [],
            "requiredAppDependencies": [],
            "lifecyclePrerequisitesDigest": "sha256:" + "1" * 64,
            "state": "removed",
            "critical": False,
            "predecessorTimelineDigest": None,
            "timelineDigest": ZERO,
        }
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["requiredCapabilities"] = ["queue.read"]
        ledger = {"entries": [row]}

        findings = api1x._deprecation_subject_errors(
            ledger,
            self.fixture.baseline_registry_value,
            matrix,
            read_json(self.fixture.snapshot23)["contract"],
        )

        self.assertIn(
            "derived supported baseline memberships differ for capability:queue.read", findings
        )
        self.assertIn(
            "derived required app dependencies differ for capability:queue.read", findings
        )
        self.assertIn(
            "removal is blocked by a supported baseline or app for capability:queue.read",
            findings,
        )
        self.assertIn(
            "critical stable removal is non-waivable for capability:queue.read", findings
        )

    def test_deprecationLedger_whenSupportedSnapshotNoticeIsOmitted_expectBlocked(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)["contract"]
        descriptor = next(
            item for item in snapshot["capabilities"] if item["name"] == "queue.read"
        )
        descriptor["stability"] = "deprecated"
        descriptor["deprecation"] = {
            "deprecatedSinceContractVersion": 23,
            "removalContractVersion": 25,
            "note": "fixture notice",
        }

        findings = api1x._deprecation_subject_errors(
            {"entries": []},
            self.fixture.baseline_registry_value,
            self.fixture.matrix_value,
            snapshot,
        )

        self.assertIn(
            "supported stable deprecation is absent from the ledger for capability:queue.read",
            findings,
        )

    def test_snapshotBaseline_whenTerminalDefinitionMemberIsAbsent_expectAllowed(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)["contract"]

        for status in ("rejected", "end-of-support"):
            with self.subTest(status=status):
                registry = self._registry_with_future_baseline(status, "fixture")
                registry["baselineRegistry"]["definitions"][1][
                    "firstCompleteContractVersion"
                ] = 23
                findings = api1x._snapshot_baseline_errors(
                    snapshot, registry, f"{status} snapshot"
                )
                self.assertFalse(
                    any("future.read" in finding for finding in findings), findings
                )

    def test_snapshotBaseline_whenSupportedDefinitionMemberIsAbsent_expectBlocked(self) -> None:
        snapshot = read_json(self.fixture.snapshot23)["contract"]
        registry = self._registry_with_future_baseline("active", "protected-review")
        registry["baselineRegistry"]["definitions"][1][
            "firstCompleteContractVersion"
        ] = 23

        findings = api1x._snapshot_baseline_errors(snapshot, registry, "active snapshot")

        self.assertTrue(any("future.read" in finding for finding in findings), findings)

    def test_matrix_whenStaticRowClaimsRuntime_expectFinding(self) -> None:
        matrix = read_json(self.fixture.evidence / "matrix.json")
        matrix["rows"][0]["evaluations"][0]["runtimeObserved"] = True
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertTrue(any("static matrix claims" in item for item in findings))

    def test_matrix_whenLedgerProjectionDiffersFromDerivedLifecycle_expectDerivedSubjectWins(self) -> None:
        ledger = copy.deepcopy(self.fixture.ledger_value)
        ledger["oldestSupportedRecordDigest"] = ledger["records"][-1]["selfDigest"]
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["evaluations"].append(
            {
                "releaseRole": "oldest-supported",
                "releaseId": "fixture-release-23",
                "contractVersion": 23,
                "baselineId": "1.0",
                "verdict": "compatible",
                "staticVerified": True,
                "runtimeObserved": False,
                "findingCodes": [],
            }
        )

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            ledger,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
            self.fixture.ledger_value["records"][0],
        )

        self.assertIn(
            "app matrix row 0 oldest-supported evaluation subject differs from history",
            findings,
        )

    def test_matrix_whenStableBaselineIsInactive_expectFinding(self) -> None:
        matrix = read_json(self.fixture.evidence / "matrix.json")
        matrix["rows"][0]["targetBaseline"] = "1.1"
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertTrue(any("inactive baseline" in item for item in findings))

    def test_matrix_whenStableBaselineIsDeprecated_expectCompatibleWarning(self) -> None:
        registry = copy.deepcopy(self.fixture.baseline_registry_value)
        baseline_registry = registry["baselineRegistry"]
        previous = baseline_registry["lineage"][-1]
        deprecated = copy.deepcopy(previous)
        deprecated.update(
            {
                "status": "deprecated",
                "evidenceKind": "fixture",
                "evidenceDigest": "8" * 64,
                "previousLineageDigest": previous["lineageDigest"],
            }
        )
        deprecated["lineageDigest"] = api1x._baseline_lineage_digest(deprecated)
        baseline_registry["lineage"].append(deprecated)
        baseline_registry["registryDigest"] = api1x._baseline_registry_digest(
            baseline_registry
        )
        matrix = copy.deepcopy(self.fixture.matrix_value)
        evaluation = matrix["rows"][0]["evaluations"][0]
        evaluation["verdict"] = "compatible-with-warnings"
        evaluation["findingCodes"] = ["baseline.deprecated"]
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            registry,
            self.fixture.history_subjects,
        )

        self.assertFalse(any("inactive baseline" in item for item in findings), findings)
        self.assertFalse(any("verdict differs" in item for item in findings), findings)

    def test_matrix_whenReleaseOrSourceDiffers_expectSubjectFinding(self) -> None:
        matrix = read_json(self.fixture.evidence / "matrix.json")
        matrix["releaseId"] = "substituted-release"
        matrix["sourceCommit"] = "b" * 40
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertIn("app compatibility matrix release subject differs", findings)

    def test_matrix_whenProposalBindsAnotherMatrix_expectFinding(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        proposal = {"appMatrixDigest": "sha256:" + "9" * 64}

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            proposal,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertIn(
            "proposal app-matrix digest differs from the accepted matrix", findings
        )

    def test_matrix_whenRequiredCandidateIsPreviewOnly_expectBlocked(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        row = matrix["rows"][0]
        row["fixtureOnly"] = False
        row["evaluations"] = [
            {
                "releaseRole": "oldest-supported",
                "releaseId": "fixture-release-22",
                "contractVersion": 22,
                "baselineId": "1.0",
                "verdict": "compatible",
                "staticVerified": True,
                "runtimeObserved": False,
                "findingCodes": [],
            },
            {
                "releaseRole": "previous",
                "releaseId": "fixture-release-22",
                "contractVersion": 22,
                "baselineId": "1.0",
                "verdict": "compatible-with-warnings",
                "staticVerified": True,
                "runtimeObserved": False,
                "findingCodes": ["fixture.warning"],
            },
            {
                "releaseRole": "candidate",
                "releaseId": "fixture-release-23",
                "contractVersion": 23,
                "baselineId": "1.0",
                "verdict": "preview-only",
                "staticVerified": True,
                "runtimeObserved": False,
                "findingCodes": ["fixture.preview-only"],
            },
        ]
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            False,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertIn(
            "app matrix row 0 candidate verdict differs from contract-derived compatibility",
            findings,
        )

    def test_matrix_whenRequiredProductionRoleIsMissing_expectBlocked(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["fixtureOnly"] = False
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            False,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertIn(
            "app matrix row 0 omits a required static release-role evaluation", findings
        )

    def test_matrix_whenStableAppClaimsRestrictedCapabilityIsCompatible_expectBlocked(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["requiredCapabilities"] = ["vault.identities.manage"]
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertIn(
            "app matrix row 0 candidate verdict differs from contract-derived compatibility",
            findings,
        )
        self.assertIn(
            "app matrix row 0 candidate finding codes differ from contract-derived compatibility",
            findings,
        )

    def test_matrix_whenRequiredSubjectRemovedFromMatrixAndLabels_expectBlocked(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"] = []
        matrix["requiredAppIds"] = []
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
            app_subject_inventory=self.fixture.app_subject_inventory_value,
        )

        self.assertIn(
            "app matrix subject set differs from the authenticated inventory", findings
        )
        self.assertIn(
            "app matrix required app IDs differ from the authenticated inventory", findings
        )

    def test_matrix_whenCompatibilityFieldsDifferFromInventory_expectBlocked(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["requiredCapabilities"] = ["vault.identities.manage"]
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            True,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
            app_subject_inventory=self.fixture.app_subject_inventory_value,
        )

        self.assertIn("app matrix row 0 differs from the authenticated subject", findings)

    def test_appSubjectInventory_whenAppVersionIsRebound_expectBlocked(self) -> None:
        inventory = copy.deepcopy(self.fixture.app_subject_inventory_value)
        duplicate = copy.deepcopy(inventory["subjects"][0])
        duplicate["bundleDigest"] = "sha256:" + "8" * 64
        _seal(duplicate, "subjectDigest")
        inventory["subjects"].append(duplicate)
        _seal(inventory, "inventoryDigest")
        policy = api1x._policy(workspace_root())[0]

        findings = api1x._app_subject_inventory_errors(
            inventory, True, self.fixture.contract, policy
        )

        self.assertIn(
            "app subject inventory row 1 duplicates an app version with another bundle",
            findings,
        )

    def test_appSubjectInventory_whenBroadAuthorityDigestIsCited_expectProjectionBlocked(
        self,
    ) -> None:
        inventory = copy.deepcopy(self.fixture.app_subject_inventory_value)
        inventory["fixtureOnly"] = False
        subject = inventory["subjects"][0]
        subject["sourceAuthority"] = "first-party-release"
        subject["sourceAuthorityRoot"] = self.fixture.contract["authorityRoots"][
            "independentReproducibility"
        ]
        subject["sourceEvidenceDigest"] = "sha256:" + "8" * 64
        subject["fixtureOnly"] = False
        _seal(subject, "subjectDigest")
        _seal(inventory, "inventoryDigest")
        policy = api1x._policy(workspace_root())[0]

        findings = api1x._app_subject_inventory_errors(
            inventory, False, self.fixture.contract, policy
        )

        self.assertIn(
            "app subject inventory row 0 lacks an authenticated complete compatibility projection",
            findings,
        )

    def test_matrixVerification_whenBroadAuthorityDigestIsCited_expectNoVerifiedState(
        self,
    ) -> None:
        inventory = copy.deepcopy(self.fixture.app_subject_inventory_value)
        inventory["fixtureOnly"] = False
        subject = inventory["subjects"][0]
        subject["sourceAuthority"] = "first-party-release"
        subject["sourceAuthorityRoot"] = self.fixture.contract["authorityRoots"][
            "independentReproducibility"
        ]
        subject["sourceEvidenceDigest"] = "sha256:" + "8" * 64
        subject["fixtureOnly"] = False
        _seal(subject, "subjectDigest")
        _seal(inventory, "inventoryDigest")
        inventory_path = self.fixture.evidence / "app-subject-inventory.json"
        write_json(inventory_path, inventory)

        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["sourceAuthority"] = "first-party-release"
        matrix["rows"][0]["fixtureOnly"] = False
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")
        matrix_path = self.fixture.evidence / "matrix.json"
        write_json(matrix_path, matrix)

        self.fixture.contract["fixtureOnly"] = False
        self.fixture.contract["selfTest"] = False
        self.fixture.contract["requestedState"] = "app-matrix-verified"
        self.fixture.contract["evidence"]["appSubjectInventory"] = _binding(
            inventory_path
        )
        self.fixture.contract["evidence"]["appMatrix"] = _binding(matrix_path)
        self.fixture.rewrite_contract()

        result = api1x.run(
            workspace_root(),
            self.fixture.contract_path,
            "verify-app-matrix",
            self.root / "out",
            self.fixture.evidence,
        )

        self.assertEqual(1, result)
        summary = read_json(self.root / "out" / api1x.SUMMARY_FILE)
        self.assertNotEqual("app-matrix-verified", summary["state"])
        self.assertIn(
            "app subject inventory row 0 lacks an authenticated complete compatibility projection",
            summary["blockers"],
        )

    def test_matrix_whenOperationalInventoryIsAbsent_expectBlocked(self) -> None:
        matrix = copy.deepcopy(self.fixture.matrix_value)
        matrix["rows"][0]["fixtureOnly"] = False
        matrix["rows"][0]["sourceAuthority"] = "first-party-release"
        matrix["appSubjectsDigest"] = api1x._matrix_app_subjects_digest(matrix)
        _seal(matrix, "matrixDigest")

        findings = api1x._matrix_errors(
            matrix,
            False,
            self.fixture.contract,
            None,
            self.fixture.ledger_value,
            self.fixture.baseline_registry_value,
            self.fixture.history_subjects,
        )

        self.assertIn(
            "operational app matrix lacks an authenticated app subject inventory", findings
        )

    def test_runtime_whenSnapshotOrAppSubjectsDiffer_expectHistoryAndMatrixFindings(self) -> None:
        observation = {
            "schemaVersion": 1,
            "kind": "platform-api-1.x-runtime-observation",
            "observationId": "fixture-observation",
            "releaseId": "fixture-release-23",
            "buildVersion": 23,
            "sourceCommit": SOURCE,
            "releaseRootDigest": "sha256:" + "1" * 64,
            "contractVersion": 23,
            "contractSnapshotDigest": "sha256:" + "8" * 64,
            "appSubjectsDigest": "sha256:" + "9" * 64,
            "baselineIds": ["1.0"],
            "workflowPath": ".github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml",
            "runId": 1,
            "runAttempt": 1,
            "startedAt": "2026-09-01T00:00:00Z",
            "completedAt": "2026-09-01T00:01:00Z",
            "status": "pass",
            "partial": False,
            "fixtureOnly": True,
            "longDurationSoak": False,
            "representativeChecks": [
                "app.start",
                "platform.contract.read",
                "stable-endpoint.subset",
                "cleanup.restored",
            ],
            "authorizationFailureChecks": [
                "capability.denied",
                "operator-route.denied",
            ],
            "observationDigest": ZERO,
        }
        _seal(observation, "observationDigest")

        findings = api1x._runtime_errors(
            observation,
            self.fixture.contract,
            True,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
            self.fixture.ledger_value,
            self.fixture.matrix_value,
        )

        self.assertIn(
            "runtime observation contract snapshot differs from accepted history", findings
        )
        self.assertIn(
            "runtime observation app subjects differ from the accepted matrix", findings
        )
        self.assertIn(
            "operational runtime observation lacks an authenticated protected producer",
            api1x._runtime_errors(
                observation,
                self.fixture.contract,
                False,
                api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
                api1x._policy(workspace_root())[0],
                self.fixture.ledger_value,
                self.fixture.matrix_value,
            ),
        )

    def test_supportLifecycle_whenOperationalAuthorityIsAbsent_expectBlocked(self) -> None:
        contract = copy.deepcopy(self.fixture.contract)
        contract["fixtureOnly"] = False
        contract["selfTest"] = False

        selected, findings = api1x._support_lifecycle_errors(
            contract,
            self.fixture.evidence,
            self.fixture.ledger_value,
            False,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertIsNone(selected)
        self.assertIn(
            "operational oldest-supported selection requires authenticated support-lifecycle evidence",
            findings,
        )

    def test_supportLifecycle_whenProtectedReceiptSelectsMinimumBuild_expectDerivedRecord(self) -> None:
        record = self.fixture.ledger_value["records"][0]
        lifecycle_digest = "sha256:" + "2" * 64
        descriptor = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-descriptor",
            "stableMilestone": "1.0",
            "descriptorEdition": 1,
            "updateKeyIdentityDigest": "sha256:" + "3" * 64,
            "updateKeyScope": "sha256:" + "3" * 64 + "/support-lifecycle/0",
            "updateKeyDocName": "support-lifecycle",
            "generatedAt": "2026-08-31T00:00:00Z",
            "effectiveAt": "2026-08-31T00:00:00Z",
            "staleAt": "2026-09-02T00:00:00Z",
            "ledgerDigest": lifecycle_digest,
            "inventoryDigest": "sha256:" + "4" * 64,
            "currentStableBuild": str(record["buildVersion"]),
            "minimumSupportedBuild": str(record["buildVersion"]),
            "minimumSecuritySupportedBuild": str(record["buildVersion"]),
            "recommendedBuild": None,
            "entries": [
                {
                    "releaseId": record["releaseId"],
                    "buildVersion": str(record["buildVersion"]),
                    "tag": "v22",
                    "sourceCommit": record["sourceCommit"],
                    "productDigest": record["releaseRootDigest"],
                    "publicationReceiptDigest": "sha256:" + "5" * 64,
                    "baselineDigest": "sha256:" + "6" * 64,
                    "publishedAt": "2026-08-30T00:00:00Z",
                    "lifecycleStatus": "current-stable",
                    "statusEffectiveAt": "2026-08-31T00:00:00Z",
                    "fullSupportUntil": "2026-09-10T00:00:00Z",
                    "securityFixesUntil": "2026-09-20T00:00:00Z",
                    "deprecationEffectiveAt": "2026-09-11T00:00:00Z",
                    "endOfSupportAt": "2026-09-21T00:00:00Z",
                    "securityRevocationEffectiveAt": None,
                    "replacementBuild": None,
                    "recoveryGuidance": None,
                    "advisoryIds": [],
                    "reasonCodes": [],
                }
            ],
            "previousDescriptorEdition": None,
            "previousDescriptorDigest": None,
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
        descriptor["descriptorDigest"] = api1x._descriptor_semantic_digest(descriptor)
        descriptor_path = self.fixture.evidence / "support-lifecycle-descriptor.json"
        write_json(descriptor_path, descriptor)
        descriptor_binding = _binding(descriptor_path)
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-publication-receipt",
            "generatedAt": "2026-09-01T00:00:00Z",
            "stableMilestone": "1.0",
            "descriptorEdition": 1,
            "descriptorDigest": descriptor["descriptorDigest"],
            "descriptorBytesDigest": descriptor_binding["digest"],
            "ledgerDigest": lifecycle_digest,
            "updateKeyIdentityDigest": descriptor["updateKeyIdentityDigest"],
            "updateKeyScope": descriptor["updateKeyScope"],
            "updateKeyDocName": "support-lifecycle",
            "publicRequestUri": "https://example.invalid/support-lifecycle.json",
            "previousDescriptorEdition": None,
            "previousDescriptorDigest": None,
            "publicationPlanDigest": "sha256:" + "7" * 64,
            "authorizationDigest": "sha256:" + "8" * 64,
            "operation": "verified-existing",
            "publicationState": "publication-complete",
            "verificationStatus": "verified",
            "conflict": False,
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }
        receipt_path = self.fixture.evidence / (
            "stable-1.0-support-lifecycle-independent-verification-receipt.json"
        )
        write_json(receipt_path, receipt)
        receipt_binding = _binding(receipt_path)
        contract = copy.deepcopy(self.fixture.contract)
        contract["evidence"]["supportLifecycleDescriptor"] = descriptor_binding
        artifact_digest = "sha256:" + "9" * 64
        contract["supportLifecycleAuthority"] = {
            "summaryDigest": receipt_binding["digest"],
            "artifactDigest": artifact_digest,
            "operational": True,
            "provenance": {
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-support-lifecycle.yml",
                "workflowCommit": SOURCE,
                "runId": 10,
                "runAttempt": 2,
                "artifactName": "stable-1-0-lifecycle-verification-fixture-release-23-10-2",
                "artifactDigest": artifact_digest,
                "environment": "stable-1.0-lifecycle-evidence",
                "conclusion": "success",
            },
            "summary": receipt_binding,
        }

        selected, findings = api1x._support_lifecycle_errors(
            contract,
            self.fixture.evidence,
            self.fixture.ledger_value,
            False,
            api1x._timestamp("2026-09-01T00:02:00Z", "evaluation"),
            api1x._policy(workspace_root())[0],
        )

        self.assertEqual([], findings)
        self.assertEqual(record["selfDigest"], selected["selfDigest"])

    def test_matrixVerification_whenCurrentDeprecationSchemaIsInvalid_expectParseFindingPreserved(self) -> None:
        invalid = read_json(self.fixture.evidence / "deprecations.json")
        del invalid["entries"]
        write_json(self.fixture.evidence / "deprecations.json", invalid)
        self.fixture.contract["evidence"]["deprecationLedger"] = _binding(
            self.fixture.evidence / "deprecations.json"
        )
        self.fixture.rewrite_contract()

        result = api1x.run(
            workspace_root(),
            self.fixture.contract_path,
            "verify-app-matrix",
            self.root / "out",
            self.fixture.evidence,
        )

        self.assertEqual(1, result)
        summary = read_json(self.root / "out" / api1x.SUMMARY_FILE)
        self.assertTrue(
            any(
                "deprecation ledger" in item and "omits required field entries" in item
                for item in summary["blockers"]
            )
        )

    def test_closeout_whenEvidenceContainsUnboundMember_expectPartial(self) -> None:
        write_json(self.fixture.evidence / "raw-manifest.json", {"app": "unbound"})

        result = api1x.run(
            workspace_root(), self.fixture.contract_path, "closeout", self.root / "out", self.fixture.evidence
        )

        self.assertEqual(1, result)
        summary = read_json(self.root / "out" / api1x.SUMMARY_FILE)
        self.assertIn("unexpected evidence member raw-manifest.json", summary["blockers"])
        self.assertFalse(summary["operational"])


if __name__ == "__main__":
    unittest.main()
