"""Durable source-lineage activation tests for PR-290."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptad_certification.tests.test_stable_dependency_vulnerability_workflows import (
    lineage,
    osv_inventory_anchor,
)


class DependencyIntelligenceLineageActivationTest(unittest.TestCase):
    def test_finalizeBatch_whenPairPreparedOrPartlySuperseded_expectAtomicWriteOrNoOp(
        self,
    ) -> None:
        artifact_map = {
            source_id: {
                "sourceName": f"source-{source_id}",
                "sourceDigest": "sha256:" + digit * 64,
                "proposalName": f"proposal-{source_id}",
                "proposalDigest": "sha256:" + str(int(digit) + 3) * 64,
            }
            for source_id, digit in (
                ("github-public-advisories", "1"),
                ("osv-public", "2"),
            )
        }
        current = json.loads(lineage._SET_GENESIS.read_text(encoding="utf-8"))
        arguments = argparse.Namespace(
            repository="crypta-network/cryptad",
            artifact_map=Path("artifact-map.json"),
            root=Path("root"),
            workflow_commit="a" * 40,
            run_id=12,
            run_attempt=1,
            event="schedule",
            activated_at="2026-08-13T00:00:00Z",
        )

        def load(path: Path, _limit: int = 0) -> dict[str, object]:
            if path == lineage._POLICY:
                return {"policyDigest": current["policyDigest"]}
            if path in lineage._GENESIS.values():
                return json.loads(path.read_text(encoding="utf-8"))
            if path == arguments.artifact_map:
                return artifact_map
            source_id = next(
                source
                for source in artifact_map
                if artifact_map[source]["proposalName"] in path.parts
            )
            coordinates = artifact_map[source_id]
            return {
                "sourceId": source_id,
                "sourceArtifactName": coordinates["sourceName"],
                "sourceArtifactDigest": coordinates["sourceDigest"],
                "proposalArtifactName": coordinates["proposalName"],
            }

        def finalization(
            _arguments: argparse.Namespace,
            proposal: dict[str, object],
            *_coordinates: object,
        ) -> argparse.Namespace:
            source_id = str(proposal["sourceId"])
            coordinates = artifact_map[source_id]
            return argparse.Namespace(
                source_id=source_id,
                expected_anchor_digest=current["lineages"][
                    list(artifact_map).index(source_id)
                ]["anchorDigest"],
                workflow_commit="a" * 40,
                run_id=12,
                run_attempt=1,
                artifact_name=coordinates["sourceName"],
                artifact_digest=coordinates["sourceDigest"],
            )

        with mock.patch.object(lineage, "_load", side_effect=load), mock.patch.object(
            lineage, "_read_set", return_value=current
        ), mock.patch.object(
            lineage, "_finalization_arguments", side_effect=finalization
        ), mock.patch.object(
            lineage,
            "_successor",
            side_effect=lambda activation, anchor: {
                **anchor,
                "sourceId": activation.source_id,
            },
        ), mock.patch.object(lineage, "_write_set") as write:
            lineage._finalize_batch(arguments)

        write.assert_called_once()
        written = write.call_args.args[1]
        self.assertEqual(1, written["setEdition"])
        self.assertEqual(
            list(lineage._SOURCE_IDS),
            [row["sourceId"] for row in written["lineages"]],
        )

        with mock.patch.object(lineage, "_load", side_effect=load), mock.patch.object(
            lineage, "_read_set", return_value=current
        ), mock.patch.object(
            lineage, "_finalization_arguments", side_effect=finalization
        ), mock.patch.object(
            lineage,
            "_successor",
            side_effect=(current["lineages"][0], lineage.LineageError("second-invalid")),
        ), mock.patch.object(lineage, "_write_set") as failed_write, self.assertRaisesRegex(
            lineage.LineageError, "second-invalid"
        ):
            lineage._finalize_batch(arguments)

        failed_write.assert_not_called()

        replay = json.loads(json.dumps(current))
        for source_id, coordinates in artifact_map.items():
            anchor = next(
                row for row in replay["lineages"] if row["sourceId"] == source_id
            )
            anchor.update(
                producerWorkflow=lineage._WORKFLOW,
                workflowCommit="a" * 40,
                runId=12,
                runAttempt=1,
                artifactName=coordinates["sourceName"],
                artifactDigest=coordinates["sourceDigest"],
            )
        with mock.patch.object(lineage, "_load", side_effect=load), mock.patch.object(
            lineage, "_read_set", return_value=replay
        ), mock.patch.object(
            lineage, "_finalization_arguments", side_effect=finalization
        ), mock.patch.object(lineage, "_successor") as replay_successor, mock.patch.object(
            lineage, "_write_set"
        ) as replay_write:
            lineage._finalize_batch(arguments)

        replay_successor.assert_not_called()
        replay_write.assert_not_called()

        partially_superseded = json.loads(json.dumps(current))
        github_anchor = next(
            row
            for row in partially_superseded["lineages"]
            if row["sourceId"] == "github-public-advisories"
        )
        github_anchor.update(
            producerWorkflow=lineage._WORKFLOW,
            workflowCommit="b" * 40,
            runId=99,
            runAttempt=1,
            artifactName="source-github-public-advisories-99-1",
            artifactDigest="sha256:" + "f" * 64,
            anchorDigest="sha256:" + "e" * 64,
        )
        with mock.patch.object(lineage, "_load", side_effect=load), mock.patch.object(
            lineage, "_read_set", return_value=partially_superseded
        ), mock.patch.object(
            lineage, "_finalization_arguments", side_effect=finalization
        ), mock.patch.object(
            lineage,
            "_successor",
            side_effect=lambda activation, anchor: {
                **anchor,
                "sourceId": activation.source_id,
            },
        ) as partial_successor, mock.patch.object(
            lineage, "_write_set"
        ) as partial_write:
            lineage._finalize_batch(arguments)

        self.assertEqual(1, partial_successor.call_count)
        partial_write.assert_not_called()

    def test_inventoryFinalize_whenLatestProposalAlreadyCurrent_expectNoMutation(
        self,
    ) -> None:
        current_artifact = {
            "workflow": osv_inventory_anchor._RETENTION_WORKFLOW,
            "workflowCommit": "a" * 40,
            "runId": 12,
            "runAttempt": 1,
            "artifactName": "stable-1-0-dependency-osv-inventory-retention-12-1",
            "artifactDigest": "sha256:" + "1" * 64,
        }
        arguments = argparse.Namespace(
            repository="crypta-network/cryptad",
            mode="renew",
            workflow_commit=current_artifact["workflowCommit"],
            run_id=current_artifact["runId"],
            run_attempt=current_artifact["runAttempt"],
            artifact_name=current_artifact["artifactName"],
            artifact_digest=current_artifact["artifactDigest"],
        )

        with mock.patch.object(
            osv_inventory_anchor,
            "_read",
            return_value={"currentArtifact": current_artifact},
        ), mock.patch.object(
            osv_inventory_anchor, "_artifact_metadata", return_value={}
        ) as metadata:
            osv_inventory_anchor._advance_command(arguments)

        metadata.assert_called_once()

    def test_activate_whenCompleteContentIsUnchanged_expectNewRunAndAuditedStatus(self) -> None:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        timestamp = now.isoformat().replace("+00:00", "Z")
        anchor = json.loads(lineage._GENESIS["osv-public"].read_text(encoding="utf-8"))
        anchor.update(
            {
                "initialized": True,
                "anchorSequence": 1,
                "sourceSnapshotDigest": "sha256:" + "1" * 64,
                "rawContentDigest": "sha256:" + "2" * 64,
                "canonicalRecordSetDigest": "sha256:" + "3" * 64,
                "componentInventoryDigest": "sha256:" + "4" * 64,
                "retrievedAt": timestamp,
                "previousAnchorDigest": anchor["anchorDigest"],
                "producerWorkflow": lineage._WORKFLOW,
                "workflowCommit": "a" * 40,
                "runId": 10,
                "runAttempt": 1,
                "artifactName": "stable-1-0-dependency-intelligence-osv-public-10-1",
                "artifactDigest": "sha256:" + "5" * 64,
                "contentStatus": "changed",
                "retrievalValidation": "complete-200-response",
                "activatedAt": timestamp,
            }
        )
        anchor["anchorDigest"] = lineage._semantic(anchor, "anchorDigest")
        source = {
            "sourceEdition": 2,
            "sourceSnapshotDigest": "sha256:" + "6" * 64,
            "rawContentDigest": anchor["rawContentDigest"],
            "canonicalRecordSetDigest": anchor["canonicalRecordSetDigest"],
            "componentInventoryDigest": anchor["componentInventoryDigest"],
            "retrievedAt": timestamp,
            "expiresAt": (now + dt.timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        written: dict[str, object] = {}
        current = json.loads(lineage._SET_GENESIS.read_text(encoding="utf-8"))
        current["lineages"] = [
            anchor if row["sourceId"] == "osv-public" else row
            for row in current["lineages"]
        ]
        current["setDigest"] = lineage._semantic(current, "setDigest")

        def read_set(_repository: str, _token: str) -> dict[str, object]:
            return written.get("successor", current)  # type: ignore[return-value]

        def github(_token: str, arguments: list[str]) -> bytes:
            if "PATCH" in arguments:
                value = next(row.removeprefix("value=") for row in arguments if row.startswith("value="))
                written["successor"] = json.loads(value)
            return b"{}"

        arguments = argparse.Namespace(
            repository="crypta-network/cryptad",
            source_id="osv-public",
            expected_anchor_digest=anchor["anchorDigest"],
            source_record=Path("source.json"),
            provenance=Path("provenance.json"),
            manifest=Path("manifest.json"),
            workflow_commit="b" * 40,
            run_id=11,
            run_attempt=2,
            artifact_name="stable-1-0-dependency-intelligence-osv-public-11-2",
            artifact_digest="sha256:" + "7" * 64,
            activated_at=timestamp,
        )
        with (
            mock.patch.object(lineage, "_read_set", side_effect=read_set),
            mock.patch.object(lineage, "_authenticate_artifact"),
            mock.patch.object(lineage, "_bundle", return_value=source),
            mock.patch.object(lineage, "_gh", side_effect=github),
        ):
            lineage._activate(arguments)

        successor_set = written["successor"]
        successor = next(
            row
            for row in successor_set["lineages"]
            if row["sourceId"] == "osv-public"
        )
        self.assertEqual("unchanged-full-retrieval", successor["contentStatus"])
        self.assertEqual("complete-200-response", successor["retrievalValidation"])
        self.assertEqual(11, successor["runId"])
        self.assertEqual(2, successor["runAttempt"])
        self.assertEqual(anchor["anchorDigest"], successor["previousAnchorDigest"])
        self.assertNotEqual(anchor["sourceSnapshotDigest"], successor["sourceSnapshotDigest"])
        self.assertEqual(current["setEdition"] + 1, successor_set["setEdition"])

    def test_authenticateArtifact_whenProducerNotCompletedSuccessfully_expectReject(
        self,
    ) -> None:
        arguments = argparse.Namespace(
            repository="crypta-network/cryptad",
            workflow_commit="a" * 40,
            run_id=11,
            run_attempt=2,
            artifact_name="stable-1-0-dependency-intelligence-osv-public-11-2",
            artifact_digest="sha256:" + "7" * 64,
        )
        artifact_pages = [{"artifacts": [{"name": arguments.artifact_name, "digest": arguments.artifact_digest, "expired": False, "workflow_run": {"id": arguments.run_id}}]}]
        for status, conclusion in (
            ("in_progress", None),
            ("completed", "failure"),
            ("completed", "cancelled"),
        ):
            run = {
                "id": arguments.run_id,
                "run_attempt": arguments.run_attempt,
                "path": lineage._WORKFLOW,
                "head_sha": arguments.workflow_commit,
                "head_repository": {"full_name": "crypta-network/cryptad"},
                "event": "schedule",
                "status": status,
                "conclusion": conclusion,
            }
            with self.subTest(status=status, conclusion=conclusion), mock.patch.object(
                lineage,
                "_gh",
                side_effect=(lineage._canonical(run), lineage._canonical(artifact_pages)),
            ), self.assertRaisesRegex(
                lineage.LineageError,
                "dependency-intelligence-lineage-run-invalid",
            ):
                lineage._authenticate_artifact(arguments)

    def test_authenticateArtifact_whenOverallProducerCompletedSuccessfully_expectPass(
        self,
    ) -> None:
        arguments = argparse.Namespace(
            repository="crypta-network/cryptad",
            workflow_commit="a" * 40,
            run_id=11,
            run_attempt=2,
            artifact_name="stable-1-0-dependency-intelligence-osv-public-11-2",
            artifact_digest="sha256:" + "7" * 64,
        )
        run = {
            "id": arguments.run_id,
            "run_attempt": arguments.run_attempt,
            "path": lineage._WORKFLOW,
            "head_sha": arguments.workflow_commit,
            "head_repository": {"full_name": "crypta-network/cryptad"},
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
        }
        artifact_pages = [{"artifacts": [{"name": arguments.artifact_name, "digest": arguments.artifact_digest, "expired": False, "workflow_run": {"id": arguments.run_id}}]}]

        with mock.patch.object(
            lineage,
            "_gh",
            side_effect=(lineage._canonical(run), lineage._canonical(artifact_pages)),
        ):
            lineage._authenticate_artifact(arguments)

    def test_activationProposal_whenCompletedArtifactFinalized_expectExactBindings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            source_record = source_root / "stable-1.0-dependency-intelligence-source.json"
            provenance = source_root / "stable-1.0-dependency-intelligence-provenance.json"
            manifest = source_root / "producer-manifest.json"
            for path, content in (
                (source_record, b'{"source":true}\n'),
                (provenance, b'{"provenance":true}\n'),
                (manifest, b'{"manifest":true}\n'),
            ):
                path.write_bytes(content)
            predecessor = root / "predecessor.json"
            anchor = json.loads(lineage._GENESIS["osv-public"].read_text(encoding="utf-8"))
            predecessor.write_bytes(lineage._canonical(anchor))
            source_name = "stable-1-0-dependency-intelligence-osv-public-11-2"
            proposal_name = "stable-1-0-dependency-intelligence-activation-proposal-osv-public-11-2"
            proposal_path = root / "proposal" / lineage._PROPOSAL_FILE
            write_arguments = argparse.Namespace(
                source_id="osv-public",
                expected_anchor_digest=anchor["anchorDigest"],
                predecessor=predecessor,
                source_record=source_record,
                provenance=provenance,
                manifest=manifest,
                workflow_commit="a" * 40,
                run_id=11,
                run_attempt=2,
                source_artifact_name=source_name,
                source_artifact_digest="sha256:" + "7" * 64,
                proposal_artifact_name=proposal_name,
                out=proposal_path,
            )
            with mock.patch.object(lineage, "_bundle"):
                lineage._write_proposal(write_arguments)
            proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
            self.assertEqual([], lineage._proposal_errors(proposal))
            self.assertEqual(lineage._byte_digest(source_record), proposal["sourceRecordByteDigest"])
            invalid_proposal = dict(proposal)
            invalid_proposal["sourceId"] = []
            self.assertIn(
                "dependency-intelligence-lineage-proposal-identity-invalid",
                lineage._proposal_errors(invalid_proposal),
            )

            finalize_arguments = argparse.Namespace(
                repository="crypta-network/cryptad",
                proposal=proposal_path,
                root=source_root,
                workflow_commit="a" * 40,
                run_id=11,
                run_attempt=2,
                proposal_artifact_name=proposal_name,
                proposal_artifact_digest="sha256:" + "8" * 64,
                activated_at="2026-08-13T00:00:00Z",
            )
            with mock.patch.object(
                lineage, "_authenticate_artifact"
            ) as authenticate, mock.patch.object(lineage, "_activate") as activate:
                lineage._finalize(finalize_arguments)

            self.assertEqual(proposal_name, authenticate.call_args.args[0].artifact_name)
            self.assertEqual(source_name, activate.call_args.args[0].artifact_name)
            self.assertEqual(proposal["sourceArtifactDigest"], activate.call_args.args[0].artifact_digest)


if __name__ == "__main__":
    unittest.main()
