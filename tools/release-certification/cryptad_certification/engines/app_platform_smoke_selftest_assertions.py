"""Implementation segment for the selftest assertions portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def assert_maintenance_policy_evidence_redacts_invalid_values() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-maintenance-policy-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_path = workspace / FIRST_PARTY_MAINTENANCE_POLICY_PATH
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        app_policy = policy["apps"]["queue-manager"]
        app_policy["channel"] = str(workspace / "private-channel-token.txt")
        app_policy["supportStatus"] = "token=status-secret"
        app_policy["deprecationStatus"] = "USK@PRIVATE-DEPRECATION"
        maintenance = app_policy["maintenance"]
        maintenance["owner"] = "crypta-core token=owner-secret"
        maintenance["ownerUri"] = (
            "https://example.invalid/crypta/owners/core?token=owner-uri-secret"
        )
        maintenance["supportUri"] = str(workspace / "private-support-token.txt")
        maintenance["securityPolicy"] = "token=security-secret"
        write_json(policy_path, policy)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_first_party_maintenance_policy_evidence(settings)
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert "<redacted>" in encoded, encoded
        for forbidden in (
            "owner-secret",
            "owner-uri-secret",
            "private-support-token.txt",
            "security-secret",
            "private-channel-token.txt",
            "status-secret",
            "PRIVATE-DEPRECATION",
            str(workspace),
        ):
            assert forbidden not in encoded, f"maintenance evidence leaked {forbidden}: {encoded}"

def assert_maintenance_policy_evidence_rejects_redacted_uri_values() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-maintenance-policy-uri-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_path = workspace / FIRST_PARTY_MAINTENANCE_POLICY_PATH
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["apps"]["queue-manager"]["maintenance"]["supportUri"] = (
            "https://example.invalid/crypta/apps/queue-manager/support?token=support-uri-secret"
        )
        write_json(policy_path, policy)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_first_party_maintenance_policy_evidence(settings)
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert "queue-manager: urisAreMetadataOnly" in encoded, encoded
        assert "queue-manager: maintenanceEvidenceValuesSafe" in encoded, encoded
        assert "support-uri-secret" not in encoded, encoded

def assert_maintenance_policy_evidence_rejects_allowed_policy_drift() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-maintenance-policy-drift-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        policy_path = workspace / FIRST_PARTY_MAINTENANCE_POLICY_PATH
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        maintenance = policy["apps"]["queue-manager"]["maintenance"]
        maintenance["securityPolicy"] = "unsupported"
        maintenance["deprecationPolicy"] = "security-only"
        write_json(policy_path, policy)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_first_party_maintenance_policy_evidence(settings)
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert "queue-manager: policyMatchesExpectedAppClass" in encoded, encoded
        assert '"securityPolicy": "unsupported"' in encoded, encoded
        assert '"deprecationPolicy": "security-only"' in encoded, encoded

def first_party_beta_quality_settings(workspace: Path) -> Settings:
    return Settings(
        workspace_root=workspace.resolve(),
        out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
        mode="release-candidate",
        skip_gradle=True,
        cli_path=None,
        live=False,
        live_base_url="",
        live_form_password="",
        timeout_seconds=60,
    )

def assert_first_party_beta_quality_rejects_missing_metadata() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-metadata-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        readiness_path = workspace / FIRST_PARTY_BETA_READINESS_PATH
        readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
        del readiness["apps"]["queue-manager"]
        write_json(readiness_path, readiness)

        item = collect_first_party_beta_quality_evidence(
            first_party_beta_quality_settings(workspace)
        )
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "fail", item
        assert "allFirstPartyAppsCovered" in encoded, encoded
        assert "queue-manager: readinessEntryPresent" in encoded, encoded

def assert_first_party_beta_quality_rejects_unknown_readiness_metadata_without_leak() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-readiness-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        readiness_path = workspace / FIRST_PARTY_BETA_READINESS_PATH
        readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
        beta_readiness = readiness["apps"]["feed-reader"]["betaReadiness"]
        beta_readiness["supportNote"] = "tainted-readiness-token-123456789012"
        beta_readiness["diagnostics"] = "tainted-readiness-token-123456789012"
        write_json(readiness_path, readiness)

        item = collect_first_party_beta_quality_evidence(
            first_party_beta_quality_settings(workspace)
        )
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "fail", item
        assert "feed-reader: readinessFieldsClosed" in encoded, encoded
        assert "feed-reader: readinessValuesMatchExpected" in encoded, encoded
        assert "supportNote" not in encoded, encoded
        assert "tainted-readiness-token" not in encoded, encoded
        assert '"diagnostics": "<invalid>"' in encoded, encoded

def assert_first_party_beta_quality_rejects_missing_empty_state_marker() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-ui-marker-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        index_path = workspace / "apps/queue-manager/src/staged/static/index.html"
        index_path.write_text(
            index_path.read_text(encoding="utf-8").replace("data-beta-empty-state ", ""),
            encoding="utf-8",
        )

        item = collect_first_party_beta_quality_evidence(
            first_party_beta_quality_settings(workspace)
        )
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "fail", item
        assert "queue-manager: uiReadinessMarkersPresent" in encoded, encoded

def assert_first_party_beta_quality_rejects_sensitive_diagnostics() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        readme_path = workspace / "apps/feed-reader/README.md"
        readme_path.write_text(
            readme_path.read_text(encoding="utf-8")
            + "\nSupport authorization: Bearer tainted-support-token-123456789012\n",
            encoding="utf-8",
        )

        item = collect_first_party_beta_quality_evidence(
            first_party_beta_quality_settings(workspace)
        )
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "fail", item
        assert "redactionFindings" in encoded, encoded
        assert "tainted-support-token" not in encoded, encoded

def assert_first_party_beta_quality_rejects_sensitive_static_assets() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-static-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        app_js_path = workspace / "apps/feed-reader/src/staged/static/app.js"
        app_js_path.write_text(
            app_js_path.read_text(encoding="utf-8")
            + "\nconst supportHeader = 'Bearer tainted-static-token-123456789012';\n"
            + "const launchSecret = 'CRYPTAD_APP_TOKEN=tainted-static-token-123456789012';\n",
            encoding="utf-8",
        )
        app_css_path = workspace / "apps/feed-reader/src/staged/static/app.css"
        app_css_path.write_text(
            app_css_path.read_text(encoding="utf-8")
            + "\n/* support bundle path: /etc/cryptad/node.conf */\n",
            encoding="utf-8",
        )

        item = collect_first_party_beta_quality_evidence(
            first_party_beta_quality_settings(workspace)
        )
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "fail", item
        assert "redactionFindings" in encoded, encoded
        assert "static/app.js" in encoded, encoded
        assert "static/app.css" in encoded, encoded
        assert "tainted-static-token" not in encoded, encoded
        assert "/etc/cryptad/node.conf" not in encoded, encoded

def assert_first_party_beta_quality_rejects_sensitive_manifest_metadata() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-manifest-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        manifest_path = workspace / "apps/feed-reader/src/staged/cryptad-app.properties.template"
        manifest_path.write_text(
            manifest_path.read_text(encoding="utf-8")
            + "\npermissions.rationale.support=Authorization: Basic tainted-basic-token\n"
            + "app.beta.support.note=formPassword=hunter2\n",
            encoding="utf-8",
        )

        item = collect_first_party_beta_quality_evidence(
            first_party_beta_quality_settings(workspace)
        )
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "fail", item
        assert "redactionFindings" in encoded, encoded
        assert "cryptad-app.properties.template" in encoded, encoded
        assert "tainted-basic-token" not in encoded, encoded
        assert "hunter2" not in encoded, encoded

def assert_first_party_beta_quality_redaction_handles_insert_uri_examples() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-beta-quality-uri-redaction-") as temp_name:
        workspace = Path(temp_name) / "repo"
        source = workspace / "apps/trust-graph/src/staged/static/index.html"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "\n".join(
                (
                    'placeholder="USK@publisher/trust/0/trust.json"',
                    'placeholder="crypta:USK@source-key/social/0/social-outbox.json"',
                    "",
                )
            ),
            encoding="utf-8",
        )

        assert first_party_beta_redaction_findings("trust-graph", workspace, (source,)) == []

        source.write_text(
            '{"privateInsertUri":"USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0"}\n',
            encoding="utf-8",
        )
        findings = first_party_beta_redaction_findings("trust-graph", workspace, (source,))

        assert findings == [
            {
                "appId": "trust-graph",
                "kind": "private-insert-uri",
                "source": "<repo>/apps/trust-graph/src/staged/static/index.html",
            }
        ], findings

def assert_security_response_drill_verify_rejects_sensitive_artifacts(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    tainted_values = (
        "Bearer tainted-token",
        "Authorization: Basic tainted-token",
        "x-crypta-app-session: tainted-token",
        "bearer tainted-token",
        "rawAppData: private-app-record",
        "local path /var/lib/crypta/private.json",
        "content key crypta:USK@fetched-evidence/0/report.json",
    )
    for tainted_value in tainted_values:
        assert_security_response_drill_verify_rejects_sensitive_artifact(verifier, tainted_value)

def assert_security_response_drill_verify_rejects_sensitive_json_keys(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    sensitive_fields = (
        ("authorizationHeader", "private-auth-header"),
        ("rawAppData", "private-app-record"),
        ("rawAppDataSource", "private-app-record-source"),
        ("rawAppDataStatus", "private-app-record-status"),
        ("rawFetchedContent", "private-fetched-record"),
        ("token", "tainted-token"),
        ("tokenStatus", "tainted-token-status"),
    )
    for key, value in sensitive_fields:
        assert_security_response_drill_verify_rejects_sensitive_json_key(verifier, key, value)

def assert_security_response_drill_verify_allows_boolean_redaction_metadata(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    with tempfile.TemporaryDirectory(prefix="cryptad-security-drill-boolean-metadata-") as temp_name:
        artifact_path = Path(temp_name) / "support-bundle-intake-redaction.json"
        artifact = {
            "schemaVersion": 1,
            "kind": "cryptad-security-response-drill",
            "scenario": "support-bundle-intake-redaction",
            "rawAppDataPresent": True,
            "rawAppDataRedacted": True,
            "drill": {
                "id": "support-bundle-intake-redaction",
                "severity": "medium",
                "trigger": "operator sends security incident support evidence",
                "containmentActions": ["quarantine inbound support bundle"],
                "catalogActions": ["record no catalog mutation required"],
                "reviewActions": ["record no review mutation required"],
                "operatorActions": ["show support bundle redaction status"],
                "schedulerExpectations": ["continue safe update checks"],
                "redactionRequirements": ["omit raw app data"],
                "verificationEvidence": ["production-security.support-redaction"],
                "releaseNotesTemplate": "support bundle note and redaction note",
                "rawAppDataPresent": True,
                "rawAppDataRedacted": True,
            },
        }
        artifact_path.write_text(json.dumps(artifact, sort_keys=True) + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "drill",
                "verify",
                "--input",
                str(artifact_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "pass", parsed
    assert parsed["ok"] is True, parsed
    assert parsed["redactionClean"] is True, parsed

def assert_security_response_runbook_verify_rejects_sensitive_text_assignments(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    with tempfile.TemporaryDirectory(prefix="cryptad-security-runbook-text-") as temp_name:
        temp_dir = Path(temp_name)
        runbook = temp_dir / "production-security-response-runbook.md"
        model = temp_dir / "production-security-response-runbook.json"
        template = temp_dir / "security-release-notes.md"
        shutil.copyfile(repo_root / "docs/production-security-response-runbook.md", runbook)
        shutil.copyfile(
            repo_root / "tools/release-certification/production-security-response-runbook.json",
            model,
        )
        shutil.copyfile(repo_root / "docs/templates/security-release-notes.md", template)
        runbook.write_text(
            runbook.read_text(encoding="utf-8")
            + "\nauthorizationHeader=private-auth-header\n"
            + "ciSecretValue=ci-secret-value\n"
            + "rawFetchedContent=private-fetched-record\n"
            + "localEvidencePath=/var/lib/crypta/private.json\n"
            + "privateInsertUri=crypta:USK@fetched-evidence/0/report.json\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "verify",
                "--runbook",
                str(runbook),
                "--model",
                str(model),
                "--template",
                str(template),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode != 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "fail", parsed
    assert parsed["checks"]["redactionClean"] is False, parsed
    assert "redactionClean" in parsed["errors"], parsed
    for forbidden_value in (
        "private-auth-header",
        "ci-secret-value",
        "private-fetched-record",
        "/var/lib/crypta/private.json",
        "crypta:USK@fetched-evidence",
    ):
        assert forbidden_value not in result.stdout, result.stdout

def assert_security_response_runbook_verify_allows_boolean_redaction_metadata(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    with tempfile.TemporaryDirectory(prefix="cryptad-security-runbook-boolean-metadata-") as temp_name:
        temp_dir = Path(temp_name)
        runbook = temp_dir / "production-security-response-runbook.md"
        model = temp_dir / "production-security-response-runbook.json"
        template = temp_dir / "security-release-notes.md"
        shutil.copyfile(repo_root / "docs/production-security-response-runbook.md", runbook)
        shutil.copyfile(
            repo_root / "tools/release-certification/production-security-response-runbook.json",
            model,
        )
        shutil.copyfile(repo_root / "docs/templates/security-release-notes.md", template)
        loaded_model = json.loads(model.read_text(encoding="utf-8"))
        loaded_model["drills"][0]["rawAppDataPresent"] = True
        loaded_model["drills"][0]["rawAppDataRedacted"] = True
        write_json(model, loaded_model)
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "verify",
                "--runbook",
                str(runbook),
                "--model",
                str(model),
                "--template",
                str(template),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "pass", parsed
    assert parsed["checks"]["modelValid"] is True, parsed
    assert parsed["checks"]["redactionClean"] is True, parsed

def assert_security_response_drill_verify_rejects_sensitive_json_key(
    verifier: Path,
    key: str,
    value: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-drill-json-key-") as temp_name:
        tainted_artifact = Path(temp_name) / "reviewer-key-compromise.json"
        artifact = {
            "schemaVersion": 1,
            "kind": "cryptad-security-response-drill",
            "scenario": "reviewer-key-compromise",
            key: value,
            "drill": {
                "id": "reviewer-key-compromise",
                "severity": "high",
                "trigger": "reviewer key compromise drill",
                "containmentActions": ["mark reviewer key revoked"],
                "catalogActions": ["publish affected app advisories"],
                "reviewActions": ["revoke exact receipt fingerprints"],
                "operatorActions": ["show reviewer key revoked"],
                "schedulerExpectations": ["fail revoked-reviewer receipts closed"],
                "redactionRequirements": ["omit reviewer private keys"],
                "verificationEvidence": ["app-review.reviewer-key-compromise-flow"],
                "releaseNotesTemplate": "reviewer key id and replacement review status",
            },
        }
        tainted_artifact.write_text(json.dumps(artifact, sort_keys=True) + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "drill",
                "verify",
                "--input",
                str(tainted_artifact),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode != 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "fail", parsed
    assert parsed["ok"] is False, parsed
    assert parsed["redactionClean"] is False, parsed
    assert "redactionClean" in parsed["errors"], parsed
    assert value not in result.stdout, result.stdout

def assert_security_response_drill_verify_rejects_malformed_envelope(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    with tempfile.TemporaryDirectory(prefix="cryptad-security-drill-envelope-") as temp_name:
        malformed_artifact = Path(temp_name) / "reviewer-key-compromise.json"
        malformed_artifact.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "kind": "cryptad-security-response-drill",
                    "scenario": "vulnerable-app-version",
                    "drill": {
                        "id": "reviewer-key-compromise",
                        "severity": "high",
                        "trigger": "reviewer key compromise drill",
                        "containmentActions": ["mark reviewer key revoked"],
                        "catalogActions": ["publish affected app advisories"],
                        "reviewActions": ["revoke exact receipt fingerprints"],
                        "operatorActions": ["show reviewer key revoked"],
                        "schedulerExpectations": ["fail revoked-reviewer receipts closed"],
                        "redactionRequirements": ["omit reviewer private keys"],
                        "verificationEvidence": ["app-review.reviewer-key-compromise-flow"],
                        "releaseNotesTemplate": "reviewer key id and replacement review status",
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "drill",
                "verify",
                "--input",
                str(malformed_artifact),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode != 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "fail", parsed
    assert parsed["ok"] is False, parsed
    assert "generatedAt must be an ISO-8601 UTC timestamp" in parsed["errors"], parsed
    assert "releaseId must be a non-empty string" in parsed["errors"], parsed
    assert "steps must be a non-empty array" in parsed["errors"], parsed
    assert "redaction must be an object" in parsed["errors"], parsed

def assert_security_response_verifier_rejects_bounded_model_violations(repo_root: Path) -> None:
    verifier = repo_root / "tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py"
    assert verifier.is_file(), verifier
    with tempfile.TemporaryDirectory(prefix="cryptad-security-runbook-bounds-") as temp_name:
        temp_dir = Path(temp_name)
        runbook = temp_dir / "production-security-response-runbook.md"
        model = temp_dir / "production-security-response-runbook.json"
        template = temp_dir / "security-release-notes.md"
        shutil.copyfile(repo_root / "docs/production-security-response-runbook.md", runbook)
        shutil.copyfile(
            repo_root / "tools/release-certification/production-security-response-runbook.json",
            model,
        )
        shutil.copyfile(repo_root / "docs/templates/security-release-notes.md", template)
        loaded_model = json.loads(model.read_text(encoding="utf-8"))
        loaded_model["drills"][0]["containmentActions"] = [
            f"bounded containment action {index}" for index in range(7)
        ]
        loaded_model["drills"][1]["verificationEvidence"] = ["v" * 161]
        loaded_model["drills"][2]["releaseNotesTemplate"] = "r" * 161
        write_json(model, loaded_model)

        verify_result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "verify",
                "--runbook",
                str(runbook),
                "--model",
                str(model),
                "--template",
                str(template),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        drill_artifact = temp_dir / "vulnerable-app-version.json"
        write_json(
            drill_artifact,
            {
                "schemaVersion": 1,
                "kind": "cryptad-security-response-drill",
                "scenario": loaded_model["drills"][0]["id"],
                "drill": loaded_model["drills"][0],
            },
        )
        drill_result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "drill",
                "verify",
                "--input",
                str(drill_artifact),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert verify_result.returncode != 0, verify_result.stdout
    verify_parsed = json.loads(verify_result.stdout)
    assert verify_parsed["status"] == "fail", verify_parsed
    assert verify_parsed["checks"]["modelValid"] is False, verify_parsed
    assert "modelValid" in verify_parsed["errors"], verify_parsed
    assert any("at most 6 entries" in error for error in verify_parsed["errors"]), verify_parsed
    assert any("1..160 characters" in error for error in verify_parsed["errors"]), verify_parsed

    assert drill_result.returncode != 0, drill_result.stdout
    drill_parsed = json.loads(drill_result.stdout)
    assert drill_parsed["status"] == "fail", drill_parsed
    assert drill_parsed["ok"] is False, drill_parsed
    assert drill_parsed["redactionClean"] is True, drill_parsed
    assert any("at most 6 entries" in error for error in drill_parsed["errors"]), drill_parsed

def assert_security_response_drill_verify_rejects_sensitive_artifact(
    verifier: Path, tainted_value: str
) -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-drill-redaction-") as temp_name:
        tainted_artifact = Path(temp_name) / "reviewer-key-compromise.json"
        tainted_artifact.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "kind": "cryptad-security-response-drill",
                    "scenario": "reviewer-key-compromise",
                    "drill": {
                        "id": "reviewer-key-compromise",
                        "severity": "high",
                        "trigger": tainted_value,
                        "containmentActions": ["mark reviewer key revoked"],
                        "catalogActions": ["publish affected app advisories"],
                        "reviewActions": ["revoke exact receipt fingerprints"],
                        "operatorActions": ["show reviewer key revoked"],
                        "schedulerExpectations": ["fail revoked-reviewer receipts closed"],
                        "redactionRequirements": ["omit reviewer private keys"],
                        "verificationEvidence": ["app-review.reviewer-key-compromise-flow"],
                        "releaseNotesTemplate": "reviewer key id and replacement review status",
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "drill",
                "verify",
                "--input",
                str(tainted_artifact),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode != 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "fail", parsed
    assert parsed["ok"] is False, parsed
    assert parsed["redactionClean"] is False, parsed
    assert "redactionClean" in parsed["errors"], parsed
    for forbidden_value in (
        "tainted-token",
        "private-app-record",
        "/var/lib/crypta/private.json",
        "crypta:USK@fetched-evidence",
    ):
        assert forbidden_value not in result.stdout, result.stdout

def assert_production_security_evidence_rejects_sensitive_text() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-response-evidence-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        runbook_path = workspace / "docs/production-security-response-runbook.md"
        runbook_path.write_text(
            runbook_path.read_text(encoding="utf-8")
            + "\nAuthorization: Basic tainted-token\n"
            + "rawAppData: private-app-record\n"
            + "rawFetchedContent=private-fetched-record\n",
            encoding="utf-8",
        )
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_production_security_response_runbook_evidence(settings)
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert "sensitiveMarkersAbsent" in encoded, encoded
        assert "redactionFindings" in encoded, encoded
        assert "raw app data marker" in encoded, encoded
        assert "raw fetched content marker" in encoded, encoded
        assert "Basic tainted-token" not in encoded, encoded
        assert "private-app-record" not in encoded, encoded
        assert "private-fetched-record" not in encoded, encoded

def assert_production_security_evidence_rejects_sensitive_model_keys() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-response-model-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["drills"][0]["authorizationHeader"] = "private-auth-header"
        model["drills"][0]["rawAppData"] = "private-app-record"
        model["drills"][0]["rawAppDataSource"] = "private-app-record-source"
        model["drills"][0]["rawAppDataStatus"] = "private-app-record-status"
        model["drills"][0]["rawFetchedContent"] = "private-fetched-record"
        model["drills"][0]["token"] = "tainted-token"
        model["drills"][0]["tokenStatus"] = "tainted-token-status"
        write_json(model_path, model)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_production_security_response_runbook_evidence(settings)
        encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert "sensitiveMarkersAbsent" in encoded, encoded
        assert "redactionFindings" in encoded, encoded
        assert "sensitive JSON key marker" in encoded, encoded
        for forbidden_value in (
            "private-auth-header",
            "private-app-record",
            "private-app-record-source",
            "private-app-record-status",
            "private-fetched-record",
            "tainted-token",
            "tainted-token-status",
        ):
            assert forbidden_value not in encoded, encoded

    for key, value in (
        ("authorizationHeader", "private-auth-header"),
        ("rawAppDataStatus", "private-app-record-status"),
        ("rawAppDataSource", "private-app-record-source"),
        ("rawFetchedContent", "private-fetched-record"),
        ("tokenStatus", "tainted-token-status"),
    ):
        with tempfile.TemporaryDirectory(prefix="cryptad-security-response-model-key-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
            model = json.loads(model_path.read_text(encoding="utf-8"))
            model["drills"][0][key] = value
            write_json(model_path, model)
            settings = Settings(
                workspace_root=workspace.resolve(),
                out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
                mode="pr",
                skip_gradle=True,
                cli_path=None,
                live=False,
                live_base_url="",
                live_form_password="",
                timeout_seconds=60,
            )

            item = collect_production_security_response_runbook_evidence(settings)
            encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert "sensitiveMarkersAbsent" in encoded, encoded
        assert "redactionFindings" in encoded, encoded
        assert "sensitive JSON key marker" in encoded, encoded
        assert value not in encoded, encoded

def assert_production_security_evidence_scans_raw_invalid_model_text() -> None:
    tainted_models = (
        '{"schemaVersion": 1, "token": "tainted-token", "path": "/var/lib/crypta/private.json",',
        json.dumps(
            [
                "Authorization: Basic tainted-token",
                "local path /var/lib/crypta/private.json",
                "content key crypta:USK@fetched-evidence/0/report.json",
            ]
        ),
    )
    for model_text in tainted_models:
        with tempfile.TemporaryDirectory(prefix="cryptad-security-response-raw-model-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
            model_path.write_text(model_text + "\n", encoding="utf-8")
            settings = Settings(
                workspace_root=workspace.resolve(),
                out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
                mode="pr",
                skip_gradle=True,
                cli_path=None,
                live=False,
                live_base_url="",
                live_form_password="",
                timeout_seconds=60,
            )

            item = collect_production_security_response_runbook_evidence(settings)
            encoded = json.dumps(item.to_json(), sort_keys=True)

        assert item.status == "warn", item
        assert item.details["checks"]["runbookModelValid"] is False, item.details
        assert item.details["checks"]["sensitiveMarkersAbsent"] is False, item.details
        assert "redactionFindings" in item.details, item.details
        assert "tainted-token" not in encoded, encoded
        assert "/var/lib/crypta/private.json" not in encoded, encoded
        assert "crypta:USK@fetched-evidence" not in encoded, encoded

def assert_production_security_evidence_rejects_malformed_model_scalars() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-response-model-shape-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["drills"][0]["severity"] = None
        model["drills"][1]["trigger"] = 42
        model["drills"][2]["releaseNotesTemplate"] = ""
        write_json(model_path, model)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_production_security_response_runbook_evidence(settings)

        assert item.status == "warn", item
        assert item.details["checks"]["runbookModelValid"] is False, item.details
        assert "runbookModelValid" in item.details["errors"], item.details

def assert_production_security_evidence_rejects_duplicate_drill_ids() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-response-duplicate-drill-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        duplicated = dict(model["drills"][0])
        model["drills"].append(duplicated)
        write_json(model_path, model)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_production_security_response_runbook_evidence(settings)

        assert item.status == "warn", item
        assert item.details["checks"]["runbookModelValid"] is False, item.details
        assert item.details["duplicateDrillIds"] == [duplicated["id"]], item.details
        assert "runbookModelValid" in item.details["errors"], item.details

def assert_production_security_evidence_allows_boolean_redaction_metadata() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-security-response-boolean-metadata-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        model_path = workspace / "tools/release-certification/production-security-response-runbook.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["drills"][0]["rawAppDataPresent"] = True
        model["drills"][0]["rawAppDataRedacted"] = True
        write_json(model_path, model)
        settings = Settings(
            workspace_root=workspace.resolve(),
            out_dir=(workspace / DEFAULT_OUT_DIR).resolve(),
            mode="pr",
            skip_gradle=True,
            cli_path=None,
            live=False,
            live_base_url="",
            live_form_password="",
            timeout_seconds=60,
        )

        item = collect_production_security_response_runbook_evidence(settings)

        assert item.status == "pass", item
        assert item.details["checks"]["runbookModelValid"] is True, item.details
        assert item.details["checks"]["sensitiveMarkersAbsent"] is True, item.details
        assert "redactionFindings" not in item.details, item.details

def run_self_test(repo_root: Path) -> None:
    assert_maintenance_policy_evidence_redacts_invalid_values()
    assert_maintenance_policy_evidence_rejects_redacted_uri_values()
    assert_maintenance_policy_evidence_rejects_allowed_policy_drift()
    assert_first_party_beta_quality_rejects_missing_metadata()
    assert_first_party_beta_quality_rejects_unknown_readiness_metadata_without_leak()
    assert_first_party_beta_quality_rejects_missing_empty_state_marker()
    assert_first_party_beta_quality_rejects_sensitive_diagnostics()
    assert_first_party_beta_quality_rejects_sensitive_static_assets()
    assert_first_party_beta_quality_rejects_sensitive_manifest_metadata()
    assert_first_party_beta_quality_redaction_handles_insert_uri_examples()
    assert_security_response_drill_verify_rejects_sensitive_artifacts(repo_root)
    assert_security_response_drill_verify_rejects_sensitive_json_keys(repo_root)
    assert_security_response_drill_verify_allows_boolean_redaction_metadata(repo_root)
    assert_security_response_runbook_verify_rejects_sensitive_text_assignments(repo_root)
    assert_security_response_runbook_verify_allows_boolean_redaction_metadata(repo_root)
    assert_security_response_drill_verify_rejects_malformed_envelope(repo_root)
    assert_security_response_verifier_rejects_bounded_model_violations(repo_root)
    assert_production_security_evidence_rejects_sensitive_text()
    assert_production_security_evidence_rejects_sensitive_model_keys()
    assert_production_security_evidence_scans_raw_invalid_model_text()
    assert_production_security_evidence_rejects_malformed_model_scalars()
    assert_production_security_evidence_rejects_duplicate_drill_ids()
    assert_production_security_evidence_allows_boolean_redaction_metadata()
    fixture_dir = repo_root / "tools/release-certification/fixtures"
    catalog_fixture = fixture_dir / "self-test-catalog.properties"
    registry_fixture = fixture_dir / "self-test-legacy-registry.java-fragment"
    catalog = parse_properties(catalog_fixture)
    assert catalog["catalog.id"] == "cert-smoke"
    assert "feed-reader" in parse_permission_set(catalog["catalog.entries"])
    assert "social-inbox" in parse_permission_set(catalog["catalog.entries"])
    assert "trust-graph" in parse_permission_set(catalog["catalog.entries"])
    assert catalog["app.cert-smoke.bundle.sha256"] == "0" * 64
    assert catalog["app.feed-reader.permissions"] == (
        "content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,"
        "app.data.read,app.data.write"
    )
    assert catalog["app.feed-reader.api.minimumVersion"] == "9"
    assert catalog["app.feed-reader.api.maximumTestedVersion"] == str(
        FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION
    )
    assert catalog["app.social-inbox.permissions"] == (
        "vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,"
        "content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,"
        "app.data.write,app.services.read,app.services.call"
    )
    assert catalog["app.social-inbox.api.minimumVersion"] == "16"
    assert catalog["app.social-inbox.api.maximumTestedVersion"] == str(
        FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION
    )
    assert catalog["app.trust-graph.permissions"] == (
        "trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,"
        "queue.read,queue.write,vault.identities.read,vault.identities.create,vault.identities.use,"
        "app.data.read,app.data.write"
    )
    assert catalog["app.trust-graph.api.minimumVersion"] == "22"
    assert catalog["app.trust-graph.api.maximumTestedVersion"] == "22"
    registry_text = registry_fixture.read_text(encoding="utf-8")
    counts = legacy_counts_from_registry_text(registry_text)
    assert counts == {
        "PRIMARY_REPLACED": 14,
        "PENDING": 2,
        "RETAINED": 1,
        "INFRASTRUCTURE": 1,
    }, counts
    assert legacy_removal_wave_three_ids(registry_text) == ["security-levels"]
    assert legacy_removal_wave_four_ids(registry_text) == ["diagnostic"]
    assert legacy_removal_wave_five_ids(registry_text) == []
    assert legacy_final_surface_category_ids(
        registry_text, "RETAINED_BROWSE_SURFACE"
    ) == list(LEGACY_FINAL_RETAINED_BROWSE_IDS)
    assert legacy_final_surface_category_ids(
        registry_text, "SUPPORT_EMERGENCY_FALLBACK"
    ) == list(LEGACY_FINAL_SUPPORT_EMERGENCY_IDS)
    assert legacy_final_surface_category_ids(
        registry_text, "STARTUP_RECOVERY_FALLBACK"
    ) == list(LEGACY_FINAL_STARTUP_RECOVERY_IDS)
    extra_wave_three_text = registry_text.replace(
        "securityLevelsWave3Redirect()",
        'securityLevelsWave3Redirect(),\n'
        '          wave3Redirect("diagnostic", "Diagnostic", "/diagnostic/", '
        '"/app/node/#diagnostics", "Shell diagnostics", "Wrong.", false)',
    )
    assert legacy_removal_wave_three_ids(extra_wave_three_text) != list(
        LEGACY_REMOVAL_WAVE_THREE_IDS
    )
    fallback_checks = legacy_fallback_link_checks(registry_text)
    assert fallback_checks["primaryReplacedExcludedFromFallbackLinks"] is True, fallback_checks
    assert fallback_checks["primaryReplacedAbsentFromPrimaryNavigation"] is True, fallback_checks
    unsafe_registry_text = registry_text.replace("true,\n        false);", "true,\n        true);", 1)
    unsafe_fallback_checks = legacy_fallback_link_checks(unsafe_registry_text)
    assert unsafe_fallback_checks["primaryReplacedExcludedFromFallbackLinks"] is False, unsafe_fallback_checks
    assert legacy_scope_expansion_wave_two_ids("") == []
    assert legacy_scope_expansion_wave_two_ids("final class LegacyAdminRetirementRegistry {}") == []
    assert social_inbox_docs_frame_spike_non_goals(
        "This is a migration spike, not a production social network, mail protocol, "
        "full WoT implementation, Freetalk/Sone/Freemail compatibility layer, "
        "encrypted mail transport, and daemon-core message store."
    )
    assert social_inbox_docs_frame_spike_non_goals(
        "This is a migration spike, not a full Web of Trust, not Freetalk, not Sone, "
        "not Freemail, not encrypted mail, and not a daemon message store."
    )
    assert not social_inbox_docs_frame_spike_non_goals(
        "This is a migration spike with Freetalk, Sone, Freemail, encrypted mail, "
        "and daemon-core message store non-goals but no WoT limitation."
    )
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
            shutil.copy(canonical_sdk, static_dir / "crypta-platform.js")
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
    signature_scrubbed = scrub_text(
        "signature.value.base64=raw-signature signature.algorithm=Ed25519",
        repo_root,
    )
    assert "raw-signature" not in signature_scrubbed, signature_scrubbed
    assert "Ed25519" in signature_scrubbed, signature_scrubbed
    body_label_scrubbed = scrub_text(
        "raw trust statement body: signed-trust-document\n"
        "raw message body: private-social-body\n"
        "request body: form-password=secret\n"
        "raw feed body: <script>alert(1)</script>",
        repo_root,
    )
    for forbidden in (
        "signed-trust-document",
        "private-social-body",
        "form-password=secret",
        "<script>alert(1)</script>",
    ):
        assert forbidden not in body_label_scrubbed, body_label_scrubbed
    assert "raw trust statement body: <redacted>" in body_label_scrubbed, body_label_scrubbed
    assert "raw message body: <redacted>" in body_label_scrubbed, body_label_scrubbed
    safe_bundle_source = (
        "record AppServiceGrantBundle(String bundleId) { "
        "/* comments can mention tokens and local paths */ "
        "void toJson(java.util.Map<String,Object> json) { json.put(\"bundleId\", bundleId); } }"
    )
    unsafe_bundle_source = (
        "record AppServiceGrantBundle(String bundleId, String tokenPath) { "
        "void toJson(java.util.Map<String,Object> json) { json.put(\"tokenPath\", tokenPath); } }"
    )
    assert app_service_bundle_public_fields_are_safe(safe_bundle_source), safe_bundle_source
    assert not app_service_bundle_public_fields_are_safe(unsafe_bundle_source), unsafe_bundle_source
    pem_scrubbed = scrub_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "pem-private-key-body\n"
        "-----END PRIVATE KEY-----\n"
        "public reviewer key id remains",
        repo_root,
    )
    for forbidden in ("BEGIN PRIVATE KEY", "pem-private-key-body", "END PRIVATE KEY"):
        assert forbidden not in pem_scrubbed, pem_scrubbed
    assert "public reviewer key id remains" in pem_scrubbed, pem_scrubbed
    truncated_pem_scrubbed = scrub_text(
        "before\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "truncated-pem-private-key-body\n"
        "more-private-key-body",
        repo_root,
    )
    for forbidden in (
        "BEGIN PRIVATE KEY",
        "truncated-pem-private-key-body",
        "more-private-key-body",
    ):
        assert forbidden not in truncated_pem_scrubbed, truncated_pem_scrubbed
    assert "before" in truncated_pem_scrubbed, truncated_pem_scrubbed
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
        "/app-data/status /app-data/records/{namespace}/{key} "
        "/content/fetch /content/subscriptions/{subscriptionId}/refresh "
        "/queue/inserts/app-document /trust-graph/import-uri /mnt/secrets/signing/key.pem",
        repo_root,
    )
    assert "/apps/install" in route_scrubbed, route_scrubbed
    assert "/apps/cert-smoke/runtime" in route_scrubbed, route_scrubbed
    assert "/api/v1/diagnostics" in route_scrubbed, route_scrubbed
    assert "/app-data/status" in route_scrubbed, route_scrubbed
    assert "/app-data/records/{namespace}/{key}" in route_scrubbed, route_scrubbed
    assert "/content/fetch" in route_scrubbed, route_scrubbed
    assert "/content/subscriptions/{subscriptionId}/refresh" in route_scrubbed, route_scrubbed
    assert "/queue/inserts/app-document" in route_scrubbed, route_scrubbed
    assert "/trust-graph/import-uri" in route_scrubbed, route_scrubbed
    assert "/mnt/secrets/signing/key.pem" not in route_scrubbed, route_scrubbed
    assert "<path>/key.pem" in route_scrubbed, route_scrubbed
    content_root_path_scrubbed = scrub_text("/content/cryptad/build/key.pem", repo_root)
    queue_root_path_scrubbed = scrub_text("/queue/cryptad/build/token.txt", repo_root)
    assert "/content/cryptad" not in content_root_path_scrubbed, content_root_path_scrubbed
    assert "/queue/cryptad" not in queue_root_path_scrubbed, queue_root_path_scrubbed
    assert "<path>/key.pem" in content_root_path_scrubbed, content_root_path_scrubbed
    assert "<path>/token.txt" in queue_root_path_scrubbed, queue_root_path_scrubbed
    content_workspace_scrubbed = scrub_text(
        "/content/cryptad/build/app-platform-smoke/summary.json",
        Path("/content/cryptad"),
    )
    assert (
        content_workspace_scrubbed == "<repo>/build/app-platform-smoke/summary.json"
    ), content_workspace_scrubbed
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
    feed_body_metadata = sanitize_value(
        {
            "rawFeedBody": "<feed><entry>private body</entry></feed>",
            "rawFeedBodyBase64": "opaque-feed-body-base64",
            "rawRequestBody": "uri=SSK@private",
            "requestBodyText": "opaque-request-body-text",
            "feedContentPreview": "opaque-feed-preview",
            "rawFeedBodySource": "opaque-feed-body-source",
            "requestBodySource": "opaque-request-body-source",
            "rawTrustStatementBody": '{"type":"crypta.trust.statement.v1","signature":{"value":"sig"}}',
            "trustStatementBodies": ["signed trust statement body"],
            "trustStatementPayload": {"signature": {"value": "trust-signature"}},
            "rawTrustStatementBodySource": "opaque-trust-body-source",
            "trustStatementBodiesExcluded": True,
            "feedSummary": "3 entries",
            "rawFeedBodyRedacted": True,
            "rawFeedBodiesExcluded": True,
            "rawMessageBodiesExcludedFromEvidence": True,
        },
        repo_root,
    )
    assert feed_body_metadata["rawFeedBody"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawFeedBodyBase64"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawRequestBody"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["requestBodyText"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["feedContentPreview"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawFeedBodySource"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["requestBodySource"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawTrustStatementBody"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["trustStatementBodies"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["trustStatementPayload"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["rawTrustStatementBodySource"] == "<redacted>", feed_body_metadata
    assert feed_body_metadata["trustStatementBodiesExcluded"] is True, feed_body_metadata
    assert feed_body_metadata["feedSummary"] == "3 entries", feed_body_metadata
    assert feed_body_metadata["rawFeedBodyRedacted"] is True, feed_body_metadata
    assert feed_body_metadata["rawFeedBodiesExcluded"] is True, feed_body_metadata
    assert feed_body_metadata["rawMessageBodiesExcludedFromEvidence"] is True, feed_body_metadata
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
        ] == CURRENT_PLATFORM_API_CONTRACT_VERSION
        python_fake_init_dir = workspace / "python-fake-init"
        python_fake_init_result = subprocess.run(
            [
                sys.executable,
                str(python_fake_cli),
                "init",
                "--dir",
                str(python_fake_init_dir),
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
            capture_output=True,
            text=True,
            check=False,
        )
        assert python_fake_init_result.returncode == 0, python_fake_init_result.stderr
        python_fake_manifest = parse_properties(python_fake_init_dir / "cryptad-app.properties")
        assert python_fake_manifest["api.maximumTestedVersion"] == str(
            CURRENT_PLATFORM_API_CONTRACT_VERSION
        )
        assert python_fake_manifest["api.targetStability"] == "stable"
        python_fake_contract = workspace / "python-fake-platform-api-contract.json"
        python_fake_snapshot_result = subprocess.run(
            [
                sys.executable,
                str(python_fake_cli),
                "api",
                "snapshot",
                "--output",
                str(python_fake_contract),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert python_fake_snapshot_result.returncode == 0, python_fake_snapshot_result.stderr
        python_fake_snapshot = json.loads(python_fake_contract.read_text(encoding="utf-8"))
        python_fake_baseline = python_fake_snapshot["contract"]["stableBaseline"]
        assert python_fake_baseline["name"] == "1.0", python_fake_baseline
        assert python_fake_baseline["contractVersion"] == (
            CURRENT_PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION
        ), python_fake_baseline
        assert python_fake_baseline["capabilityCount"] == 9, python_fake_baseline
        assert python_fake_baseline["endpointCount"] == 32, python_fake_baseline
        assert python_fake_baseline["capabilities"] == [
            "app.data.read",
            "app.data.write",
            "content.fetch",
            "content.insert",
            "content.insert.app-document",
            "content.subscribe",
            "platform.contract.read",
            "queue.read",
            "queue.write",
        ], python_fake_baseline
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
        assert evidence_by_id[FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID]["status"] == "pass"
        devtools_item = evidence_by_id["app-platform.devtools-cli"]
        assert devtools_item["status"] == "pass", devtools_item
        toolkit_item = evidence_by_id["app-platform.developer-beta-toolkit"]
        assert toolkit_item["status"] == "pass", toolkit_item
        assert toolkit_item["details"]["checks"]["devCommand"] is True, toolkit_item
        assert toolkit_item["details"]["checks"]["templates"]["queue-dashboard"] is True, toolkit_item
        for evidence_id in THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        for evidence_id in PUBLIC_BETA_DOCS_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        public_beta_readme = workspace / "docs/public-beta/README.md"
        public_beta_readme_original = read_source(public_beta_readme)
        sensitive_public_beta_targets = (
            "USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/private/doc.md",
            "/home/alice/key.md",
        )
        try:
            public_beta_readme.write_text(
                public_beta_readme_original
                + "\n[Sensitive public beta URI](USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/private/doc.md)\n"
                + "[Sensitive public beta path](/home/alice/key.md)\n",
                encoding="utf-8",
            )
            unsafe_public_beta_evidence = {
                item.id: item.to_json()
                for item in collect_public_beta_docs_onboarding_evidence(settings)
            }
        finally:
            public_beta_readme.write_text(public_beta_readme_original, encoding="utf-8")
        public_beta_links = unsafe_public_beta_evidence["public-beta.links-redaction"]
        assert public_beta_links["status"] != "pass", public_beta_links
        public_beta_links_json = json.dumps(public_beta_links, sort_keys=True)
        for target in sensitive_public_beta_targets:
            assert target not in public_beta_links_json, public_beta_links
        assert app_platform_docs_check.REDACTED_BROKEN_LINK_TARGET in public_beta_links_json, (
            public_beta_links
        )
        third_party_intake = evidence_by_id["third-party-intake.beta-catalog-install-smoke"]
        assert (
            "install-from-beta-catalog smoke passed"
            in third_party_intake["details"]["sampleFlow"]
        ), third_party_intake
        third_party_sample = evidence_by_id["third-party-developer.sample-app-flow"]
        assert third_party_sample["details"]["template"] == "hello-stable", third_party_sample
        assert (
            third_party_sample["details"]["apiTargetStability"] == "stable"
        ), third_party_sample
        assert "operator-only rejection" in third_party_sample["details"]["sampleFlow"]
        third_party_redaction = evidence_by_id["third-party-developer.redaction"]
        assert "security-notes.md" in third_party_redaction["details"][
            "sampleReviewFilesScanned"
        ], third_party_redaction
        tainted_review_note = (
            workspace
            / "samples/third-party/hello-stable-app/review/security-notes.md"
        )
        for tainted_text, expected_finding in (
            ("Authorization: Bearer review-note-secret\n", "credential-or-path marker"),
            ("publish URI: USK@PRIVATE-INSERT-URI\n", "credential-or-path marker"),
            ("/home/alice/.crypta/apps/hello-stable/data.json\n", "credential-or-path marker"),
            ("raw app data: private-record-value\n", "raw app data marker"),
            ("raw fetched content: private-fetched-body\n", "raw fetched content marker"),
        ):
            tainted_review_note.write_text(tainted_text, encoding="utf-8")
            tainted_third_party_evidence = {
                item.id: item
                for item in collect_third_party_developer_beta_program_evidence(settings)
            }
            tainted_redaction = tainted_third_party_evidence[
                "third-party-developer.redaction"
            ]
            assert tainted_redaction.status != "pass", tainted_redaction
            assert (
                "sampleSensitiveMarkersAbsent" in tainted_redaction.details["errors"]
            ), tainted_redaction
            assert (
                expected_finding in tainted_redaction.details["sampleRedactionFindings"]
            ), tainted_redaction
        tainted_review_note.write_text("fixture\n", encoding="utf-8")
        assert evidence_by_id["legacy-admin.removal-wave-1"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-1"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-2"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-2"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-3"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-3"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-4"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-4"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-4"]["details"][
            "removedByDefaultRouteIds"
        ] == ["diagnostic"]
        assert evidence_by_id["legacy-admin.removal-wave-5"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.removal-wave-5"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.removal-wave-5"]["details"][
            "waveFivePromotedRouteIds"
        ] == []
        assert evidence_by_id["legacy-admin.final-admin-surface"]["status"] == "pass"
        assert (
            evidence_by_id["legacy-admin.final-admin-surface"]["requiredForReleaseCandidate"]
            is True
        )
        assert evidence_by_id["legacy-admin.browse-retained"]["status"] == "pass"
        assert evidence_by_id["legacy-admin.browse-retained"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-admin.emergency-fallback-retained"]["status"] == "pass"
        assert (
            evidence_by_id["legacy-admin.emergency-fallback-retained"][
                "requiredForReleaseCandidate"
            ]
            is True
        )
        contract_item = evidence_by_id["platform-api.contract"]
        assert contract_item["status"] == "pass", contract_item
        assert evidence_by_id["platform-api.stable-baseline"]["status"] == "pass"
        assert evidence_by_id["platform-api.stable-breaking-change-check"]["status"] == "pass"
        assert evidence_by_id["platform-api.compatibility-window"]["status"] == "pass"
        assert evidence_by_id["platform-api.previous-contract-snapshot"]["status"] == "pass"
        deprecation_policy_item = evidence_by_id["platform-api.deprecation-window-policy"]
        assert deprecation_policy_item["status"] == "pass"
        assert evidence_by_id["platform-api.experimental-graduation-policy"]["status"] == "pass"
        assert evidence_by_id["platform-api.manifest-target-stability"]["status"] == "pass"
        assert evidence_by_id["platform-api.first-party-stability-declarations"]["status"] == "pass"
        assert evidence_by_id["platform-api.stable-reference-docs"]["status"] == "pass"
        vault_item = evidence_by_id["app-vault.capabilities"]
        assert vault_item["status"] == "pass", vault_item
        assert vault_item["requiredForReleaseCandidate"] is True, vault_item
        assert vault_item["details"]["capabilities"] == list(APP_VAULT_CAPABILITIES), vault_item
        for evidence_id in (
            "app-services.registry",
            "app-services.grants",
            "app-services.dependency-graph",
            "app-services.grant-bundles",
            "app-services.grant-expiry-renewal",
            "app-services.provider-revalidation",
            "app-services.trust-score-provider",
            "reference-app.social-inbox-service-grant",
            "reference-app.social-inbox-service-dependency",
            "app-services.web-shell",
            "app-services.redaction",
            "app-services.dependency-redaction",
        ):
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        assert evidence_by_id["app-platform.identity-profile-publish"]["status"] == "pass"
        assert evidence_by_id["app-platform.generated-document-insert"]["status"] == "pass"
        assert evidence_by_id["app-platform.content-fetch"]["status"] == "pass"
        assert evidence_by_id["app-platform.content-subscriptions"]["status"] == "pass"
        assert evidence_by_id["network-content.subscription-scheduler"]["status"] == "pass"
        assert evidence_by_id["app-platform.durable-app-data-store"]["status"] == "pass"
        backup_restore_item = evidence_by_id["app-data.backup-restore-portability"]
        assert backup_restore_item["status"] == "pass", backup_restore_item
        assert backup_restore_item["requiredForReleaseCandidate"] is True
        assert backup_restore_item["details"]["backupVersion"] == 1, backup_restore_item
        assert backup_restore_item["details"]["restoreModes"] == [
            "merge",
            "replaceNamespace",
            "replaceApp",
        ], backup_restore_item
        contract_details = contract_item["details"]
        assert contract_details["stableDescriptorDeprecations"] == [], contract_item
        assert deprecation_policy_item["details"]["stableDescriptorDeprecations"] == []
        assert deprecation_policy_item["details"]["descriptorErrors"] == []
        bad_contract_details = dict(contract_details)
        bad_contract_details["stableDescriptorDeprecations"] = [
            {
                "kind": "capability",
                "identity": "queue.read",
                "stability": "scheduled-for-removal",
                "hasDeprecationMetadata": False,
            },
            {
                "kind": "endpoint",
                "identity": "GET /queue",
                "stability": "deprecated",
                "hasDeprecationMetadata": True,
                FIELD_DEPRECATED_SINCE_CONTRACT_VERSION: CURRENT_PLATFORM_API_CONTRACT_VERSION,
                FIELD_REMOVAL_CONTRACT_VERSION: CURRENT_PLATFORM_API_CONTRACT_VERSION + 1,
            },
        ]
        bad_deprecation_evidence = {
            item.id: item.to_json()
            for item in collect_platform_api_stable_freeze_evidence(
                dataclasses.replace(settings, mode="release-candidate"),
                EvidenceItem(
                    "platform-api.contract",
                    "pass",
                    True,
                    "self-test contract",
                    summary_source(settings),
                    bad_contract_details,
                ),
            )
        }
        bad_deprecation_policy = bad_deprecation_evidence[
            "platform-api.deprecation-window-policy"
        ]
        assert bad_deprecation_policy["status"] == "fail", bad_deprecation_policy
        bad_deprecation_errors = bad_deprecation_policy["details"]["descriptorErrors"]
        assert any(
            "without deprecatedSinceContractVersion" in error
            for error in bad_deprecation_errors
        ), bad_deprecation_policy
        assert any(
            "deprecation window is shorter" in error for error in bad_deprecation_errors
        ), bad_deprecation_policy
        assert (
            contract_details["contractVersion"] == CURRENT_PLATFORM_API_CONTRACT_VERSION
        ), contract_item
        assert contract_details["compatibilityWindow"]["baselineName"] == "1.0", contract_item
        assert contract_details["compatibilityWindow"][
            "previousSnapshotRequiredInProductionBeta"
        ] is True, contract_item
        assert contract_details["compatibilityWindow"][
            "criticalStableRemovalWaiverAllowed"
        ] is False, contract_item
        assert contract_details["capabilityCount"] == 17, contract_item
        assert contract_details["endpointCount"] == 65, contract_item
        assert contract_details["appServicesContract"]["missingCapabilities"] == [], contract_item
        assert contract_details["appServicesContract"]["missingEndpoints"] == [], contract_item
        assert contract_details["stableBaselineCapabilities"] == [
            "app.data.read",
            "app.data.write",
            "content.fetch",
            "content.insert",
            "content.insert.app-document",
            "content.subscribe",
            "platform.contract.read",
            "queue.read",
            "queue.write",
        ], contract_item
        assert contract_details["stableBaselineEndpoints"] == [
            "DELETE /app-data/namespaces/{namespace}",
            "DELETE /app-data/records/{namespace}/{key}",
            "DELETE /content/subscriptions/{subscriptionId}",
            "GET /app-data/export",
            "GET /app-data/namespaces",
            "GET /app-data/namespaces/{namespace}",
            "GET /app-data/records",
            "GET /app-data/records/{namespace}/{key}",
            "GET /app-data/status",
            "GET /content/subscriptions",
            "GET /content/subscriptions/{subscriptionId}",
            "GET /platform/contract",
            "GET /queue",
            "GET /queue/count",
            "GET /queue/keys",
            "POST /app-data/import",
            "POST /app-data/namespaces/{namespace}/schema",
            "POST /app-data/records",
            "POST /content/fetch",
            "POST /content/subscriptions",
            "POST /content/subscriptions/{subscriptionId}/pause",
            "POST /content/subscriptions/{subscriptionId}/refresh",
            "POST /content/subscriptions/{subscriptionId}/resume",
            "POST /queue/cleanup/downloads",
            "POST /queue/cleanup/uploads",
            "POST /queue/downloads",
            "POST /queue/inserts/app-document",
            "POST /queue/inserts/directory",
            "POST /queue/inserts/file",
            "POST /queue/requests/priority",
            "POST /queue/requests/remove",
            "POST /queue/requests/restart",
        ], contract_item
        assert set(contract_details["stableEndpointRequiredCapabilities"]) == set(
            contract_details["stableBaselineEndpoints"]
        ), contract_item
        assert contract_details["stableEndpointRequiredCapabilities"]["GET /queue"] == [
            "queue.read"
        ], contract_item
        assert set(contract_details["stableEndpointAppAccess"]) == set(
            contract_details["stableBaselineEndpoints"]
        ), contract_item
        assert contract_details["stableEndpointAppAccess"]["GET /queue"] == {
            "appBrowserPrincipalsAllowed": True,
            "appProcessPrincipalsAllowed": True,
        }, contract_item
        assert set(contract_details["stableEndpointActionLabels"]) == set(
            contract_details["stableBaselineEndpoints"]
        ), contract_item
        assert contract_details["stableEndpointActionLabels"]["GET /queue"], contract_item
        assert contract_details["snapshotCommand"]["exitCode"] == 0, contract_item
        assert contract_details["verifier"]["cert-smoke"]["exitCode"] == 0, contract_item
        assert evidence_by_id["catalog.smoke"]["status"] in {"warn", "pass"}
        assert evidence_by_id["catalog.live-usk-publication"]["status"] == "pass"
        first_party_beta_item = evidence_by_id["app-catalog.first-party-beta"]
        assert first_party_beta_item["status"] == "pass", first_party_beta_item
        assert first_party_beta_item["details"]["catalogId"] == "crypta-first-party-beta"
        assert first_party_beta_item["details"]["requiredFirstPartyApps"] == list(APP_IDS)
        production_channels_item = evidence_by_id["catalog.production-channels"]
        assert production_channels_item["status"] == "pass", production_channels_item
        assert production_channels_item["details"]["channels"] == [
            "stable",
            "beta",
            "nightly",
            "deprecated",
        ]
        catalog_operations_item = evidence_by_id["catalog.operations-and-mirrors"]
        assert catalog_operations_item["status"] == "pass", catalog_operations_item
        assert catalog_operations_item["details"]["liveNodeRequired"] is False
        maintenance_item = evidence_by_id["app-catalog.first-party-maintenance-policy"]
        assert maintenance_item["status"] == "pass", maintenance_item
        assert maintenance_item["details"]["requiredFirstPartyApps"] == list(APP_IDS)
        assert maintenance_item["details"]["apps"]["trust-graph"]["maintenance"][
            "supportLevel"
        ] == "local-rc", maintenance_item
        assert maintenance_item["details"]["apps"]["feed-reader"]["maintenance"][
            "dataSchemaPolicy"
        ] == "migratable", maintenance_item
        assert evidence_by_id["catalog.live-usk-source-verification"]["status"] == "pass"
        assert evidence_by_id["app-ui.design-system"]["status"] == "pass"
        assert evidence_by_id["app-ui.lint"]["status"] == "pass"
        assert evidence_by_id["app-ui.first-party-adoption"]["status"] == "pass"
        assert evidence_by_id["reference-apps.content"]["status"] == "pass"
        assert evidence_by_id["reference-app.profile-publisher"]["status"] == "pass"
        assert evidence_by_id["reference-app.profile-publisher-app-data"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-signed-message"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-subscriptions"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-app-data"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-trust-annotations"]["status"] == "pass"
        assert evidence_by_id["reference-app.social-inbox-rc-threading"]["status"] == "pass"
        assert (
            evidence_by_id["reference-app.social-inbox-rc-threading"]["requiredForReleaseCandidate"]
            is True
        )
        assert evidence_by_id["app-platform.trust-social-beta-hardening"]["status"] == "pass"
        assert (
            evidence_by_id["app-platform.trust-social-beta-hardening"][
                "requiredForReleaseCandidate"
            ]
            is True
        )
        assert (
            evidence_by_id["app-platform.trust-social-content-format-profiles"]["status"] == "pass"
        )
        assert (
            evidence_by_id["app-platform.trust-social-content-format-profiles"][
                "requiredForReleaseCandidate"
            ]
            is True
        )
        assert evidence_by_id["migration.social-mail-preview"]["status"] == "pass"
        assert evidence_by_id["legacy-plugin.migration-guide"]["status"] == "pass"
        assert evidence_by_id["legacy-plugin.social-inbox-spike"]["status"] == "pass"
        assert evidence_by_id["legacy-plugin.freeze-policy"]["status"] == "pass"
        assert evidence_by_id["legacy-plugin.freeze-policy"]["requiredForReleaseCandidate"] is True
        assert evidence_by_id["legacy-plugin.migration-finalization"]["status"] == "pass"
        assert (
            evidence_by_id["legacy-plugin.migration-finalization"]["requiredForReleaseCandidate"]
            is True
        )
        migration_cookbook = workspace / PLUGIN_MIGRATION_COOKBOOK_PATH
        migration_cookbook_text = migration_cookbook.read_text(encoding="utf-8")
        try:
            migration_cookbook.unlink()
            missing_cookbook_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            migration_cookbook.write_text(migration_cookbook_text, encoding="utf-8")
        assert missing_cookbook_item.status == "fail", missing_cookbook_item
        assert "cookbookExists" in missing_cookbook_item.details["errors"], (
            missing_cookbook_item
        )
        try:
            migration_cookbook.write_text(
                migration_cookbook_text.replace("Trust Graph Local RC", "Local score app"),
                encoding="utf-8",
            )
            missing_trust_graph_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            migration_cookbook.write_text(migration_cookbook_text, encoding="utf-8")
        assert missing_trust_graph_item.status == "fail", missing_trust_graph_item
        assert "webOfTrustMapsToTrustGraphLocalRc" in missing_trust_graph_item.details["errors"], (
            missing_trust_graph_item
        )
        shim_source = (
            workspace
            / "runtime-node/src/main/java/network/crypta/runtime/WebOfTrustCompatibilityShim.java"
        )
        shim_source.parent.mkdir(parents=True, exist_ok=True)
        try:
            shim_source.write_text(
                "package network.crypta.runtime; final class WebOfTrustCompatibilityShim {}\n",
                encoding="utf-8",
            )
            shim_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            shim_source.unlink(missing_ok=True)
        assert shim_item.status == "fail", shim_item
        assert "sourceSurfaceAuditPasses" in shim_item.details["errors"], shim_item
        route_source = (
            workspace
            / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyPluginRouteProbe.java"
        )
        route_source.parent.mkdir(parents=True, exist_ok=True)
        try:
            route_source.write_text(
                "package network.crypta.clients.http; "
                "final class LegacyPluginRouteProbe { "
                "void install(Object router) { router.register(\"/plugins/WebOfTrust/\"); } }\n",
                encoding="utf-8",
            )
            route_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            route_source.unlink(missing_ok=True)
        assert route_item.status == "fail", route_item
        assert "sourceSurfaceAuditPasses" in route_item.details["errors"], route_item
        assert any(
            violation.get("reason") == "legacy plugin route registration"
            for violation in route_item.details["runtimeSurfaceViolations"]
        ), route_item
        unsafe_example = workspace / PLUGIN_MIGRATION_EXAMPLE_PATHS[1]
        unsafe_example_text = unsafe_example.read_text(encoding="utf-8")
        try:
            unsafe_example.write_text(
                unsafe_example_text + '\n"rawSocialMessage": "private-message-body"\n',
                encoding="utf-8",
            )
            raw_artifact_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            unsafe_example.write_text(unsafe_example_text, encoding="utf-8")
        assert raw_artifact_item.status == "fail", raw_artifact_item
        assert "redactionChecksPass" in raw_artifact_item.details["errors"], raw_artifact_item
        assert "private-message-body" not in json.dumps(raw_artifact_item.to_json()), (
            raw_artifact_item
        )
        try:
            unsafe_example.write_text(
                unsafe_example_text
                + "\nrawSocialMessage: <redacted> private-message-body\n",
                encoding="utf-8",
            )
            partial_raw_artifact_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            unsafe_example.write_text(unsafe_example_text, encoding="utf-8")
        assert partial_raw_artifact_item.status == "fail", partial_raw_artifact_item
        assert "redactionChecksPass" in partial_raw_artifact_item.details["errors"], (
            partial_raw_artifact_item
        )
        assert "private-message-body" not in json.dumps(
            partial_raw_artifact_item.to_json()
        ), partial_raw_artifact_item
        try:
            unsafe_example.write_text(
                unsafe_example_text
                + '\n"rawSocialMessage": {\n'
                + '  "body": "private-message-body"\n'
                + "}\n",
                encoding="utf-8",
            )
            multiline_raw_artifact_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            unsafe_example.write_text(unsafe_example_text, encoding="utf-8")
        assert multiline_raw_artifact_item.status == "fail", multiline_raw_artifact_item
        assert "redactionChecksPass" in multiline_raw_artifact_item.details["errors"], (
            multiline_raw_artifact_item
        )
        assert "private-message-body" not in json.dumps(
            multiline_raw_artifact_item.to_json()
        ), multiline_raw_artifact_item
        try:
            unsafe_example.write_text(
                unsafe_example_text + "\nexportPath=file:/home/alice/plugin-export.json\n",
                encoding="utf-8",
            )
            java_file_uri_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            unsafe_example.write_text(unsafe_example_text, encoding="utf-8")
        assert java_file_uri_item.status == "fail", java_file_uri_item
        assert "redactionChecksPass" in java_file_uri_item.details["errors"], (
            java_file_uri_item
        )
        for leak_text in (
            '"raw_social_message": "private-message-body"',
            "raw-trust-statement: trust-statement-json",
            '"old_plugin_export": "serialized-state-with-secrets"',
            '"raw profile document": "private-profile-document"',
            "rawSocialMessage: <redacted> private-message-body",
            '"rawSocialMessage": "<redacted> private-message-body"',
            '"rawSocialMessage": {\n  "body": "private-message-body"\n}',
            '"rawTrustStatement": [\n  {"issuer": "private-issuer"}\n]',
        ):
            separator_findings = plugin_migration_redaction_findings_for_text(
                leak_text,
                workspace,
                "separator-leak",
            )
            assert any(
                finding["kind"] == "raw migration artifact"
                for finding in separator_findings
            ), separator_findings
        for safe_redacted_text in (
            "rawSocialMessage: <redacted>",
            '"rawSocialMessage": "<redacted>",',
            "rawSocialMessage: <redacted>\nnextField: summary-only",
        ):
            safe_redacted_findings = plugin_migration_redaction_findings_for_text(
                safe_redacted_text,
                workspace,
                "safe-redacted",
            )
            assert not any(
                finding["kind"] == "raw migration artifact"
                for finding in safe_redacted_findings
            ), safe_redacted_findings
        assert not plugin_migration_redaction_findings_for_text(
            "crypta:USK@<example-public-read-key>/profile/1/profile.json",
            workspace,
            "safe-placeholder",
        )
        java_file_uri_findings = plugin_migration_redaction_findings_for_text(
            "exportPath=file:/home/alice/plugin-export.json",
            workspace,
            "java-file-uri",
        )
        assert any(
            finding["kind"] == "local path" for finding in java_file_uri_findings
        ), java_file_uri_findings
        for leak_text in (
            '"privateKey": "MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop"',
            "formPassword=hunter2",
            "Cookie: sid=abcdef0123456789",
            "X-Crypta-App-Session: browser-session-secret",
        ):
            leak_findings = plugin_migration_redaction_findings_for_text(
                leak_text,
                workspace,
                "generic-leak",
            )
            assert any(
                finding["kind"] == "credential-or-path marker" for finding in leak_findings
            ), leak_findings
        try:
            unsafe_example.write_text(
                unsafe_example_text
                + '\n"privateKey": "MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop"\n'
                + "formPassword=hunter2\n"
                + "Cookie: sid=abcdef0123456789\n"
                + "X-Crypta-App-Session: browser-session-secret\n",
                encoding="utf-8",
            )
            generic_secret_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            unsafe_example.write_text(unsafe_example_text, encoding="utf-8")
        assert generic_secret_item.status == "fail", generic_secret_item
        assert "redactionChecksPass" in generic_secret_item.details["errors"], (
            generic_secret_item
        )
        generic_secret_json = json.dumps(generic_secret_item.to_json())
        for leaked_value in (
            "MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop",
            "hunter2",
            "sid=abcdef0123456789",
            "browser-session-secret",
        ):
            assert leaked_value not in generic_secret_json, generic_secret_item
        broken_negative_fixture = (
            workspace
            / "tools/release-certification/fixtures/plugin-migration-redaction-raw-social-message.json"
        )
        broken_negative_fixture_text = broken_negative_fixture.read_text(encoding="utf-8")
        try:
            write_json(
                broken_negative_fixture,
                {
                    "legacyPluginId": "legacy.example",
                    "newAppId": "app-id.example",
                    "summary": "summary-only",
                },
            )
            broken_negative_fixture_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            broken_negative_fixture.write_text(
                broken_negative_fixture_text, encoding="utf-8"
            )
        assert broken_negative_fixture_item.status == "fail", broken_negative_fixture_item
        assert "redactionChecksPass" in broken_negative_fixture_item.details["errors"], (
            broken_negative_fixture_item
        )
        negative_redaction_findings = broken_negative_fixture_item.details.get(
            "redactionFindings", []
        )
        assert any(
            finding.get("kind") == "negative redaction fixture failed"
            and finding.get("path")
            == "tools/release-certification/fixtures/plugin-migration-redaction-raw-social-message.json"
            for finding in negative_redaction_findings
        ), broken_negative_fixture_item
        assert (
            "synthetic-private-message-body"
            not in json.dumps(broken_negative_fixture_item.to_json())
        ), broken_negative_fixture_item
        try:
            broken_negative_fixture.unlink()
            missing_negative_fixture_item = collect_legacy_plugin_migration_finalization_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            broken_negative_fixture.write_text(
                broken_negative_fixture_text, encoding="utf-8"
            )
        assert missing_negative_fixture_item.status == "fail", missing_negative_fixture_item
        assert "redactionChecksPass" in missing_negative_fixture_item.details["errors"], (
            missing_negative_fixture_item
        )
        missing_negative_fixture_findings = missing_negative_fixture_item.details.get(
            "redactionFindings", []
        )
        assert any(
            finding.get("kind") == "negative redaction fixture failed"
            and finding.get("path")
            == "tools/release-certification/fixtures/plugin-migration-redaction-raw-social-message.json"
            and "missing fixture" in finding.get("detectedKinds", [])
            for finding in missing_negative_fixture_findings
        ), missing_negative_fixture_item
        freeze_policy = workspace / "docs/legacy-plugin-freeze-policy.md"
        freeze_policy_text = freeze_policy.read_text(encoding="utf-8")
        try:
            freeze_policy.unlink()
            missing_freeze_policy_item = collect_legacy_plugin_freeze_policy_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            freeze_policy.write_text(freeze_policy_text, encoding="utf-8")
        assert missing_freeze_policy_item.status == "fail", missing_freeze_policy_item
        assert "freezePolicyDocumentExists" in missing_freeze_policy_item.details["errors"], (
            missing_freeze_policy_item
        )
        freeze_migration_guide = workspace / "docs/legacy-plugin-migration-guide.md"
        freeze_migration_guide_text = freeze_migration_guide.read_text(encoding="utf-8")
        try:
            freeze_migration_guide.write_text(
                freeze_migration_guide_text.replace("legacy-plugin-freeze-policy.md, ", ""),
                encoding="utf-8",
            )
            missing_freeze_link_item = collect_legacy_plugin_freeze_policy_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            freeze_migration_guide.write_text(freeze_migration_guide_text, encoding="utf-8")
        assert missing_freeze_link_item.status == "fail", missing_freeze_link_item
        assert "migrationGuideLinksFreezePolicy" in missing_freeze_link_item.details["errors"], (
            missing_freeze_link_item
        )
        social_inbox_app_js = workspace / "apps/social-inbox/src/staged/static/app.js"
        original_social_inbox_js = social_inbox_app_js.read_text(encoding="utf-8")
        try:
            social_inbox_app_js.write_text(
                original_social_inbox_js
                + "\nfetch('http://127.0.0.1:8888/api/v1/app-services');\n",
                encoding="utf-8",
            )
            direct_local_endpoint_item = collect_legacy_plugin_social_inbox_spike_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            social_inbox_app_js.write_text(original_social_inbox_js, encoding="utf-8")
        assert direct_local_endpoint_item.status == "fail", direct_local_endpoint_item
        assert "noDirectLocalEndpointReference" in direct_local_endpoint_item.details["errors"], (
            direct_local_endpoint_item
        )
        try:
            social_inbox_app_js.write_text(
                original_social_inbox_js
                + "\nCryptaPlatform.trust.score({ subjectKind: 'identity' });\n"
                + "\nfetch('/api/v1/trust-graph/score');\n",
                encoding="utf-8",
            )
            direct_trust_route_item = collect_social_inbox_rc_threading_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            social_inbox_app_js.write_text(original_social_inbox_js, encoding="utf-8")
        assert direct_trust_route_item.status == "fail", direct_trust_route_item
        assert "social inbox RC threading check failed: trustGraphMediatedOnly" in (
            direct_trust_route_item.details["errors"]
        ), direct_trust_route_item
        assert evidence_by_id["reference-app.feed-reader"]["status"] == "pass"
        assert evidence_by_id["reference-app.feed-reader-subscriptions"]["status"] == "pass"
        assert evidence_by_id["reference-app.feed-reader-app-data"]["status"] == "pass"
        assert evidence_by_id["reference-app.trust-graph"]["status"] == "pass"
        assert evidence_by_id["reference-app.trust-graph-durable-exchange"]["status"] == "pass"
        assert evidence_by_id["reference-app.trust-graph-app-data-preview"]["status"] == "pass"
        assert evidence_by_id["app-platform.trust-graph-preview"]["status"] == "pass"
        assert (
            evidence_by_id["app-platform.trust-graph-rc-scope-and-safety"]["status"] == "pass"
        )
        assert evidence_by_id["app-platform.trust-graph-durable-store"]["status"] == "pass"
        assert evidence_by_id["app-platform.trust-graph-exchange"]["status"] == "pass"
        assert evidence_by_id["app-platform.trust-statement-signing"]["status"] == "pass"
        assert evidence_by_id["app-platform.social-message-signing"]["status"] == "pass"
        migration_guide = workspace / "docs/legacy-plugin-migration-guide.md"
        migration_guide_text = migration_guide.read_text(encoding="utf-8")
        try:
            migration_guide.unlink()
            missing_guide_item = collect_legacy_plugin_migration_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            migration_guide.write_text(migration_guide_text, encoding="utf-8")
        assert missing_guide_item.status == "fail", missing_guide_item
        assert "guideExists" in missing_guide_item.details["errors"], missing_guide_item
        registry_source = (
            workspace
            / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java"
        )
        registry_source_text = registry_source.read_text(encoding="utf-8")
        try:
            registry_source.write_text(
                registry_source_text.replace(
                    "securityLevelsWave3Redirect(),",
                    'securityLevelsWave3Redirect(),\n'
                    '          wave3Redirect("diagnostic", "Diagnostic", "/diagnostic/", '
                    '"/app/node/#diagnostics", "Shell diagnostics", "Wrong.", false),',
                ),
                encoding="utf-8",
            )
            extra_wave_three_item = collect_legacy_removal_wave_three_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            registry_source.write_text(registry_source_text, encoding="utf-8")
        assert extra_wave_three_item.status == "fail", extra_wave_three_item
        assert "waveThreeIdsMatch" in extra_wave_three_item.details["errors"], (
            extra_wave_three_item
        )
        removal_policy_source = (
            workspace
            / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRemovalPolicy.java"
        )
        removal_policy_text = removal_policy_source.read_text(encoding="utf-8")
        try:
            removal_policy_source.write_text(
                removal_policy_text.replace(
                    "legacyFallback=diagnostic-export", "legacyFallback=unexpected"
                ),
                encoding="utf-8",
            )
            missing_diagnostic_marker_item = collect_legacy_removal_wave_four_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            removal_policy_source.write_text(removal_policy_text, encoding="utf-8")
        assert missing_diagnostic_marker_item.status == "fail", missing_diagnostic_marker_item
        assert "diagnosticFallbackMarkerPolicyExact" in missing_diagnostic_marker_item.details[
            "errors"
        ], missing_diagnostic_marker_item
        plugin_manager_source = (
            workspace
            / "runtime-node/src/main/java/network/crypta/pluginmanager/PluginManager.java"
        )
        plugin_manager_source.parent.mkdir(parents=True, exist_ok=True)
        try:
            plugin_manager_source.write_text(
                "package network.crypta.pluginmanager; public final class PluginManager {}\n",
                encoding="utf-8",
            )
            plugin_runtime_item = collect_legacy_plugin_freeze_policy_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            plugin_manager_source.unlink(missing_ok=True)
        assert plugin_runtime_item.status == "fail", plugin_runtime_item
        assert "noRuntimePluginSurfaceViolations" in plugin_runtime_item.details["errors"], (
            plugin_runtime_item
        )
        plugin_static_import_source = (
            workspace
            / "runtime-node/src/main/java/network/crypta/runtime/PluginImportProbe.java"
        )
        plugin_static_import_source.parent.mkdir(parents=True, exist_ok=True)
        try:
            plugin_static_import_source.write_text(
                "package network.crypta.runtime;\n"
                "import static network.crypta.pluginmanager.PluginManager.start;\n"
                "final class PluginImportProbe {}\n",
                encoding="utf-8",
            )
            plugin_static_import_item = collect_legacy_plugin_freeze_policy_evidence(
                dataclasses.replace(settings, mode="release-candidate")
            )
        finally:
            plugin_static_import_source.unlink(missing_ok=True)
        assert plugin_static_import_item.status == "fail", plugin_static_import_item
        assert "noRuntimePluginSurfaceViolations" in plugin_static_import_item.details["errors"], (
            plugin_static_import_item
        )
        assert any(
            violation["path"]
            == "runtime-node/src/main/java/network/crypta/runtime/PluginImportProbe.java"
            and violation["reason"] == "pluginmanager import"
            for violation in plugin_static_import_item.details["runtimeSurfaceViolations"]
        ), plugin_static_import_item
        feed_reader_app_js = workspace / "apps/feed-reader/src/staged/static/app.js"
        original_feed_reader_js = feed_reader_app_js.read_text(encoding="utf-8")
        try:
            feed_reader_app_js.write_text(
                "const appId = 'feed-reader';\n"
                "CryptaPlatform.bootstrap.load({ appId });\n"
                "CryptaPlatform.feed.parseSnapshot('{}');\n"
                "CryptaPlatform.feed.publishSnapshot({ snapshot: { type: 'crypta.feed.snapshot.v1', items: [] } });\n"
                "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
                encoding="utf-8",
            )
            missing_fetch_settings = dataclasses.replace(settings, mode="release-candidate")
            missing_fetch_item = collect_feed_reader_reference_app_evidence(missing_fetch_settings)
        finally:
            feed_reader_app_js.write_text(original_feed_reader_js, encoding="utf-8")
        assert missing_fetch_item.status == "fail", missing_fetch_item
        assert (
            missing_fetch_item.details["checks"]["usesContentFetchRouteOrHelper"] is False
        ), missing_fetch_item
        try:
            feed_reader_app_js.write_text(
                "const appId = 'feed-reader';\n"
                "CryptaPlatform.bootstrap.load({ appId });\n"
                "CryptaPlatform.content.fetchText({ uri: 'USK@redacted/feed/0/feed.json' });\n"
                "CryptaPlatform.feed.fetchSnapshot({ uri: 'USK@redacted/feed/0/feed.json' });\n"
                "CryptaPlatform.feed.publishSnapshot({ snapshot: { type: 'crypta.feed.snapshot.v1', items: [] } });\n"
                "CryptaPlatform.queue.snapshot({ page: 'uploads' });\n",
                encoding="utf-8",
            )
            missing_subscription_settings = dataclasses.replace(settings, mode="release-candidate")
            missing_subscription_item = collect_feed_reader_subscription_evidence(
                missing_subscription_settings
            )
        finally:
            feed_reader_app_js.write_text(original_feed_reader_js, encoding="utf-8")
        assert missing_subscription_item.status == "fail", missing_subscription_item
        assert (
            missing_subscription_item.details["checks"]["appUsesPlatformSubscriptionWorkflow"]
            is False
        ), missing_subscription_item
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
        for evidence_id in PUBLIC_BETA_SECURITY_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
        production_security_item = evidence_by_id["production-security.response-runbook"]
        assert production_security_item["status"] == "pass", production_security_item
        assert production_security_item["requiredForReleaseCandidate"] is True
        production_security_checks = production_security_item["details"]["checks"]
        assert production_security_checks["runbookModelValid"] is True, production_security_checks
        assert production_security_checks["sensitiveMarkersAbsent"] is True, production_security_checks
        assert "secretMarkersAbsent" not in production_security_checks, production_security_checks
        assert production_security_checks["operatorApiSummary"] is True, production_security_checks
        assert production_security_checks["webShellSummary"] is True, production_security_checks
        assert production_security_item["details"]["duplicateDrillIds"] == [], production_security_item
        assert set(production_security_item["details"]["drillIds"]) == set(
            PRODUCTION_SECURITY_REQUIRED_DRILLS
        )
        consent_item = evidence_by_id["app-platform.user-consent-flow"]
        assert consent_item["status"] == "pass", consent_item
        assert consent_item["requiredForReleaseCandidate"] is True
        consent_checks = consent_item["details"]["checks"]
        assert consent_checks["consentModelsPresent"] is True, consent_checks
        assert consent_checks["previewRoutesPresent"] is True, consent_checks
        assert consent_checks["automaticUpdateGatingPresent"] is True, consent_checks
        assert consent_checks["snapshotDigestAndStaleApprovalProtection"] is True, consent_checks
        assert consent_checks["webShellConsentUiPresent"] is True, consent_checks
        assert consent_checks["docsPresent"] is True, consent_checks
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
        assert evidence_by_id["app-update.scheduler"]["status"] == "pass"
        assert evidence_by_id["app-update.scheduler"]["requiredForReleaseCandidate"] is True
        scheduler_checks = evidence_by_id["app-update.scheduler"]["details"]["checks"]
        assert scheduler_checks["schedulerConfigPresent"] is True, scheduler_checks
        assert scheduler_checks["schedulerDelegatesToUpdateCheck"] is True, scheduler_checks
        assert scheduler_checks["schedulerManualPolicyDoesNotMutate"] is True, scheduler_checks
        assert scheduler_checks["schedulerPolicyDrivenChecks"] is True, scheduler_checks
        assert scheduler_checks["schedulerPerAppSerialized"] is True, scheduler_checks
        assert scheduler_checks["schedulerPathAndPrivateDataFree"] is True, scheduler_checks
        assert scheduler_checks["schedulerLifecycleDocumented"] is True, scheduler_checks
        assert evidence_by_id["app-update.live-catalog-refresh"]["status"] == "pass"
        live_catalog_refresh_checks = evidence_by_id["app-update.live-catalog-refresh"]["details"][
            "checks"
        ]
        assert (
            live_catalog_refresh_checks["schedulerSummaryPrivacyGuard"] is True
        ), live_catalog_refresh_checks
        assert all(
            isinstance(value, bool) for value in live_catalog_refresh_checks.values()
        ), live_catalog_refresh_checks
        assert evidence_by_id["app-update.rollback"]["status"] == "pass"
        assert evidence_by_id["app-update.rollback"]["requiredForReleaseCandidate"] is True
        rollback_checks = evidence_by_id["app-update.rollback"]["details"]["checks"]
        assert rollback_checks["restorePreviousBundleOnReplacementFailure"] is True, rollback_checks
        assert rollback_checks["mutableDirectoriesPreservedByUpdate"] is True, rollback_checks
        assert rollback_checks["mutableDirectoriesPreservedByRollback"] is True, rollback_checks
        migration_contract_item = evidence_by_id["app-update.data-migration-contract"]
        assert migration_contract_item["status"] == "pass", migration_contract_item
        assert migration_contract_item["requiredForReleaseCandidate"] is True
        migration_contract_checks = migration_contract_item["details"]["checks"]
        assert migration_contract_checks["manifestModelsAndParser"] is True, migration_contract_checks
        assert migration_contract_checks["snapshotBeforeReplacementAndRestoreOnFailure"] is True, (
            migration_contract_checks
        )
        assert migration_contract_checks["feedReaderDeclaresMigrationExample"] is True, (
            migration_contract_checks
        )
        assert migration_contract_checks["trustGraphDeclaresMigrationExample"] is True, (
            migration_contract_checks
        )
        for evidence_id in OPERATOR_BETA_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]["status"] == "pass", evidence_by_id[evidence_id]
            assert evidence_by_id[evidence_id]["requiredForReleaseCandidate"] is True
        assert (
            evidence_by_id["operator-beta.support-bundle-redaction"]["details"]["checks"][
                "redactorApplied"
            ]
            is True
        )
        assert (
            evidence_by_id["operator-beta.web-shell"]["details"]["checks"]["loadsOperatorEndpoints"]
            is True
        )
        privacy_diagnostics_item = evidence_by_id[PRIVACY_BETA_DIAGNOSTICS_EVIDENCE_ID]
        assert privacy_diagnostics_item["status"] == "pass", privacy_diagnostics_item
        assert privacy_diagnostics_item["requiredForReleaseCandidate"] is True
        privacy_diagnostics_checks = privacy_diagnostics_item["details"]["checks"]
        assert privacy_diagnostics_checks["redactionFixtures"] is True, privacy_diagnostics_checks
        assert privacy_diagnostics_checks["productionBlockers"] is True, privacy_diagnostics_checks
        privacy_fixture_entries = privacy_diagnostics_item["details"]["fixtures"]["entries"]
        assert all(entry["redactedFindingCount"] == 0 for entry in privacy_fixture_entries), (
            privacy_fixture_entries
        )
        assert all(
            entry["rawFindingCount"] > 0
            for entry in privacy_fixture_entries
            if not entry["expectedSafe"]
        ), privacy_fixture_entries
        private_insert_text_entry = next(
            entry
            for entry in privacy_fixture_entries
            if entry["fixture"] == "support-bundle-redaction-private-insert-uri-text.json"
        )
        assert "content-uri" in private_insert_text_entry["findings"], private_insert_text_entry
        assert private_insert_text_entry["omittedFieldCount"] == 0, private_insert_text_entry
        encoded = json.dumps(summary, sort_keys=True)
        for forbidden in ("CRYPTAD_APP_TOKEN=secret", "formPassword=hunter2", str(workspace)):
            assert forbidden not in encoded, f"self-test leaked {forbidden}"
        for forbidden in (
            "$.privateInsertUri",
            "$.rawProfileDocument",
            "$.rawFeedSnapshot",
            "$.rawTrustStatement",
            "$.rawSocialMessage",
            "$.rawAppDataValue",
            "$.appServiceInvocationBody",
        ):
            assert forbidden not in encoded, f"self-test exported raw fixture finding path {forbidden}"
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
