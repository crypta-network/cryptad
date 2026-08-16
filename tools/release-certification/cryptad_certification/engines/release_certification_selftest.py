"""Implementation segment for the selftest portion of ``release_certification.py``."""

from __future__ import annotations

def run_self_test(repo_root: Path) -> None:
    for unsafe_redaction_status in ('fail', 'warn', 'missing', 'skip', 'success', None, True):
        assert redaction_signal_has_unwaivable_findings({'status': unsafe_redaction_status}), unsafe_redaction_status
    assert not redaction_signal_has_unwaivable_findings({'status': 'pass'})
    fixture_dir = repo_root / 'tools/release-certification/fixtures'
    with tempfile.TemporaryDirectory(prefix='cryptad-cert-self-test-') as temp_name:
        workspace = Path(temp_name) / 'repo'
        out_dir = workspace / 'build/release-certification'
        (workspace / 'build/interop-smoke').mkdir(parents=True)
        (workspace / 'build/interop-extended').mkdir(parents=True)
        (workspace / 'build/perf-smoke').mkdir(parents=True)
        (out_dir / 'app-platform-smoke').mkdir(parents=True)
        (out_dir / 'network-scale-soak').mkdir(parents=True)
        (out_dir / 'multi-node-beta-soak').mkdir(parents=True)
        for spec in ecosystem_matrix_row_specs():
            for doc_path in spec.docs:
                source_doc = repo_root / doc_path
                target_doc = workspace / doc_path
                target_doc.parent.mkdir(parents=True, exist_ok=True)
                assert source_doc.is_file(), f'matrix doc path missing: {doc_path}'
                shutil.copy(source_doc, target_doc)
        docs_check_paths = {*app_platform_docs_check.REQUIRED_DOCS, *app_platform_docs_check.REQUIRED_PORTAL_LINKS, *app_platform_docs_check.ISSUE_TEMPLATES, app_platform_docs_check.PUBLIC_BETA_KNOWN_ISSUES_METADATA, app_platform_docs_check.PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE, *app_platform_docs_check.PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES, 'README.md', 'samples/third-party/hello-stable-app/README.md', 'tools/interop/README.md', 'tools/perf/README.md'}
        for source_doc in repo_root.glob('docs/**/*.md'):
            target_doc = workspace / source_doc.relative_to(repo_root)
            target_doc.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source_doc, target_doc)
        for doc_path in sorted(docs_check_paths):
            source_doc = repo_root / doc_path
            target_doc = workspace / doc_path
            target_doc.parent.mkdir(parents=True, exist_ok=True)
            assert source_doc.is_file(), f'docs-check path missing: {doc_path}'
            shutil.copy(source_doc, target_doc)
        shutil.copy(fixture_dir / 'self-test-interop-smoke.json', workspace / 'build/interop-smoke/summary.json')
        shutil.copy(fixture_dir / 'self-test-interop-extended.json', workspace / 'build/interop-extended/summary.json')
        shutil.copy(fixture_dir / 'self-test-perf-smoke.json', workspace / 'build/perf-smoke/summary.json')
        shutil.copy(fixture_dir / 'self-test-app-platform-smoke.json', out_dir / 'app-platform-smoke/summary.json')
        shutil.copy(fixture_dir / 'self-test-network-scale-soak.json', out_dir / 'network-scale-soak/summary.json')
        multi_node_config = multi_node_beta_soak.validate_config(multi_node_beta_soak.load_config(fixture_dir / 'self-test-multi-node-beta-soak.json'))
        multi_node_summary = multi_node_beta_soak.build_summary(multi_node_config, out_dir=out_dir / 'multi-node-beta-soak', base_dir=fixture_dir)
        write_json(out_dir / 'multi-node-beta-soak/summary.json', multi_node_summary)
        write_text(out_dir / 'multi-node-beta-soak/multi-node-beta-soak-summary.md', multi_node_beta_soak.render_report(multi_node_summary))
        security_drills_summary = out_dir / 'security-drills/security-drills-summary.json'
        security_response_runbook.drill_run_all(repo_root / security_response_runbook.DEFAULT_MODEL, out_dir / 'security-drills', security_drills_summary, release_id='cryptad-production-beta-self-test', generated_at=security_response_runbook.utc_now())
        settings = Settings(workspace_root=workspace.resolve(), out_dir=out_dir.resolve(), mode='release-candidate', interop_smoke_summary=workspace / 'build/interop-smoke/summary.json', interop_extended_summary=workspace / 'build/interop-extended/summary.json', perf_smoke_summary=workspace / 'build/perf-smoke/summary.json', app_platform_summary=out_dir / 'app-platform-smoke/summary.json', live_network_summary=out_dir / 'live-network-beta-smoke/summary.json', network_scale_soak_summary=out_dir / 'network-scale-soak/summary.json', live_network_beta_enabled=False, live_network_beta_required=False, multi_node_soak_summary=out_dir / 'multi-node-beta-soak/summary.json', multi_node_soak_required=False, security_drills_summary=security_drills_summary, waivers={}, metadata={'selfTest': 'true', 'candidateReleaseId': 'cryptad-production-beta-self-test'}, skip_git_metadata=True, history_dir=workspace / 'build/no-auto-history')
        security_item = security_drills_evidence(security_drills_summary, workspace.resolve(), out_dir.resolve(), 'release-candidate')
        assert security_item.status == 'pass', security_item
        missing_artifacts_dir = workspace / 'security-drills-missing-artifacts'
        missing_artifacts_summary = missing_artifacts_dir / 'security-drills-summary.json'
        security_drills_summary_value = read_json(security_drills_summary)
        assert isinstance(security_drills_summary_value, dict), security_drills_summary
        write_json(missing_artifacts_summary, security_drills_summary_value)
        missing_artifacts_item = security_drills_evidence(missing_artifacts_summary, workspace.resolve(), out_dir.resolve(), 'release-candidate')
        assert missing_artifacts_item.status == 'fail', missing_artifacts_item
        assert any(('security drill artifact for reviewer-key-compromise is missing' == error for error in missing_artifacts_item.details.get('validationErrors', []))), missing_artifacts_item.details
        tampered_artifacts_dir = workspace / 'security-drills-tampered-artifacts'
        shutil.copytree(security_drills_summary.parent, tampered_artifacts_dir)
        tampered_summary_path = tampered_artifacts_dir / 'security-drills-summary.json'
        tampered_artifact_path = tampered_artifacts_dir / security_response_runbook.DRILL_OUTPUT_FILENAMES['reviewer-key-compromise']
        tampered_artifact = read_json(tampered_artifact_path)
        assert isinstance(tampered_artifact, dict), tampered_artifact_path
        tampered_artifact['steps'][0]['safeSummary'] = 'Tampered but redaction-safe drill text.'
        write_json(tampered_artifact_path, tampered_artifact)
        tampered_summary = read_json(tampered_summary_path)
        assert isinstance(tampered_summary, dict), tampered_summary_path
        for artifact_entry in tampered_summary.get('artifacts', []):
            if isinstance(artifact_entry, dict) and artifact_entry.get('scenario') == 'reviewer-key-compromise':
                artifact_entry['digest'] = security_response_runbook.sha256_path(tampered_artifact_path)
                break
        write_json(tampered_summary_path, tampered_summary)
        tampered_artifacts_item = security_drills_evidence(tampered_summary_path, workspace.resolve(), out_dir.resolve(), 'release-candidate')
        assert tampered_artifacts_item.status == 'fail', tampered_artifacts_item
        assert any(('security drill artifact for reviewer-key-compromise failed offline verification' == error for error in tampered_artifacts_item.details.get('validationErrors', []))), tampered_artifacts_item.details
        stale_artifacts_dir = workspace / 'security-drills-stale-artifacts'
        stale_artifacts_summary = stale_artifacts_dir / 'security-drills-summary.json'
        fresh_summary_generated_at = security_response_runbook.utc_now()
        fresh_summary_time = security_response_runbook.parse_timestamp(fresh_summary_generated_at)
        assert fresh_summary_time is not None, fresh_summary_generated_at
        stale_artifact_generated_at = (fresh_summary_time - dt.timedelta(days=security_response_runbook.DEFAULT_MAX_AGE_DAYS + 2)).isoformat().replace('+00:00', 'Z')
        security_response_runbook.drill_run_all(repo_root / security_response_runbook.DEFAULT_MODEL, stale_artifacts_dir, stale_artifacts_summary, release_id='cryptad-production-beta-self-test', generated_at=stale_artifact_generated_at)
        stale_summary = read_json(stale_artifacts_summary)
        assert isinstance(stale_summary, dict), stale_artifacts_summary
        stale_summary['generatedAt'] = fresh_summary_generated_at
        write_json(stale_artifacts_summary, stale_summary)
        stale_artifacts_item = security_drills_evidence(stale_artifacts_summary, workspace.resolve(), out_dir.resolve(), 'release-candidate')
        assert stale_artifacts_item.status == 'fail', stale_artifacts_item
        assert any((str(error).startswith('security drill artifact for reviewer-key-compromise is stale:') for error in stale_artifacts_item.details.get('validationErrors', []))), stale_artifacts_item.details
        redaction_unsafe_security_drills = read_json(security_drills_summary)
        assert isinstance(redaction_unsafe_security_drills, dict), security_drills_summary
        redaction_unsafe_security_drills['redaction'] = {'status': 'fail', 'rawSensitiveMaterialExcluded': True, 'findings': ['safe redaction finding: support bundle material excluded']}
        redaction_unsafe_security_drills_path = workspace / 'redaction-unsafe-security-drills-summary.json'
        write_json(redaction_unsafe_security_drills_path, redaction_unsafe_security_drills)
        redaction_unsafe_security_item = security_drills_evidence(redaction_unsafe_security_drills_path, workspace.resolve(), out_dir.resolve(), 'release-candidate')
        assert redaction_unsafe_security_item.status == 'fail', redaction_unsafe_security_item
        assert 'safe redaction finding: support bundle material excluded' in redaction_unsafe_security_item.details.get('redactionFindings', []), redaction_unsafe_security_item.details
        production_beta_drills_summary = out_dir / 'security-drills-production-beta/security-drills-summary.json'
        security_response_runbook.drill_run_all(repo_root / security_response_runbook.DEFAULT_MODEL, out_dir / 'security-drills-production-beta', production_beta_drills_summary, release_id='cryptad-production-beta-self-test', generated_at=security_response_runbook.utc_now(), mode='production-beta')
        production_beta_security_item = security_drills_evidence(production_beta_drills_summary, workspace.resolve(), out_dir.resolve(), 'release-candidate')
        assert production_beta_security_item.status == 'pass', production_beta_security_item
        assert production_beta_security_item.details['mode'] == 'production-beta', production_beta_security_item.details
        write_json(settings.live_network_summary, {'schemaVersion': 1, 'kind': 'live-network-beta-smoke', 'mode': 'release-candidate', 'enabled': True, 'required': True, 'status': 'fail', 'node': {'baseUrlShape': 'http://127.0.0.1:<port>', 'localhostOnly': True}, 'evidence': [{'id': 'live-network-beta.preflight', 'status': 'fail', 'requiredForReleaseCandidate': True, 'summary': 'stale live summary should be ignored when live beta is disabled.', 'source': 'live-network-beta-self-test', 'details': {'enabled': True, 'required': True}}], 'redaction': {'status': 'fail'}})
        write_text(settings.live_network_summary.parent / 'live-network-beta-smoke-report.md', '# stale live report\n\nThis stale report should not be copied when live-network beta is disabled.\n')
        failing_app_platform_summary = read_json(settings.app_platform_summary)
        assert failing_app_platform_summary is not None, settings.app_platform_summary
        for entry in failing_app_platform_summary['evidence']:
            if entry.get('id') == 'production-security.response-runbook':
                entry['status'] = 'fail'
                entry['summary'] = 'Security response runbook integration failed.'
                entry['details'] = {'checks': {'runbookDocExists': False}}
                break
        else:
            raise AssertionError('production-security.response-runbook fixture evidence is missing')
        failing_app_platform_summary_path = out_dir / 'app-platform-smoke/failing-security-response-summary.json'
        write_json(failing_app_platform_summary_path, failing_app_platform_summary)
        failing_settings = dataclasses.replace(settings, app_platform_summary=failing_app_platform_summary_path)
        failing_evidence_by_id = {item.id: item for item in gather_evidence(failing_settings, WaiverContext())}
        failing_security_evidence = failing_evidence_by_id['production-security.response-runbook']
        assert failing_security_evidence.status == 'fail', failing_security_evidence
        assert failing_security_evidence.details['componentStatuses'] == {'appPlatformRunbook': 'fail', 'securityDrills': 'pass'}, failing_security_evidence.details
        summary, exit_code = run(settings)
        assert exit_code == 0, summary
        assert summary['status'] == 'warn', summary
        assert summary['promotionDecision'] == 'PASS WITH WARNINGS', summary
        assert summary['releaseCandidatePassed'] is True, summary
        assert summary['ecosystemRcDecision'] == 'PASS_WITH_WARNINGS', summary
        assert summary['ecosystemRcPassed'] is True, summary
        assert summary['ecosystemRcGate']['id'] == ECOSYSTEM_RC_GATE_ID, summary
        assert summary['ecosystemRcGate']['status'] == 'warn', summary
        assert not any(('live-network-beta' in artifact for artifact in summary['copiedArtifacts'])), summary['copiedArtifacts']
        assert not (out_dir / 'artifacts/live-network-beta-smoke-summary.json').exists(), summary['copiedArtifacts']
        assert not (out_dir / 'artifacts/live-network-beta-smoke-report.md').exists(), summary['copiedArtifacts']
        assert summary['waivers'] == {}, summary
        assert summary['waiverRecords'] == [], summary
        assert summary['historyComparison']['status'] == 'warn', summary
        assert (out_dir / HISTORY_COMPARISON_FILE_NAME).is_file(), summary
        assert (out_dir / HISTORY_COMPARISON_REPORT_FILE_NAME).is_file(), summary
        assert (out_dir / ECOSYSTEM_MATRIX_FILE_NAME).is_file(), summary
        assert (out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).is_file(), summary
        matrix = read_json(out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        assert matrix is not None, summary
        assert matrix['schemaVersion'] == ECOSYSTEM_MATRIX_SCHEMA_VERSION, matrix
        assert matrix['kind'] == 'ecosystem-certification-matrix', matrix
        assert matrix['coverage']['requiredEvidenceCovered'] is True, matrix
        assert matrix['coverage']['ecosystemGatesCovered'] is True, matrix
        assert matrix['coverage']['firstPartyAppsCovered'] is True, matrix
        assert matrix['coverage']['docsCovered'] is True, matrix
        assert matrix['coverage']['redactionPassed'] is True, matrix
        assert set(matrix['coverage']['coveredFirstPartyApps']) == set(EXPECTED_FIRST_PARTY_APPS), matrix
        matrix_rows_by_id = {row['id']: row for row in matrix['rows']}
        pr253_app_service_evidence_ids = APP_SERVICE_DEPENDENCY_AND_GRANT_BUNDLE_EVIDENCE_IDS
        for row_id in ('app-update', 'first-party-beta-catalog', 'production-catalog-channels', 'first-party-app-maintenance-policy', 'ecosystem-security-advisory-and-revocation', 'production-security-response-runbook', 'developer-beta-toolkit', 'app-platform-beta-docs-and-program', 'third-party-developer-beta-program', 'app-store-submission-and-review', 'review-governance-transparency', 'app-vault-and-generated-documents', 'content-fetch-and-networked-content', 'app-data-backup-restore-portability', 'trust-graph-preview-platform', 'social-inbox-preview', 'legacy-plugin-migration', 'apphost-sandbox-provider', 'public-beta-security-hardening', 'app-platform-user-consent-flow', 'operator-beta-ux-and-recovery', 'operator-rc-recovery-and-support-workflow', 'platform-api-contract', 'interop-smoke', 'performance-smoke', 'live-network-beta-certification', 'legacy-retirement', 'ecosystem-certification-matrix', ECOSYSTEM_RC_MATRIX_ROW_ID, 'app-service-discovery-and-grants'):
            assert row_id in matrix_rows_by_id, row_id
        rc_gate_row = matrix_rows_by_id[ECOSYSTEM_RC_MATRIX_ROW_ID]
        assert ECOSYSTEM_RC_EVIDENCE_ID in rc_gate_row['requiredEvidenceIds'], rc_gate_row
        assert ECOSYSTEM_RC_GATE_ID in rc_gate_row['gateIds'], rc_gate_row
        app_services_row = matrix_rows_by_id['app-service-discovery-and-grants']
        for evidence_id in pr253_app_service_evidence_ids:
            assert evidence_id in app_services_row['requiredEvidenceIds'], app_services_row
        app_store_row = matrix_rows_by_id['app-store-submission-and-review']
        for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS:
            assert evidence_id in app_store_row['requiredEvidenceIds'], app_store_row
        disabled_live_row = matrix_rows_by_id['live-network-beta-certification']
        assert disabled_live_row['status'] == 'pass', disabled_live_row
        assert disabled_live_row['releaseBlocker'] is False, disabled_live_row
        assert not any((issue_id.startswith('evidence.live-network-beta.') for issue_id in disabled_live_row.get('issueIds', []))), disabled_live_row
        stable_not_requested_row = matrix_rows_by_id['stable-1-0-readiness']
        assert stable_not_requested_row['status'] == 'pass', stable_not_requested_row
        assert stable_not_requested_row['releaseBlocker'] is False, stable_not_requested_row
        assert stable_not_requested_row['previousStatus'] == 'pass', stable_not_requested_row
        assert stable_not_requested_row['regressionStatus'] == 'unchanged', stable_not_requested_row
        assert stable_not_requested_row['details']['notRequested'] is True, stable_not_requested_row
        assert stable_not_requested_row['details']['required'] is False, stable_not_requested_row
        assert not any((issue_id.startswith('evidence.stable-1.0.') for issue_id in stable_not_requested_row.get('issueIds', []))), stable_not_requested_row
        covered_evidence_ids = {evidence_id for row in matrix['rows'] for evidence_id in row.get('evidenceIds', [])}
        for evidence_id, item in {item['id']: item for item in summary['evidence']}.items():
            if item['requiredForReleaseCandidate']:
                assert evidence_id in covered_evidence_ids, evidence_id
        for evidence_id in ('app-platform.trust-graph-preview', 'app-platform.trust-graph-durable-store', 'app-platform.trust-graph-exchange', 'app-platform.trust-statement-signing', 'app-platform.social-message-signing', 'app-review.governance', 'app-review.reviewer-key-lifecycle', 'app-review.transparency-log', 'app-review.review-history-api', 'app-review.first-party-review-chain', 'reference-app.trust-graph', 'reference-app.trust-graph-durable-exchange', 'reference-app.social-inbox', 'reference-app.social-inbox-rc-threading', 'app-platform.trust-social-beta-hardening', 'app-platform.trust-social-content-format-profiles', 'migration.social-mail-preview', 'legacy-plugin.freeze-policy', 'legacy-plugin.migration-guide', 'legacy-plugin.social-inbox-spike', 'legacy-plugin.migration-finalization', 'legacy-admin.removal-wave-2', 'legacy-admin.removal-wave-3', 'legacy-admin.removal-wave-4', 'legacy-admin.removal-wave-5', 'legacy-admin.final-admin-surface', 'legacy-admin.browse-retained', 'legacy-admin.emergency-fallback-retained', 'app-platform.docs-portal', 'app-platform.beta-program', 'app-platform.beta-tutorials', 'app-platform.docs-redaction', 'app-data.backup-restore-portability', 'app-platform.user-consent-flow', 'operator-beta.app-data-backup-restore', *pr253_app_service_evidence_ids, ECOSYSTEM_RC_EVIDENCE_ID, *OPERATOR_RC_EVIDENCE_IDS, *ECOSYSTEM_SECURITY_EVIDENCE_IDS):
            assert evidence_id in covered_evidence_ids, evidence_id
        gate_ids = {gate['id'] for gate in summary['ecosystemGates']}
        assert ECOSYSTEM_RC_GATE_ID in gate_ids, gate_ids
        covered_gate_ids = {gate_id for row in matrix['rows'] for gate_id in row.get('gateIds', [])}
        assert gate_ids <= covered_gate_ids, (gate_ids, covered_gate_ids)
        assert summary['ecosystemMatrixPath'].endswith(ECOSYSTEM_MATRIX_FILE_NAME), summary
        assert summary['ecosystemMatrixReportPath'].endswith(ECOSYSTEM_MATRIX_REPORT_FILE_NAME), summary
        assert summary['ecosystemMatrix']['schemaVersion'] == ECOSYSTEM_MATRIX_SCHEMA_VERSION, summary
        assert summary['ecosystemMatrix']['rowCount'] == len(matrix['rows']), summary
        evidence_by_id = {item['id']: item for item in summary['evidence']}
        assert evidence_by_id['release-certification.ecosystem-matrix']['requiredForReleaseCandidate'] is True
        assert evidence_by_id[ECOSYSTEM_RC_EVIDENCE_ID]['requiredForReleaseCandidate'] is True
        assert evidence_by_id[ECOSYSTEM_RC_EVIDENCE_ID]['status'] == 'warn', evidence_by_id
        assert evidence_by_id['app-update.lifecycle']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.user-consent-flow']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.user-consent-flow']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['app-update.lifecycle']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['app-update.scheduler']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-update.scheduler']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['app-update.rollback']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-update.rollback']['requiredForReleaseCandidate'] is True
        for evidence_id in ECOSYSTEM_SECURITY_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]['status'] == 'pass', evidence_by_id
            assert evidence_by_id[evidence_id]['requiredForReleaseCandidate'] is True
        for evidence_id in OPERATOR_RC_EVIDENCE_IDS:
            assert evidence_by_id[evidence_id]['status'] == 'pass', evidence_by_id
            assert evidence_by_id[evidence_id]['requiredForReleaseCandidate'] is True
        for evidence_id in ('app-platform.docs-portal', 'app-platform.beta-program', 'app-platform.beta-tutorials', 'app-platform.docs-redaction'):
            assert evidence_by_id[evidence_id]['status'] == 'pass', evidence_by_id
            assert evidence_by_id[evidence_id]['requiredForReleaseCandidate'] is True
        report_text = (out_dir / REPORT_FILE_NAME).read_text(encoding='utf-8')
        for evidence_id in ('app-platform.docs-portal', 'app-platform.beta-program', 'app-platform.beta-tutorials', 'app-platform.docs-redaction', 'app-data.backup-restore-portability', 'operator-beta.app-data-backup-restore'):
            assert f'### `{evidence_id}`' in report_text, evidence_id
        assert 'redactionFindings' in report_text, report_text
        assert evidence_by_id['app-vault.capabilities']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-vault.capabilities']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['app-platform.identity-profile-publish']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.generated-document-insert']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.content-fetch']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.content-subscriptions']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['network-content.subscription-scheduler']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.durable-app-data-store']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-data.backup-restore-portability']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-data.backup-restore-portability']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['operator-beta.app-data-backup-restore']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.trust-graph-preview']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.trust-graph-preview']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['app-platform.trust-graph-durable-store']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.trust-graph-exchange']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.trust-statement-signing']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.trust-statement-signing']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['app-platform.social-message-signing']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['app-platform.social-message-signing']['requiredForReleaseCandidate'] is True
        for evidence_id in ('app-review.governance', 'app-review.reviewer-key-lifecycle', 'app-review.transparency-log', 'app-review.review-history-api', 'app-review.first-party-review-chain'):
            assert evidence_by_id[evidence_id]['status'] == 'pass', evidence_by_id
            assert evidence_by_id[evidence_id]['requiredForReleaseCandidate'] is True
        assert evidence_by_id['reference-app.profile-publisher']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.profile-publisher-app-data']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.feed-reader']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.feed-reader-subscriptions']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.feed-reader-app-data']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.trust-graph']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.trust-graph']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['reference-app.trust-graph-durable-exchange']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['reference-app.trust-graph-app-data-preview']['status'] == 'pass', evidence_by_id
        for evidence_id in ('reference-app.social-inbox', 'reference-app.social-inbox-signed-message', 'reference-app.social-inbox-subscriptions', 'reference-app.social-inbox-app-data', 'reference-app.social-inbox-trust-annotations', 'reference-app.social-inbox-rc-threading', 'app-platform.trust-social-beta-hardening', 'app-platform.trust-social-content-format-profiles', 'reference-app.social-inbox-service-grant', 'migration.social-mail-preview', 'legacy-plugin.freeze-policy', 'legacy-plugin.migration-guide', 'legacy-plugin.social-inbox-spike', 'legacy-plugin.migration-finalization'):
            assert evidence_by_id[evidence_id]['status'] == 'pass', evidence_by_id
            assert evidence_by_id[evidence_id]['requiredForReleaseCandidate'] is True
        for evidence_id in ('app-services.registry', 'app-services.grants', *pr253_app_service_evidence_ids, 'app-services.trust-score-provider', 'app-services.web-shell', 'app-services.redaction'):
            assert evidence_by_id[evidence_id]['status'] == 'pass', evidence_by_id
            assert evidence_by_id[evidence_id]['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.removal-wave-1']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.removal-wave-1']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.removal-wave-2']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.removal-wave-2']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.removal-wave-3']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.removal-wave-3']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.removal-wave-4']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.removal-wave-4']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.removal-wave-5']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.removal-wave-5']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.final-admin-surface']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.final-admin-surface']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.browse-retained']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.browse-retained']['requiredForReleaseCandidate'] is True
        assert evidence_by_id['legacy-admin.emergency-fallback-retained']['status'] == 'pass', evidence_by_id
        assert evidence_by_id['legacy-admin.emergency-fallback-retained']['requiredForReleaseCandidate'] is True
        optional_skip_status, optional_skip_release_passed = determine_overall_status('release-candidate', [EvidenceItem('catalog.smoke', 'pass', True, 'passed', '<repo>/summary.json', {}), EvidenceItem('apphost.live', 'skip', False, 'not requested', '<repo>/summary.json', {})], WaiverContext())
        assert optional_skip_status == 'pass', optional_skip_status
        assert optional_skip_release_passed is True, optional_skip_release_passed
        report = (out_dir / REPORT_FILE_NAME).read_text(encoding='utf-8')
        matrix_report = (out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).read_text(encoding='utf-8')
        assert 'Release Certification Report' in report
        assert 'Historical Comparison' in report
        assert 'Ecosystem RC Certification Gate' in report
        assert 'Ecosystem Gates' in report
        assert 'Ecosystem Certification Matrix' in report
        assert ECOSYSTEM_MATRIX_REPORT_FILE_NAME in report
        assert 'Ecosystem Certification Matrix' in matrix_report
        assert 'Required evidence covered' in matrix_report
        assert 'Waivers' in report
        encoded = json.dumps(summary, sort_keys=True) + json.dumps(matrix, sort_keys=True) + matrix_report
        for forbidden in ('CRYPTAD_APP_TOKEN', 'USK@private', str(workspace)):
            assert forbidden not in encoded, f'self-test leaked {forbidden}'
        feed_body_metadata = sanitize_value({'rawFeedBody': '<feed><entry>private body</entry></feed>', 'rawFeedBodyBase64': 'opaque-feed-body-base64', 'rawRequestBody': 'uri=SSK@private', 'requestBodyText': 'opaque-request-body-text', 'feedContentPreview': 'opaque-feed-preview', 'rawFeedBodySource': 'opaque-feed-body-source', 'requestBodySource': 'opaque-request-body-source', 'feedSummary': '3 entries', 'rawFeedBodyRedacted': True, 'rawFeedBodiesExcluded': True, 'rawMessageBody': 'private social message body', 'messageBodyText': 'private social message text', 'rawFetchedBody': '{"messages":[{"body":"private fetched body"}]}', 'fetchedBodyPreview': 'private fetched preview', 'rawMessageBodiesExcludedFromEvidence': True}, workspace, out_dir)
        assert feed_body_metadata['rawFeedBody'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['rawFeedBodyBase64'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['rawRequestBody'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['requestBodyText'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['feedContentPreview'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['rawFeedBodySource'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['requestBodySource'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['feedSummary'] == '3 entries', feed_body_metadata
        assert feed_body_metadata['rawFeedBodyRedacted'] is True, feed_body_metadata
        assert feed_body_metadata['rawFeedBodiesExcluded'] is True, feed_body_metadata
        assert feed_body_metadata['rawMessageBody'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['messageBodyText'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['rawFetchedBody'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['fetchedBodyPreview'] == '<redacted>', feed_body_metadata
        assert feed_body_metadata['rawMessageBodiesExcludedFromEvidence'] is True, feed_body_metadata
        interop_item = next((item for item in summary['evidence'] if item['id'] == 'interop.smoke'))
        assert 'artifacts/private-insert-uris.json' not in json.dumps(interop_item)
        direct_rc_waiver_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/direct-rc-gate-waiver-cert').resolve(), waivers={ECOSYSTEM_RC_GATE_ID: 'Release manager accepted temporary RC gate warning.'})
        direct_rc_waiver_summary, direct_rc_waiver_exit_code = run(direct_rc_waiver_settings)
        assert direct_rc_waiver_exit_code == 0, direct_rc_waiver_summary
        assert direct_rc_waiver_summary['ecosystemRcGate']['status'] == 'warn', direct_rc_waiver_summary
        assert direct_rc_waiver_summary['ecosystemRcGate']['waiverCount'] == 1, direct_rc_waiver_summary
        direct_rc_gate = next((gate for gate in direct_rc_waiver_summary['ecosystemGates'] if gate['id'] == ECOSYSTEM_RC_GATE_ID))
        assert direct_rc_gate['details']['waiverId'] == ECOSYSTEM_RC_GATE_ID, direct_rc_gate
        direct_rc_evidence = next((item for item in direct_rc_waiver_summary['evidence'] if item['id'] == ECOSYSTEM_RC_EVIDENCE_ID))
        assert direct_rc_evidence['details']['waiverCount'] == 1, direct_rc_evidence
        assert ECOSYSTEM_RC_GATE_ID in direct_rc_evidence['details']['details']['waiverIds'], direct_rc_evidence
        direct_rc_report = (direct_rc_waiver_settings.out_dir / REPORT_FILE_NAME).read_text(encoding='utf-8')
        assert f'- Waivers: `1` `{ECOSYSTEM_RC_GATE_ID}`' in direct_rc_report, direct_rc_report
        previous_good_path = workspace / 'build/previous-good/release-certification-summary.json'
        previous_good = {'schemaVersion': SCHEMA_VERSION, 'tool': TOOL_NAME, 'mode': 'release-candidate', 'status': 'pass', 'releaseCandidatePassed': True, 'generatedAt': '2026-05-01T00:00:00Z', 'metadata': {'gitCommit': 'previous-sha', 'releaseVersion': '2026.05.0'}, 'evidence': summary['evidence']}
        write_json(previous_good_path, previous_good)
        previous_production_beta_path = workspace / 'build/previous-good/production-beta-summary.json'
        previous_production_beta = {'schemaVersion': 1, 'kind': 'cryptad-production-beta-release-summary', 'tool': 'production-beta-release', 'releaseId': 'cryptad-beta-2026.05.0', 'version': '2026.05.0', 'generatedAt': '2026-05-01T00:00:00Z', 'status': 'pass', 'promotionReady': True, 'artifactBaseUri': 'https://downloads.crypta.invalid/production-beta/2026.05.0', 'metadata': {'gitCommit': 'previous-sha', 'releaseVersion': '2026.05.0'}}
        previous_candidate_fixture = read_json(multi_node_beta_soak.previous_candidate_fixture_path()) or {}
        previous_candidate_source_metadata = {field: json.loads(json.dumps(previous_candidate_fixture[field], sort_keys=True)) for field in multi_node_beta_soak.PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS if field in previous_candidate_fixture}
        for app in previous_candidate_source_metadata.get('firstPartyApps', []):
            if isinstance(app, dict):
                app['version'] = '2026.05.0'
        previous_production_beta.update(previous_candidate_source_metadata)
        write_json(previous_production_beta_path, previous_production_beta)
        previous_candidate_good_path = workspace / 'build/previous-good/previous-beta-candidate-summary.json'
        previous_candidate_good = multi_node_beta_soak.build_previous_candidate_summary(previous_good, previous_production_beta, release_certification_digest=multi_node_beta_soak.sha256_path(previous_good_path), production_beta_digest=multi_node_beta_soak.sha256_path(previous_production_beta_path), generated_at='2026-05-01T00:00:00Z')
        write_json(previous_candidate_good_path, previous_candidate_good)
        previous_matrix_good_path = workspace / 'build/previous-matrix-good/release-certification-summary.json'
        previous_matrix_good = dict(previous_good)
        previous_matrix_good['evidence'] = [item if item.get('id') != 'release-certification.ecosystem-matrix' else item | {'status': 'pass', 'summary': 'Ecosystem certification matrix status is pass.'} for item in summary['evidence']]
        previous_matrix_good['ecosystemMatrix'] = {'schemaVersion': ECOSYSTEM_MATRIX_SCHEMA_VERSION, 'status': 'pass', 'rowCount': len(matrix['rows']), 'releaseBlockerCount': 0, 'coverage': matrix['coverage'], 'rowStatuses': {row['id']: 'pass' for row in matrix['rows']}, 'matrixDiffs': []}
        write_json(previous_matrix_good_path, previous_matrix_good)
        multi_node_pass_config = multi_node_beta_soak.validate_config(multi_node_beta_soak.load_config(fixture_dir / 'self-test-multi-node-beta-soak.json'))
        multi_node_pass_config['previousCandidate']['summaryPath'] = str(previous_candidate_good_path)
        multi_node_pass_config['previousCandidate']['version'] = previous_candidate_good['version']
        multi_node_pass_path = workspace / 'build/multi-node-pass/summary.json'
        multi_node_pass_summary = multi_node_beta_soak.build_summary(multi_node_pass_config, out_dir=multi_node_pass_path.parent, base_dir=fixture_dir)
        write_json(multi_node_pass_path, multi_node_pass_summary)
        write_text(multi_node_pass_path.parent / multi_node_beta_soak.REPORT_FILE_NAME, multi_node_beta_soak.render_report(multi_node_pass_summary))
        multi_node_disabled_required_path = workspace / 'build/multi-node-disabled-required/summary.json'
        multi_node_disabled_required_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        disabled_backup = multi_node_beta_soak.scenario_map(multi_node_disabled_required_summary)['backup-restore']
        disabled_backup['status'] = 'warn'
        disabled_backup['summary'] = 'Scenario is disabled in the topology config.'
        disabled_backup['evidence'] = {'evidenceId': 'multi-node-beta.backup-restore', 'configured': False, 'strict': False}
        multi_node_disabled_required_summary['scenarioStatuses']['backup-restore'] = 'warn'
        multi_node_disabled_required_summary['status'] = 'warn'
        multi_node_disabled_required_summary['promotionReady'] = True
        multi_node_disabled_required_summary['warnings'] = ['backup-restore has warnings']
        write_json(multi_node_disabled_required_path, multi_node_disabled_required_summary)
        multi_node_disabled_required_items = multi_node_beta_soak_evidence(multi_node_disabled_required_path, workspace, out_dir, 'release-candidate', False)
        multi_node_disabled_umbrella = next((item for item in multi_node_disabled_required_items if item.id == 'multi-node-beta.soak'))
        multi_node_disabled_backup = next((item for item in multi_node_disabled_required_items if item.id == 'multi-node-beta.backup-restore'))
        assert multi_node_disabled_umbrella.status == 'fail', multi_node_disabled_umbrella
        assert multi_node_disabled_backup.status == 'fail', multi_node_disabled_backup
        assert 'backup-restore' in multi_node_disabled_umbrella.details.get('disabledRequiredScenarios', []), multi_node_disabled_umbrella
        assert 'scenario backup-restore is disabled but required in release-candidate' in multi_node_disabled_umbrella.details.get('validationErrors', []), multi_node_disabled_umbrella
        multi_node_publish_leak_path = workspace / 'build/multi-node-publish-leak/summary.json'
        multi_node_publish_leak_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_publish_leak_summary['blockers'] = ['rawBackupPayload: backup bundle bytes /srv/runner/work/cryptad/private-state']
        multi_node_publish_leak_summary['warnings'] = ['/etc/cryptad/private-state']
        multi_node_publish_leak_summary['redaction']['rawBackupPayload'] = 'backup bundle bytes'
        multi_node_publish_leak_summary['redaction']['findings'] = [{'kind': 'raw-backup-payload', 'location': '/srv/runner/work/cryptad/private-state', 'source': 'validation', 'rawBackupPayload': 'backup bundle bytes'}]
        write_json(multi_node_publish_leak_path, multi_node_publish_leak_summary)
        write_text(multi_node_publish_leak_path.parent / multi_node_beta_soak.REPORT_FILE_NAME, 'rawBackupPayload: backup bundle bytes\n/srv/runner/work/cryptad/private-state\n')
        multi_node_publish_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/multi-node-publish-cert').resolve(), multi_node_soak_summary=multi_node_publish_leak_path)
        collect_source_artifacts(multi_node_publish_settings, multi_node_publish_settings.out_dir)
        published_multi_node_summary = (multi_node_publish_settings.out_dir / 'artifacts/multi-node-beta-soak-summary.json').read_text(encoding='utf-8')
        published_multi_node_report = (multi_node_publish_settings.out_dir / 'artifacts/multi-node-beta-soak-report.md').read_text(encoding='utf-8')
        for forbidden in ('rawBackupPayload', 'backup bundle bytes', '/srv/runner', '/etc/cryptad'):
            assert forbidden not in published_multi_node_summary, published_multi_node_summary
            assert forbidden not in published_multi_node_report, published_multi_node_report
        published_multi_node_summary_json = json.loads(published_multi_node_summary)
        assert published_multi_node_summary_json['redaction']['checks']['failOnTokens'] is True, published_multi_node_summary_json
        assert 'Multi-node Beta Soak Report Redacted' in published_multi_node_report, published_multi_node_report
        multi_node_publish_tmp_path = workspace / 'build/multi-node-publish-leak/summary.json.tmp'
        write_json(multi_node_publish_tmp_path, multi_node_publish_leak_summary)
        multi_node_publish_tmp_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/multi-node-publish-tmp-cert').resolve(), multi_node_soak_summary=multi_node_publish_tmp_path)
        collect_source_artifacts(multi_node_publish_tmp_settings, multi_node_publish_tmp_settings.out_dir)
        published_multi_node_tmp_summary = (multi_node_publish_tmp_settings.out_dir / 'artifacts/multi-node-beta-soak-summary.json').read_text(encoding='utf-8')
        for forbidden in ('rawBackupPayload', 'backup bundle bytes', '/srv/runner', '/etc/cryptad'):
            assert forbidden not in published_multi_node_tmp_summary, published_multi_node_tmp_summary
        published_multi_node_tmp_summary_json = json.loads(published_multi_node_tmp_summary)
        assert published_multi_node_tmp_summary_json['redaction']['checks']['failOnTokens'] is True, published_multi_node_tmp_summary_json
        multi_node_leaky_path = workspace / 'build/multi-node-leaky/summary.json'
        multi_node_leaky_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_leaky_summary.setdefault('evidence', {})['rawAppData'] = {'value': 'unredacted value'}
        write_json(multi_node_leaky_path, multi_node_leaky_summary)
        multi_node_leaky_items = multi_node_beta_soak_evidence(multi_node_leaky_path, workspace, out_dir, 'release-candidate', True)
        multi_node_leaky_redaction = next((item for item in multi_node_leaky_items if item.id == 'multi-node-beta.redaction'))
        assert multi_node_leaky_redaction.status == 'fail', multi_node_leaky_redaction
        assert evidence_item_has_unwaivable_redaction_findings(multi_node_leaky_redaction), multi_node_leaky_redaction
        assert any((finding.get('kind') == 'raw-app-data' and finding.get('source') == 'validation' for finding in multi_node_leaky_redaction.details.get('redactionFindings', []) if isinstance(finding, dict))), multi_node_leaky_redaction
        multi_node_unsafe_flags_path = workspace / 'build/multi-node-unsafe-flags/summary.json'
        multi_node_unsafe_flags_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        unsafe_support_evidence = multi_node_beta_soak.scenario_map(multi_node_unsafe_flags_summary)['support-bundle-drill']['evidence']
        unsafe_support_evidence['privateInsertUrisIncluded'] = True
        unsafe_support_evidence['tokensIncluded'] = True
        unsafe_support_evidence['redactionScanStatus'] = 'fail'
        write_json(multi_node_unsafe_flags_path, multi_node_unsafe_flags_summary)
        multi_node_unsafe_flags_items = multi_node_beta_soak_evidence(multi_node_unsafe_flags_path, workspace, out_dir, 'release-candidate', True)
        multi_node_unsafe_flags_redaction = next((item for item in multi_node_unsafe_flags_items if item.id == 'multi-node-beta.redaction'))
        assert multi_node_unsafe_flags_redaction.status == 'fail', multi_node_unsafe_flags_redaction
        assert evidence_item_has_unwaivable_redaction_findings(multi_node_unsafe_flags_redaction), multi_node_unsafe_flags_redaction
        assert any((finding.get('kind') == 'forbidden-included-flag' and finding.get('source') == 'validation' for finding in multi_node_unsafe_flags_redaction.details.get('redactionFindings', []) if isinstance(finding, dict))), multi_node_unsafe_flags_redaction
        assert any((finding.get('kind') == 'redaction-scan-status' and finding.get('source') == 'validation' for finding in multi_node_unsafe_flags_redaction.details.get('redactionFindings', []) if isinstance(finding, dict))), multi_node_unsafe_flags_redaction
        multi_node_disabled_checks_path = workspace / 'build/multi-node-disabled-checks/summary.json'
        multi_node_disabled_checks_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_disabled_checks_summary['redaction']['checks']['failOnTokens'] = False
        write_json(multi_node_disabled_checks_path, multi_node_disabled_checks_summary)
        multi_node_disabled_checks_items = multi_node_beta_soak_evidence(multi_node_disabled_checks_path, workspace, out_dir, 'release-candidate', True)
        multi_node_disabled_checks_redaction = next((item for item in multi_node_disabled_checks_items if item.id == 'multi-node-beta.redaction'))
        assert multi_node_disabled_checks_redaction.status == 'fail', multi_node_disabled_checks_redaction
        assert evidence_item_has_unwaivable_redaction_findings(multi_node_disabled_checks_redaction), multi_node_disabled_checks_redaction
        assert any((finding.get('kind') == 'disabled-redaction-check' and finding.get('source') == 'validation' for finding in multi_node_disabled_checks_redaction.details.get('redactionFindings', []) if isinstance(finding, dict))), multi_node_disabled_checks_redaction
        multi_node_non_promotable_path = workspace / 'build/multi-node-non-promotable/summary.json'
        multi_node_non_promotable_summary = json.loads(json.dumps(multi_node_pass_summary, sort_keys=True))
        multi_node_non_promotable_summary['promotionReady'] = False
        write_json(multi_node_non_promotable_path, multi_node_non_promotable_summary)
        multi_node_non_promotable_items = multi_node_beta_soak_evidence(multi_node_non_promotable_path, workspace, out_dir, 'release-candidate', True)
        multi_node_non_promotable_soak = next((item for item in multi_node_non_promotable_items if item.id == 'multi-node-beta.soak'))
        assert multi_node_non_promotable_soak.status == 'fail', multi_node_non_promotable_soak
        assert multi_node_non_promotable_soak.details['promotionReady'] is False, multi_node_non_promotable_soak
        with_previous_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/with-previous-cert').resolve(), previous_summary=previous_good_path, multi_node_soak_summary=multi_node_pass_path)
        with_previous_summary, with_previous_exit_code = run(with_previous_settings)
        assert with_previous_exit_code == 0, with_previous_summary
        assert with_previous_summary['status'] == 'warn', with_previous_summary
        assert with_previous_summary['historyComparison']['status'] == 'pass', with_previous_summary
        assert with_previous_summary['ecosystemGateStatus'] == 'warn', with_previous_summary
        assert with_previous_summary['ecosystemRcGate']['status'] == 'warn', with_previous_summary
        assert with_previous_summary['ecosystemMatrix']['coverage']['requiredEvidenceCovered'] is True
        assert with_previous_summary['ecosystemMatrix']['coverage']['ecosystemGatesCovered'] is True
        with_previous_matrix = read_json(with_previous_settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        assert with_previous_matrix is not None, with_previous_summary
        assert with_previous_matrix['previousSummaryPresent'] is True, with_previous_matrix
        assert with_previous_matrix['previousMatrixPresent'] is False, with_previous_matrix
        history_store = workspace / 'build/release-certification-history'
        write_history_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/write-history-cert').resolve(), previous_summary=previous_good_path, write_history=True, history_dir=history_store, history_label='2026.05.0')
        write_history_summary, write_history_exit_code = run(write_history_settings)
        assert write_history_exit_code == 0, write_history_summary
        assert (history_store / 'latest-summary.json').is_file(), write_history_summary
        assert (history_store / 'latest-history-comparison.json').is_file(), write_history_summary
        assert (history_store / 'releases/2026.05.0/release-certification-summary.json').is_file(), write_history_summary
        protected_latest_summary = read_json(history_store / 'latest-summary.json')
        assert protected_latest_summary is not None, write_history_summary
        written_history_encoded = json.dumps(read_json(history_store / 'latest-summary.json'), sort_keys=True)
        assert str(workspace) not in written_history_encoded, written_history_encoded

        def write_app_summary_variant(name: str, mutate: Any) -> Path:
            app_summary = read_json(settings.app_platform_summary)
            assert app_summary is not None
            mutate(app_summary)
            path = workspace / f'build/{name}/summary.json'
            write_json(path, app_summary)
            return path

        def update_evidence(summary_value: dict[str, Any], evidence_id: str, mutate: Any) -> None:
            evidence_list = summary_value.get('evidence', [])
            assert isinstance(evidence_list, list)
            for entry in evidence_list:
                if isinstance(entry, dict) and entry.get('id') == evidence_id:
                    mutate(entry)
                    return
            raise AssertionError(f'missing evidence {evidence_id}')

        def run_with_previous(name: str, **overrides: Any) -> tuple[dict[str, Any], int]:
            previous_summary_override = overrides.pop('previous_summary', previous_good_path)
            multi_node_summary_override = overrides.pop('multi_node_soak_summary', multi_node_pass_path)
            variant_settings = dataclasses.replace(settings, out_dir=(workspace / f'build/{name}').resolve(), previous_summary=previous_summary_override, multi_node_soak_summary=multi_node_summary_override, **overrides)
            return run(variant_settings)

        def gate_by_id(summary_value: dict[str, Any], gate_id: str) -> dict[str, Any]:
            for gate in summary_value.get('ecosystemGates', []):
                if isinstance(gate, dict) and gate.get('id') == gate_id:
                    return gate
            raise AssertionError(f'missing gate {gate_id}')

        def matrix_row_by_id(out_path: Path, row_id: str) -> dict[str, Any]:
            matrix_value = read_json(out_path / ECOSYSTEM_MATRIX_FILE_NAME)
            assert matrix_value is not None
            for row in matrix_value.get('rows', []):
                if isinstance(row, dict) and row.get('id') == row_id:
                    return row
            raise AssertionError(f'missing matrix row {row_id}')

        def evidence_by_id(summary_value: dict[str, Any], evidence_id: str) -> dict[str, Any]:
            for item in summary_value.get('evidence', []):
                if isinstance(item, dict) and item.get('id') == evidence_id:
                    return item
            raise AssertionError(f'missing evidence {evidence_id}')
        clean_happy_summary, clean_happy_exit_code = run_with_previous('clean-happy-cert', previous_summary=previous_matrix_good_path)
        assert clean_happy_exit_code == 0, clean_happy_summary
        assert clean_happy_summary['status'] == 'pass', clean_happy_summary
        assert clean_happy_summary['promotionDecision'] == 'PASS', clean_happy_summary
        assert clean_happy_summary['releaseCandidatePassed'] is True, clean_happy_summary
        assert clean_happy_summary['ecosystemGateStatus'] == 'pass', clean_happy_summary
        assert clean_happy_summary['ecosystemRcDecision'] == 'PASS', clean_happy_summary
        assert clean_happy_summary['ecosystemRcPassed'] is True, clean_happy_summary
        assert clean_happy_summary['ecosystemRcGate']['status'] == 'pass', clean_happy_summary
        clean_happy_row = matrix_row_by_id(workspace / 'build/clean-happy-cert', ECOSYSTEM_RC_MATRIX_ROW_ID)
        assert clean_happy_row['status'] == 'pass', clean_happy_row
        assert clean_happy_summary['ecosystemMatrix']['status'] == 'pass', clean_happy_summary
        waived_rc_gate_missing_soak_summary, waived_rc_gate_missing_soak_exit_code = run_with_previous('waived-rc-gate-missing-network-scale-soak-cert', previous_summary=previous_matrix_good_path, network_scale_soak_summary=workspace / 'build/missing-network-scale-soak/summary.json', waivers={ECOSYSTEM_RC_GATE_ID: 'Release manager waived aggregate RC gate.'})
        assert waived_rc_gate_missing_soak_exit_code == 1, waived_rc_gate_missing_soak_summary
        assert waived_rc_gate_missing_soak_summary['releaseCandidatePassed'] is False, waived_rc_gate_missing_soak_summary
        assert waived_rc_gate_missing_soak_summary['ecosystemRcDecision'] == 'FAIL', waived_rc_gate_missing_soak_summary
        assert waived_rc_gate_missing_soak_summary['ecosystemRcPassed'] is False, waived_rc_gate_missing_soak_summary
        waived_rc_gate = gate_by_id(waived_rc_gate_missing_soak_summary, ECOSYSTEM_RC_GATE_ID)
        assert waived_rc_gate['status'] == 'warn', waived_rc_gate
        assert waived_rc_gate['releaseBlocker'] is False, waived_rc_gate
        assert waived_rc_gate['details']['waiverId'] == ECOSYSTEM_RC_GATE_ID, waived_rc_gate
        waived_soak_row_summary, waived_soak_row_exit_code = run_with_previous('waived-network-scale-soak-row-cert', previous_summary=previous_matrix_good_path, network_scale_soak_summary=workspace / 'build/missing-network-scale-soak/summary.json', waivers={'network-scale-soak-and-subscription-budget': 'Release manager accepted temporary missing network-scale soak evidence.'})
        assert waived_soak_row_exit_code == 0, waived_soak_row_summary
        assert waived_soak_row_summary['releaseCandidatePassed'] is True, waived_soak_row_summary
        assert waived_soak_row_summary['promotionDecision'] == 'PASS WITH WARNINGS', waived_soak_row_summary
        waived_soak_rc_gate = gate_by_id(waived_soak_row_summary, ECOSYSTEM_RC_GATE_ID)
        assert waived_soak_rc_gate['status'] == 'warn', waived_soak_rc_gate
        assert waived_soak_rc_gate['releaseBlocker'] is False, waived_soak_rc_gate
        assert waived_soak_rc_gate['details']['networkScaleSoakSatisfied'] is True, waived_soak_rc_gate
        assert NETWORK_SCALE_SOAK_EVIDENCE_ID in waived_soak_rc_gate['details']['waivedEvidenceIds'], waived_soak_rc_gate
        assert NETWORK_SCALE_SOAK_EVIDENCE_ID not in waived_soak_rc_gate['details']['failedEvidenceIds'], waived_soak_rc_gate
        waived_soak_row = matrix_row_by_id(workspace / 'build/waived-network-scale-soak-row-cert', 'network-scale-soak-and-subscription-budget')
        assert waived_soak_row['status'] == 'warn', waived_soak_row
        assert waived_soak_row['releaseBlocker'] is False, waived_soak_row
        missing_pr253_path = write_app_summary_variant('missing-pr253-app-service-evidence', lambda value: value.update({'evidence': [item for item in value['evidence'] if item.get('id') not in pr253_app_service_evidence_ids]}))
        missing_pr253_items = app_platform_evidence(missing_pr253_path, workspace, out_dir, 'release-candidate')
        missing_pr253_by_id = {item.id: item for item in missing_pr253_items}
        for evidence_id in pr253_app_service_evidence_ids:
            assert missing_pr253_by_id[evidence_id].status == 'missing', missing_pr253_by_id
            assert missing_pr253_by_id[evidence_id].required_for_release_candidate is True
        missing_pr253_summary, missing_pr253_exit_code = run_with_previous('missing-pr253-app-service-cert', app_platform_summary=missing_pr253_path, previous_summary=previous_matrix_good_path)
        assert missing_pr253_exit_code == 1, missing_pr253_summary
        assert missing_pr253_summary['status'] == 'fail', missing_pr253_summary
        assert missing_pr253_summary['releaseCandidatePassed'] is False, missing_pr253_summary
        assert missing_pr253_summary['ecosystemRcGate']['status'] == 'fail', missing_pr253_summary
        assert gate_by_id(missing_pr253_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        missing_pr253_row = matrix_row_by_id(workspace / 'build/missing-pr253-app-service-cert', 'app-service-discovery-and-grants')
        assert missing_pr253_row['status'] == 'fail', missing_pr253_row
        assert missing_pr253_row['releaseBlocker'] is True, missing_pr253_row
        dependency_redaction_findings_path = write_app_summary_variant('dependency-redaction-findings', lambda value: update_evidence(value, 'app-services.dependency-redaction', lambda entry: (entry.update({'status': 'fail'}), entry.setdefault('details', {}).update({'redactionFindings': [{'path': 'tools/release-certification/app-platform-smoke/summary.json', 'issue': 'raw-service-invocation-body'}]}))))
        waived_dependency_redaction_summary, waived_dependency_redaction_exit_code = run_with_previous('waived-dependency-redaction-findings-cert', app_platform_summary=dependency_redaction_findings_path, previous_summary=previous_matrix_good_path, waivers={ECOSYSTEM_RC_GATE_ID: 'Release manager attempted to waive aggregate RC gate redaction failure.', 'app-services.dependency-redaction': 'Release manager attempted to waive app-service dependency redaction findings.'})
        assert waived_dependency_redaction_exit_code == 1, waived_dependency_redaction_summary
        assert waived_dependency_redaction_summary['releaseCandidatePassed'] is False, waived_dependency_redaction_summary
        assert waived_dependency_redaction_summary['ecosystemRcPassed'] is False, waived_dependency_redaction_summary
        dependency_redaction_evidence = evidence_by_id(waived_dependency_redaction_summary, 'app-services.dependency-redaction')
        assert dependency_redaction_evidence['status'] == 'fail', dependency_redaction_evidence
        assert 'waived' not in dependency_redaction_evidence['details'], dependency_redaction_evidence
        dependency_redaction_rc_gate = gate_by_id(waived_dependency_redaction_summary, ECOSYSTEM_RC_GATE_ID)
        assert dependency_redaction_rc_gate['status'] == 'fail', dependency_redaction_rc_gate
        assert dependency_redaction_rc_gate['releaseBlocker'] is True, dependency_redaction_rc_gate
        assert 'waived' not in dependency_redaction_rc_gate['details'], dependency_redaction_rc_gate
        assert dependency_redaction_rc_gate['details']['redactionPassed'] is False, dependency_redaction_rc_gate
        assert 'app-services.dependency-redaction' in dependency_redaction_rc_gate['details']['redactionFailureEvidenceIds'], dependency_redaction_rc_gate
        assert dependency_redaction_rc_gate['details']['unwaivableFailureEvidenceIds'] == ['app-services.dependency-redaction'], dependency_redaction_rc_gate
        dependency_redaction_row = matrix_row_by_id(workspace / 'build/waived-dependency-redaction-findings-cert', 'app-service-discovery-and-grants')
        assert dependency_redaction_row['status'] == 'fail', dependency_redaction_row
        assert dependency_redaction_row['releaseBlocker'] is True, dependency_redaction_row
        assert 'app-services.dependency-redaction' not in dependency_redaction_row.get('waiverIds', []), dependency_redaction_row
        assert dependency_redaction_row['details']['unwaivableRedactionEvidenceIds'] == ['app-services.dependency-redaction'], dependency_redaction_row

        def write_live_network_summary(name: str, *, enabled: bool, required: bool, statuses: dict[str, str], mode: str='release-candidate', kind: str='live-network-beta-smoke') -> Path:
            evidence = []
            evidence_statuses = []
            for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
                status = statuses.get(evidence_id, 'pass')
                evidence_statuses.append(status)
                evidence_enabled = enabled
                if evidence_id == 'live-network-beta.app-service-score' and status == 'skip':
                    evidence_enabled = False
                evidence.append({'id': evidence_id, 'status': status, 'requiredForReleaseCandidate': required and evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS or evidence_id == 'live-network-beta.redaction', 'summary': f'{evidence_id} self-test status is {status}.', 'source': 'live-network-beta-self-test', 'details': {'enabled': evidence_enabled, 'required': required, 'node': {'baseUrlShape': 'http://127.0.0.1:<port>', 'localhostOnly': True}, 'redaction': {'status': 'pass', 'forbiddenPatternsChecked': True, 'rawBodiesStored': False, 'privateInsertUrisStored': False, 'localPathsStored': False}, 'stepCounts': {'total': len(LIVE_NETWORK_BETA_EVIDENCE_IDS), 'passed': 9}, 'artifactPaths': ['<repo>/build/release-certification/live-network-beta-smoke/summary.json']}})
            path = workspace / f'build/{name}/summary.json'
            write_json(path, {'schemaVersion': 1, 'kind': kind, 'mode': mode, 'enabled': enabled, 'required': required, 'status': aggregate_status_values(evidence_statuses), 'node': {'baseUrlShape': 'http://127.0.0.1:<port>', 'localhostOnly': True, 'version': 'redacted', 'build': 'redacted'}, 'evidence': evidence, 'redaction': {'status': 'pass', 'forbiddenPatternsChecked': True, 'rawBodiesStored': False, 'privateInsertUrisStored': False, 'localPathsStored': False}})
            return path
        candidate_bound_network_soak = read_json(settings.network_scale_soak_summary)
        assert candidate_bound_network_soak is not None
        candidate_bound_network_soak['releaseId'] = 'cryptad-beta-self-test'
        safe_candidate_bound_network_soak, candidate_bound_network_soak_errors = allowlisted_network_scale_soak_summary(candidate_bound_network_soak)
        assert candidate_bound_network_soak_errors == [], candidate_bound_network_soak_errors
        assert safe_candidate_bound_network_soak['releaseId'] == 'cryptad-beta-self-test', safe_candidate_bound_network_soak
        raw_network_soak = read_json(settings.network_scale_soak_summary)
        assert raw_network_soak is not None
        raw_network_soak['queueHtml'] = '<html>private queue details</html>'
        raw_network_soak['rawFetchedContent'] = 'USK@private-fetched-content'
        raw_network_soak['apps']['social-inbox']['rawFetchedContent'] = 'private social inbox document'
        raw_network_soak['apps']['feed-reader']['queueHtml'] = '<html>feed queue</html>'
        raw_network_soak['trustGraph']['rawStatementBody'] = 'raw trust statement body'
        raw_network_soak['redaction']['rawContent'] = 'private redaction field'
        raw_network_soak_path = workspace / 'build/network-scale-raw-soak/summary.json'
        write_json(raw_network_soak_path, raw_network_soak)
        raw_network_soak_summary, raw_network_soak_exit_code = run_with_previous('network-scale-raw-soak-cert', network_scale_soak_summary=raw_network_soak_path)
        assert raw_network_soak_exit_code == 1, raw_network_soak_summary
        raw_network_soak_item = evidence_by_id(raw_network_soak_summary, NETWORK_SCALE_SOAK_EVIDENCE_ID)
        assert raw_network_soak_item['status'] == 'fail', raw_network_soak_item
        assert any(('unsupported fields' in error for error in raw_network_soak_item['details']['errors'])), raw_network_soak_item
        copied_raw_network_soak = read_json(workspace / 'build/network-scale-raw-soak-cert/artifacts/network-scale-soak-summary.json')
        assert copied_raw_network_soak is not None, raw_network_soak_summary
        assert 'rawFetchedContent' not in copied_raw_network_soak['apps']['social-inbox']
        assert 'queueHtml' not in copied_raw_network_soak['apps']['feed-reader']
        assert 'rawStatementBody' not in copied_raw_network_soak['trustGraph']
        raw_network_soak_report = (workspace / 'build/network-scale-raw-soak-cert' / REPORT_FILE_NAME).read_text(encoding='utf-8')
        encoded_raw_network_soak = json.dumps(raw_network_soak_summary, sort_keys=True) + json.dumps(copied_raw_network_soak, sort_keys=True) + raw_network_soak_report
        for forbidden in ('<html>private queue details</html>', 'private-fetched-content', 'private social inbox document', '<html>feed queue</html>', 'raw trust statement body', 'private redaction field'):
            assert forbidden not in encoded_raw_network_soak, encoded_raw_network_soak
        missing_network_redaction_status = read_json(settings.network_scale_soak_summary)
        assert missing_network_redaction_status is not None
        missing_network_redaction_status['redaction'].pop('status', None)
        missing_network_redaction_status_path = workspace / 'build/network-scale-missing-redaction-status/summary.json'
        write_json(missing_network_redaction_status_path, missing_network_redaction_status)
        missing_network_redaction_status_summary, missing_network_redaction_status_exit_code = run_with_previous('network-scale-missing-redaction-status-cert', network_scale_soak_summary=missing_network_redaction_status_path)
        assert missing_network_redaction_status_exit_code == 1, missing_network_redaction_status_summary
        missing_network_redaction_status_item = evidence_by_id(missing_network_redaction_status_summary, NETWORK_SCALE_SOAK_EVIDENCE_ID)
        assert missing_network_redaction_status_item['status'] == 'fail', missing_network_redaction_status_item
        assert 'redaction.status must be one of the supported values' in missing_network_redaction_status_item['details']['errors'], missing_network_redaction_status_item
        fractional_network_soak = read_json(settings.network_scale_soak_summary)
        assert fractional_network_soak is not None
        fractional_network_soak['durationHoursSimulated'] = 24.5
        fractional_network_soak['apps']['social-inbox']['pollAttempts'] = -0.1
        fractional_network_soak['trustGraph']['importsAttempted'] = float('nan')
        fractional_network_soak_path = workspace / 'build/network-scale-fractional-soak/summary.json'
        write_json(fractional_network_soak_path, fractional_network_soak)
        fractional_network_soak_summary, fractional_network_soak_exit_code = run_with_previous('network-scale-fractional-soak-cert', network_scale_soak_summary=fractional_network_soak_path)
        assert fractional_network_soak_exit_code == 1, fractional_network_soak_summary
        fractional_network_soak_item = evidence_by_id(fractional_network_soak_summary, NETWORK_SCALE_SOAK_EVIDENCE_ID)
        assert fractional_network_soak_item['status'] == 'fail', fractional_network_soak_item
        assert fractional_network_soak_item['details']['errors'].count('durationHoursSimulated must be an integer') == 1, fractional_network_soak_item
        assert 'apps.social-inbox.pollAttempts must be an integer' in fractional_network_soak_item['details']['errors'], fractional_network_soak_item
        assert 'trustGraph.importsAttempted must be an integer' in fractional_network_soak_item['details']['errors'], fractional_network_soak_item
        copied_fractional_network_soak = read_json(workspace / 'build/network-scale-fractional-soak-cert/artifacts/network-scale-soak-summary.json')
        assert copied_fractional_network_soak is not None, fractional_network_soak_summary
        encoded_fractional_network_soak = json.dumps(fractional_network_soak_summary, sort_keys=True) + json.dumps(copied_fractional_network_soak, sort_keys=True)
        assert 'NaN' not in encoded_fractional_network_soak, encoded_fractional_network_soak
        assert '24.5' not in encoded_fractional_network_soak, encoded_fractional_network_soak
        assert '-0.1' not in encoded_fractional_network_soak, encoded_fractional_network_soak
        live_disabled_evidence = {item['id']: item for item in summary['evidence']}
        for evidence_id in LIVE_NETWORK_BETA_EVIDENCE_IDS:
            assert live_disabled_evidence[evidence_id]['status'] == 'skip', live_disabled_evidence
            assert live_disabled_evidence[evidence_id]['requiredForReleaseCandidate'] is False, live_disabled_evidence
        disabled_live_gate = gate_by_id(summary, 'ecosystem.live-network-beta')
        assert disabled_live_gate['status'] == 'pass', disabled_live_gate
        assert disabled_live_gate['releaseBlocker'] is False, disabled_live_gate
        optional_live_path = write_live_network_summary('live-network-optional-failing', enabled=True, required=False, statuses={'live-network-beta.content-fetch': 'fail'})
        optional_live_summary, optional_live_exit_code = run_with_previous('live-network-optional-failing-cert', live_network_summary=optional_live_path, live_network_beta_enabled=True)
        assert optional_live_exit_code == 0, optional_live_summary
        assert optional_live_summary['releaseCandidatePassed'] is True, optional_live_summary
        assert optional_live_summary['promotionDecision'] == 'PASS WITH WARNINGS', optional_live_summary
        assert optional_live_summary['ecosystemRcDecision'] == 'PASS_WITH_WARNINGS', optional_live_summary
        optional_live_gate = gate_by_id(optional_live_summary, 'ecosystem.live-network-beta')
        assert optional_live_gate['status'] == 'warn', optional_live_gate
        assert optional_live_gate['releaseBlocker'] is False, optional_live_gate
        optional_live_row = matrix_row_by_id(workspace / 'build/live-network-optional-failing-cert', 'live-network-beta-certification')
        assert optional_live_row['status'] == 'warn', optional_live_row
        assert optional_live_row['releaseBlocker'] is False, optional_live_row
        optional_missing_live_summary, optional_missing_live_exit_code = run_with_previous('live-network-optional-missing-cert', live_network_summary=workspace / 'build/missing-live-network-optional/summary.json', live_network_beta_enabled=True)
        assert optional_missing_live_exit_code == 0, optional_missing_live_summary
        assert optional_missing_live_summary['releaseCandidatePassed'] is True, optional_missing_live_summary
        assert optional_missing_live_summary['ecosystemRcDecision'] == 'PASS_WITH_WARNINGS', optional_missing_live_summary
        optional_missing_rc_gate = gate_by_id(optional_missing_live_summary, ECOSYSTEM_RC_GATE_ID)
        assert optional_missing_rc_gate['status'] == 'warn', optional_missing_rc_gate
        assert optional_missing_rc_gate['releaseBlocker'] is False, optional_missing_rc_gate
        assert optional_missing_rc_gate['details']['redactionPassed'] is True, optional_missing_rc_gate
        assert 'live-network-beta.redaction' not in optional_missing_rc_gate['details'].get('redactionFailureEvidenceIds', []), optional_missing_rc_gate
        optional_missing_live_gate = gate_by_id(optional_missing_live_summary, 'ecosystem.live-network-beta')
        assert optional_missing_live_gate['status'] == 'warn', optional_missing_live_gate
        assert optional_missing_live_gate['releaseBlocker'] is False, optional_missing_live_gate
        optional_missing_live_evidence = {item['id']: item for item in optional_missing_live_summary['evidence']}
        assert optional_missing_live_evidence['live-network-beta.redaction']['status'] == 'missing', optional_missing_live_evidence
        assert optional_missing_live_evidence['live-network-beta.redaction']['requiredForReleaseCandidate'] is False
        required_missing_summary, required_missing_exit_code = run_with_previous('live-network-required-missing-cert', live_network_summary=workspace / 'build/missing-live-network/summary.json', live_network_beta_enabled=True, live_network_beta_required=True)
        assert required_missing_exit_code == 1, required_missing_summary
        assert required_missing_summary['releaseCandidatePassed'] is False, required_missing_summary
        assert required_missing_summary['ecosystemRcGate']['status'] == 'fail', required_missing_summary
        required_missing_gate = gate_by_id(required_missing_summary, 'ecosystem.live-network-beta')
        assert required_missing_gate['status'] == 'fail', required_missing_gate
        assert required_missing_gate['releaseBlocker'] is True, required_missing_gate
        required_missing_evidence = {item['id']: item for item in required_missing_summary['evidence']}
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS:
            assert required_missing_evidence[evidence_id]['status'] == 'missing', required_missing_evidence
            assert required_missing_evidence[evidence_id]['requiredForReleaseCandidate'] is True, required_missing_evidence
        waived_required_missing_live_summary, waived_required_missing_live_exit_code = run_with_previous('live-network-required-missing-row-waived-cert', live_network_summary=workspace / 'build/missing-live-network-waived/summary.json', live_network_beta_enabled=True, live_network_beta_required=True, waivers={'live-network-beta-certification': 'Release manager accepted temporary missing required live-network beta evidence.'})
        assert waived_required_missing_live_exit_code == 0, waived_required_missing_live_summary
        assert waived_required_missing_live_summary['releaseCandidatePassed'] is True, waived_required_missing_live_summary
        assert waived_required_missing_live_summary['promotionDecision'] == 'PASS WITH WARNINGS', waived_required_missing_live_summary
        waived_required_missing_live_gate = gate_by_id(waived_required_missing_live_summary, 'ecosystem.live-network-beta')
        assert waived_required_missing_live_gate['status'] == 'warn', waived_required_missing_live_gate
        assert waived_required_missing_live_gate['releaseBlocker'] is False, waived_required_missing_live_gate
        waived_required_missing_rc_gate = gate_by_id(waived_required_missing_live_summary, ECOSYSTEM_RC_GATE_ID)
        assert waived_required_missing_rc_gate['status'] == 'warn', waived_required_missing_rc_gate
        assert waived_required_missing_rc_gate['releaseBlocker'] is False, waived_required_missing_rc_gate
        assert waived_required_missing_rc_gate['details']['liveNetworkSatisfied'] is True, waived_required_missing_rc_gate
        assert set(LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS).issubset(set(waived_required_missing_rc_gate['details']['waivedEvidenceIds'])), waived_required_missing_rc_gate
        waived_required_missing_live_row = matrix_row_by_id(workspace / 'build/live-network-required-missing-row-waived-cert', 'live-network-beta-certification')
        assert waived_required_missing_live_row['status'] == 'warn', waived_required_missing_live_row
        assert waived_required_missing_live_row['releaseBlocker'] is False, waived_required_missing_live_row
        required_failing_path = write_live_network_summary('live-network-required-failing', enabled=True, required=True, statuses={'live-network-beta.catalog-usk-fetch': 'fail'})
        required_failing_summary, required_failing_exit_code = run_with_previous('live-network-required-failing-cert', live_network_summary=required_failing_path, live_network_beta_enabled=True, live_network_beta_required=True)
        assert required_failing_exit_code == 1, required_failing_summary
        assert required_failing_summary['releaseCandidatePassed'] is False, required_failing_summary
        assert required_failing_summary['ecosystemRcGate']['status'] == 'fail', required_failing_summary
        required_failing_gate = gate_by_id(required_failing_summary, 'ecosystem.live-network-beta')
        assert required_failing_gate['status'] == 'fail', required_failing_gate
        assert required_failing_gate['details']['failureEvidenceIds'] == ['live-network-beta.catalog-usk-fetch'], required_failing_gate
        required_failing_row = matrix_row_by_id(workspace / 'build/live-network-required-failing-cert', 'live-network-beta-certification')
        assert required_failing_row['status'] == 'fail', required_failing_row
        assert required_failing_row['releaseBlocker'] is True, required_failing_row
        required_passing_path = write_live_network_summary('live-network-required-passing', enabled=True, required=True, statuses={})
        required_passing_summary, required_passing_exit_code = run_with_previous('live-network-required-passing-cert', live_network_summary=required_passing_path, live_network_beta_enabled=True, live_network_beta_required=True)
        assert required_passing_exit_code == 0, required_passing_summary
        assert required_passing_summary['releaseCandidatePassed'] is True, required_passing_summary
        required_passing_gate = gate_by_id(required_passing_summary, 'ecosystem.live-network-beta')
        assert required_passing_gate['status'] == 'pass', required_passing_gate
        required_passing_evidence = {item['id']: item for item in required_passing_summary['evidence']}
        for evidence_id in LIVE_NETWORK_BETA_REQUIRED_EVIDENCE_IDS:
            assert required_passing_evidence[evidence_id]['requiredForReleaseCandidate'] is True, required_passing_evidence
        required_passing_row = matrix_row_by_id(workspace / 'build/live-network-required-passing-cert', 'live-network-beta-certification')
        assert required_passing_row['releaseBlocker'] is False, required_passing_row
        required_without_score_path = write_live_network_summary('live-network-required-without-score', enabled=True, required=True, statuses={'live-network-beta.app-service-score': 'skip'})
        required_without_score_summary, required_without_score_exit_code = run_with_previous('live-network-required-without-score-cert', live_network_summary=required_without_score_path, live_network_beta_enabled=True, live_network_beta_required=True)
        assert required_without_score_exit_code == 0, required_without_score_summary
        required_without_score_gate = gate_by_id(required_without_score_summary, 'ecosystem.live-network-beta')
        assert required_without_score_gate['status'] == 'pass', required_without_score_gate
        assert 'warningEvidenceIds' not in required_without_score_gate['details'], required_without_score_gate
        required_without_score_row = matrix_row_by_id(workspace / 'build/live-network-required-without-score-cert', 'live-network-beta-certification')
        assert required_without_score_row['status'] == 'pass', required_without_score_row
        assert required_without_score_row['releaseBlocker'] is False, required_without_score_row
        portal_linked_doc = workspace / 'docs/app-owned-ui.md'
        original_portal_linked_doc = portal_linked_doc.read_text(encoding='utf-8')
        try:
            portal_linked_doc.write_text(original_portal_linked_doc + '\n[Broken docs-only link](missing-docs-only-link.md)\n', encoding='utf-8')
            waived_docs_link_summary, waived_docs_link_exit_code = run_with_previous('waived-docs-link-cert', waivers={'app-platform.docs-redaction': 'Release manager accepted a temporary docs-only link gap.'})
            assert waived_docs_link_exit_code == 0, waived_docs_link_summary
            assert waived_docs_link_summary['releaseCandidatePassed'] is True, waived_docs_link_summary
            waived_docs_link_evidence = {item['id']: item for item in waived_docs_link_summary['evidence']}
            docs_link_evidence = waived_docs_link_evidence['app-platform.docs-redaction']
            assert docs_link_evidence['status'] == 'warn', docs_link_evidence
            assert docs_link_evidence['details']['waived'] is True, docs_link_evidence
            assert docs_link_evidence['details']['redactionFindings'] == [], docs_link_evidence
            assert {'source': 'docs/app-owned-ui.md', 'target': 'missing-docs-only-link.md', 'reason': 'missing'} in docs_link_evidence['details']['brokenLinks'], docs_link_evidence
            waived_docs_link_row_summary, waived_docs_link_row_exit_code = run_with_previous('waived-docs-link-row-cert', waivers={'app-platform-beta-docs-and-program': 'Release manager accepted a temporary docs-only row gap.'})
            assert waived_docs_link_row_exit_code == 0, waived_docs_link_row_summary
            assert waived_docs_link_row_summary['releaseCandidatePassed'] is True, waived_docs_link_row_summary
            docs_link_row_evidence = {item['id']: item for item in waived_docs_link_row_summary['evidence']}
            docs_link_row_docs_evidence = docs_link_row_evidence['app-platform.docs-redaction']
            assert docs_link_row_docs_evidence['status'] == 'fail', docs_link_row_docs_evidence
            assert docs_link_row_docs_evidence['details']['redactionFindings'] == [], docs_link_row_docs_evidence
            docs_link_row = matrix_row_by_id(workspace / 'build/waived-docs-link-row-cert', 'app-platform-beta-docs-and-program')
            assert docs_link_row['status'] == 'warn', docs_link_row
            assert docs_link_row['releaseBlocker'] is False, docs_link_row
            assert 'app-platform-beta-docs-and-program' in docs_link_row['waiverIds'], docs_link_row
            docs_link_row_rc_gate = gate_by_id(waived_docs_link_row_summary, ECOSYSTEM_RC_GATE_ID)
            assert docs_link_row_rc_gate['status'] == 'warn', docs_link_row_rc_gate
            assert docs_link_row_rc_gate['releaseBlocker'] is False, docs_link_row_rc_gate
            assert docs_link_row_rc_gate['details']['redactionPassed'] is True, docs_link_row_rc_gate
            assert 'app-platform.docs-redaction' in docs_link_row_rc_gate['details']['waivedEvidenceIds'], docs_link_row_rc_gate
            assert 'app-platform.docs-redaction' not in docs_link_row_rc_gate['details']['failedEvidenceIds'], docs_link_row_rc_gate
            assert 'app-platform-beta-docs-and-program' in docs_link_row_rc_gate['details']['waiverIds'], docs_link_row_rc_gate
            portal_linked_doc.write_text(original_portal_linked_doc + '\nAuthorization: Bearer concrete-token-value\n', encoding='utf-8')
            waived_docs_redaction_summary, waived_docs_redaction_exit_code = run_with_previous('waived-docs-redaction-cert', waivers={'app-platform.docs-redaction': 'Release manager attempted to waive a docs redaction finding.', 'evidence.app-platform.docs-redaction': 'Release manager attempted to waive a docs redaction issue id.', 'app-platform-beta-docs-and-program': 'Release manager attempted to waive a docs redaction row.'})
            assert waived_docs_redaction_exit_code == 1, waived_docs_redaction_summary
            assert waived_docs_redaction_summary['releaseCandidatePassed'] is False, waived_docs_redaction_summary
            docs_redaction_rc_gate = gate_by_id(waived_docs_redaction_summary, ECOSYSTEM_RC_GATE_ID)
            assert docs_redaction_rc_gate['status'] == 'fail', docs_redaction_rc_gate
            assert docs_redaction_rc_gate['releaseBlocker'] is True, docs_redaction_rc_gate
            assert docs_redaction_rc_gate['details']['redactionPassed'] is False, docs_redaction_rc_gate
            assert 'app-platform-beta-docs-and-program' not in docs_redaction_rc_gate['details'].get('waiverIds', []), docs_redaction_rc_gate
            waived_docs_redaction_evidence = {item['id']: item for item in waived_docs_redaction_summary['evidence']}
            docs_redaction_evidence = waived_docs_redaction_evidence['app-platform.docs-redaction']
            assert docs_redaction_evidence['status'] == 'fail', docs_redaction_evidence
            assert 'waived' not in docs_redaction_evidence['details'], docs_redaction_evidence
            assert {'path': 'docs/app-owned-ui.md', 'issue': 'authorization-header'} in docs_redaction_evidence['details']['redactionFindings'], docs_redaction_evidence
            docs_redaction_row = matrix_row_by_id(workspace / 'build/waived-docs-redaction-cert', 'app-platform-beta-docs-and-program')
            assert docs_redaction_row['status'] == 'fail', docs_redaction_row
            assert docs_redaction_row['releaseBlocker'] is True, docs_redaction_row
            assert 'app-platform.docs-redaction' not in docs_redaction_row.get('waiverIds', []), docs_redaction_row
            assert 'evidence.app-platform.docs-redaction' not in docs_redaction_row.get('waiverIds', []), docs_redaction_row
            assert 'app-platform-beta-docs-and-program' not in docs_redaction_row.get('waiverIds', []), docs_redaction_row
            assert 'Waiver recorded' not in docs_redaction_row['summary'], docs_redaction_row
            assert 'waived' not in docs_redaction_row['recommendation'].lower(), docs_redaction_row
            assert docs_redaction_row['details']['unwaivableRedactionEvidenceIds'] == ['app-platform.docs-redaction'], docs_redaction_row
            failed_report = (workspace / 'build/waived-docs-redaction-cert' / REPORT_FILE_NAME).read_text(encoding='utf-8')
            assert '### `app-platform.docs-redaction`' in failed_report, failed_report
            assert 'redactionFindings' in failed_report, failed_report
            assert 'docs/app-owned-ui.md' in failed_report, failed_report
        finally:
            portal_linked_doc.write_text(original_portal_linked_doc, encoding='utf-8')
        unmapped_required_path = write_app_summary_variant('unmapped-required-evidence', lambda value: value.setdefault('evidence', []).append({'id': 'self-test.required-unmapped', 'status': 'pass', 'requiredForReleaseCandidate': True, 'summary': 'Self-test required evidence without a matrix row.', 'source': 'self-test', 'details': {}}))
        unmapped_required_summary, unmapped_required_exit_code = run_with_previous('unmapped-required-cert', app_platform_summary=unmapped_required_path)
        assert unmapped_required_exit_code == 1, unmapped_required_summary
        unmapped_required_matrix = read_json(workspace / 'build/unmapped-required-cert' / ECOSYSTEM_MATRIX_FILE_NAME)
        assert unmapped_required_matrix is not None, unmapped_required_summary
        assert unmapped_required_matrix['coverage']['requiredEvidenceCovered'] is False, unmapped_required_matrix
        assert unmapped_required_matrix['coverage']['unmappedRequiredEvidenceIds'] == ['self-test.required-unmapped'], unmapped_required_matrix
        assert unmapped_required_matrix['coverage']['unwaivedIssueIds'] == ['matrix.required-evidence-unmapped'], unmapped_required_matrix
        unmapped_required_row = matrix_row_by_id(workspace / 'build/unmapped-required-cert', 'ecosystem-certification-matrix')
        assert unmapped_required_row['status'] == 'fail', unmapped_required_row
        assert unmapped_required_row['releaseBlocker'] is True, unmapped_required_row
        waived_unmapped_summary, waived_unmapped_exit_code = run_with_previous('waived-unmapped-required-cert', app_platform_summary=unmapped_required_path, waivers={'matrix.required-evidence-unmapped': 'Release manager accepted the temporary matrix row coverage gap.'})
        assert waived_unmapped_exit_code == 0, waived_unmapped_summary
        assert waived_unmapped_summary['status'] == 'warn', waived_unmapped_summary
        assert waived_unmapped_summary['releaseCandidatePassed'] is True, waived_unmapped_summary
        waived_unmapped_matrix = read_json(workspace / 'build/waived-unmapped-required-cert' / ECOSYSTEM_MATRIX_FILE_NAME)
        assert waived_unmapped_matrix is not None, waived_unmapped_summary
        assert waived_unmapped_matrix['status'] == 'warn', waived_unmapped_matrix
        assert waived_unmapped_matrix['releaseCandidatePassed'] is True, waived_unmapped_matrix
        assert waived_unmapped_matrix['coverage']['requiredEvidenceCovered'] is False, waived_unmapped_matrix
        assert waived_unmapped_matrix['coverage']['waivedIssueIds'] == ['matrix.required-evidence-unmapped'], waived_unmapped_matrix
        assert waived_unmapped_matrix['coverage']['unwaivedIssueIds'] == [], waived_unmapped_matrix
        waived_unmapped_row = matrix_row_by_id(workspace / 'build/waived-unmapped-required-cert', 'ecosystem-certification-matrix')
        assert waived_unmapped_row['status'] == 'warn', waived_unmapped_row
        assert waived_unmapped_row['releaseBlocker'] is False, waived_unmapped_row
        assert 'matrix.required-evidence-unmapped' in waived_unmapped_row['waiverIds'], waived_unmapped_row
        signed_bundles_skip_path = write_app_summary_variant('signed-bundles-skip', lambda value: (value.update({'mode': 'pr'}), update_evidence(value, 'app-platform.signed-bundles', lambda entry: entry.update({'status': 'skip', 'summary': 'Signing keys were not available in PR mode.'}))))
        signed_bundles_skip_summary, _signed_bundles_skip_exit_code = run_with_previous('signed-bundles-skip-pr-cert', mode='pr', previous_summary=None, app_platform_summary=signed_bundles_skip_path)
        assert signed_bundles_skip_summary['status'] == 'warn', signed_bundles_skip_summary
        assert signed_bundles_skip_summary['ecosystemMatrix']['status'] == 'warn', signed_bundles_skip_summary
        assert signed_bundles_skip_summary['ecosystemMatrix']['releaseBlockerCount'] == 0, signed_bundles_skip_summary
        signed_bundles_skip_row = matrix_row_by_id(workspace / 'build/signed-bundles-skip-pr-cert', 'first-party-beta-catalog')
        assert signed_bundles_skip_row['status'] == 'warn', signed_bundles_skip_row
        assert signed_bundles_skip_row['releaseBlocker'] is False, signed_bundles_skip_row
        assert 'evidence.app-platform.signed-bundles' in signed_bundles_skip_row['issueIds'], signed_bundles_skip_row
        failing_history_path = write_app_summary_variant('write-history-failing-app', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.update({'status': 'fail'})))
        failing_write_history_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/write-history-failing-cert').resolve(), previous_summary=previous_good_path, app_platform_summary=failing_history_path, write_history=True, history_dir=history_store, history_label='failed-candidate')
        failing_write_history_summary, failing_write_history_exit_code = run(failing_write_history_settings)
        assert failing_write_history_exit_code == 1, failing_write_history_summary
        assert read_json(history_store / 'latest-summary.json') == protected_latest_summary, failing_write_history_summary
        assert (history_store / 'failed/failed-candidate/release-certification-summary.json').is_file(), failing_write_history_summary
        require_history_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/require-history-cert').resolve(), require_history=True)
        require_history_summary, require_history_exit_code = run(require_history_settings)
        assert require_history_exit_code == 1, require_history_summary
        assert require_history_summary['historyComparison']['status'] == 'fail', require_history_summary
        malformed_previous_path = workspace / 'build/malformed-previous/summary.json'
        malformed_previous_path.parent.mkdir(parents=True, exist_ok=True)
        malformed_previous_path.write_text('{"schemaVersion": 1', encoding='utf-8')
        malformed_previous_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/malformed-previous-cert').resolve(), previous_summary=malformed_previous_path)
        malformed_previous_summary, malformed_previous_exit_code = run(malformed_previous_settings)
        assert malformed_previous_exit_code == 1, malformed_previous_summary
        assert malformed_previous_summary['historyComparison']['status'] == 'fail', malformed_previous_summary
        invalid_previous_path = workspace / 'build/invalid-previous/summary.json'
        write_json(invalid_previous_path, {})
        invalid_previous_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/invalid-previous-cert').resolve(), previous_summary=invalid_previous_path, require_history=True)
        invalid_previous_summary, invalid_previous_exit_code = run(invalid_previous_settings)
        assert invalid_previous_exit_code == 1, invalid_previous_summary
        assert invalid_previous_summary['historyComparison']['status'] == 'fail', invalid_previous_summary
        previous_candidate_as_history_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/previous-candidate-as-history-cert').resolve(), previous_summary=previous_candidate_good_path, require_history=True)
        previous_candidate_as_history_summary, previous_candidate_as_history_exit_code = run(previous_candidate_as_history_settings)
        assert previous_candidate_as_history_exit_code == 1, previous_candidate_as_history_summary
        assert previous_candidate_as_history_summary['historyComparison']['status'] == 'fail', previous_candidate_as_history_summary
        assert 'not release-certification history baselines' in previous_candidate_as_history_summary['historyComparison']['summary'], previous_candidate_as_history_summary
        app_smoke_as_previous_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/app-smoke-as-previous-cert').resolve(), previous_summary=settings.app_platform_summary, require_history=True)
        app_smoke_as_previous_summary, app_smoke_as_previous_exit_code = run(app_smoke_as_previous_settings)
        assert app_smoke_as_previous_exit_code == 1, app_smoke_as_previous_summary
        assert app_smoke_as_previous_summary['historyComparison']['status'] == 'fail', app_smoke_as_previous_summary
        platform_fail_path = write_app_summary_variant('platform-contract-fail', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.update({'status': 'fail', 'summary': 'strict compatibility failed'})))
        platform_fail_summary, platform_fail_exit_code = run_with_previous('platform-contract-fail-cert', app_platform_summary=platform_fail_path)
        assert platform_fail_exit_code == 1, platform_fail_summary
        platform_diff = next((diff for diff in platform_fail_summary['historyComparison']['evidenceDiffs'] if diff['id'] == 'platform-api.contract'))
        assert platform_diff['classification'] == 'regression', platform_diff
        assert platform_diff['releaseBlocker'] is True, platform_diff
        platform_matrix_row = matrix_row_by_id(workspace / 'build/platform-contract-fail-cert', 'platform-api-contract')
        assert platform_matrix_row['status'] == 'fail', platform_matrix_row
        assert platform_matrix_row['releaseBlocker'] is True, platform_matrix_row
        platform_fail_with_matrix_summary, platform_fail_with_matrix_exit_code = run_with_previous('platform-contract-fail-with-matrix-cert', app_platform_summary=platform_fail_path, previous_summary=previous_matrix_good_path)
        assert platform_fail_with_matrix_exit_code == 1, platform_fail_with_matrix_summary
        platform_matrix_regression_row = matrix_row_by_id(workspace / 'build/platform-contract-fail-with-matrix-cert', 'platform-api-contract')
        assert platform_matrix_regression_row['previousStatus'] == 'pass', platform_matrix_regression_row
        assert platform_matrix_regression_row['regressionStatus'] == 'regressed-blocker', platform_matrix_regression_row
        ui_warn_path = write_app_summary_variant('ui-lint-warn', lambda value: update_evidence(value, 'app-ui.lint', lambda entry: (entry.update({'status': 'warn'}), entry.setdefault('details', {}).setdefault('apps', {}).setdefault('queue-manager', {}).setdefault('summary', {}).update({'warnings': 1}))))
        ui_warn_summary, ui_warn_exit_code = run_with_previous('ui-lint-warn-cert', app_platform_summary=ui_warn_path)
        assert ui_warn_exit_code == 0, ui_warn_summary
        assert ui_warn_summary['status'] == 'warn', ui_warn_summary
        assert gate_by_id(ui_warn_summary, 'ecosystem.app-ui-quality')['status'] == 'warn'
        optional_missing_summary, optional_missing_exit_code = run_with_previous('optional-interop-missing-cert', interop_extended_summary=workspace / 'build/missing-optional-interop/summary.json')
        assert optional_missing_exit_code == 0, optional_missing_summary
        assert optional_missing_summary['status'] == 'warn', optional_missing_summary
        optional_diff = next((diff for diff in optional_missing_summary['historyComparison']['evidenceDiffs'] if diff['id'] == 'interop.extended'))
        assert optional_diff['classification'] == 'regression', optional_diff
        assert optional_diff['releaseBlocker'] is False, optional_diff
        previous_without_rollback = dict(previous_good)
        previous_without_rollback['evidence'] = [item for item in previous_good['evidence'] if item['id'] != 'app-update.rollback']
        previous_without_rollback_path = workspace / 'build/previous-without-rollback/summary.json'
        write_json(previous_without_rollback_path, previous_without_rollback)
        new_required_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/new-required-cert').resolve(), previous_summary=previous_without_rollback_path)
        new_required_summary, new_required_exit_code = run(new_required_settings)
        assert new_required_exit_code == 0, new_required_summary
        new_required_diff = next((diff for diff in new_required_summary['historyComparison']['evidenceDiffs'] if diff['id'] == 'app-update.rollback'))
        assert new_required_diff['classification'] == 'new', new_required_diff
        previous_with_removed_optional = dict(previous_good)
        previous_with_removed_optional['evidence'] = list(previous_good['evidence']) + [{'id': 'optional.old-evidence', 'status': 'pass', 'requiredForReleaseCandidate': False, 'summary': 'Old optional evidence.', 'source': '<repo>/old.json', 'details': {}}]
        previous_with_removed_optional_path = workspace / 'build/previous-with-removed-optional/summary.json'
        write_json(previous_with_removed_optional_path, previous_with_removed_optional)
        removed_optional_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/removed-optional-cert').resolve(), previous_summary=previous_with_removed_optional_path)
        removed_optional_summary, removed_optional_exit_code = run(removed_optional_settings)
        assert removed_optional_exit_code == 0, removed_optional_summary
        removed_optional_diff = next((diff for diff in removed_optional_summary['historyComparison']['evidenceDiffs'] if diff['id'] == 'optional.old-evidence'))
        assert removed_optional_diff['classification'] == 'removed', removed_optional_diff
        assert removed_optional_diff['releaseBlocker'] is False, removed_optional_diff
        previous_with_removed_required = dict(previous_good)
        previous_with_removed_required['evidence'] = list(previous_good['evidence']) + [{'id': 'required.old-evidence', 'status': 'pass', 'requiredForReleaseCandidate': True, 'summary': 'Old required evidence.', 'source': '<repo>/old.json', 'details': {}}]
        previous_with_removed_required_path = workspace / 'build/previous-with-removed-required/summary.json'
        write_json(previous_with_removed_required_path, previous_with_removed_required)
        waived_removed_required_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/waived-removed-required-cert').resolve(), previous_summary=previous_with_removed_required_path, waivers={'required.old-evidence': 'Release manager accepted removal of retired required evidence.'})
        waived_removed_required_summary, waived_removed_required_exit_code = run(waived_removed_required_settings)
        assert waived_removed_required_exit_code == 0, waived_removed_required_summary
        removed_required_diff = next((diff for diff in waived_removed_required_summary['historyComparison']['evidenceDiffs'] if diff['id'] == 'required.old-evidence'))
        assert removed_required_diff['classification'] == 'removed', removed_required_diff
        assert removed_required_diff['releaseBlocker'] is False, removed_required_diff
        assert gate_by_id(waived_removed_required_summary, 'ecosystem.required-evidence-regressions')['status'] == 'warn'

        def set_stable_baseline_details(entry: dict[str, Any], capabilities: list[str], endpoints: list[str], endpoint_capabilities: dict[str, list[str]] | None=None, endpoint_access: dict[str, dict[str, bool]] | None=None, endpoint_action_labels: dict[str, str] | None=None) -> None:
            contract_details = entry.setdefault('details', {})
            contract_details['stableBaseline'] = {'name': '1.0', 'contractVersion': 19, 'capabilityCount': len(capabilities), 'endpointCount': len(endpoints), 'capabilities': capabilities, 'endpoints': endpoints}
            contract_details['stableBaselineCapabilities'] = capabilities
            contract_details['stableBaselineEndpoints'] = endpoints
            contract_details['stableBaselineCapabilityCount'] = len(capabilities)
            contract_details['stableBaselineEndpointCount'] = len(endpoints)
            contract_details['stableCapabilities'] = capabilities
            contract_details['stableEndpoints'] = endpoints
            if endpoint_capabilities is not None:
                contract_details['stableEndpointRequiredCapabilities'] = endpoint_capabilities
            if endpoint_access is not None:
                contract_details['stableEndpointAppAccess'] = endpoint_access
            contract_details['stableEndpointActionLabels'] = endpoint_action_labels if endpoint_action_labels is not None else {endpoint: endpoint for endpoint in endpoints}
        previous_pre_freeze_summary = json.loads(json.dumps(previous_good))
        for entry in previous_pre_freeze_summary['evidence']:
            if entry['id'] == 'platform-api.contract':
                contract_details = entry.setdefault('details', {})
                for key in ('stableBaseline', 'stableBaselineCapabilities', 'stableBaselineEndpoints', 'stableBaselineCapabilityCount', 'stableBaselineEndpointCount', 'stableEndpointRequiredCapabilities', 'stableEndpointAppAccess', 'stableEndpointActionLabels'):
                    contract_details.pop(key, None)
                contract_details['stableCapabilities'] = ['queue.read', 'trust.read', 'trust.write']
                contract_details['stableEndpoints'] = ['GET /queue', 'GET /trust-graph/audit', 'POST /trust-graph/import-uri']
                contract_details['stableCapabilityCount'] = 3
                contract_details['stableEndpointCount'] = 3
        previous_pre_freeze_path = workspace / 'build/previous-pre-freeze/summary.json'
        write_json(previous_pre_freeze_path, previous_pre_freeze_summary)
        pre_freeze_warning_summary, pre_freeze_warning_exit_code = run_with_previous('pre-freeze-history-warning-cert', previous_summary=previous_pre_freeze_path)
        assert pre_freeze_warning_exit_code == 0, pre_freeze_warning_summary
        pre_freeze_warning_platform_gate = gate_by_id(pre_freeze_warning_summary, 'ecosystem.platform-api-compatibility')
        assert pre_freeze_warning_platform_gate['status'] == 'warn', pre_freeze_warning_platform_gate
        assert 'failureEvidenceIds' not in pre_freeze_warning_platform_gate['details'], pre_freeze_warning_platform_gate
        assert any(('stable baseline comparison is status-limited' in warning for warning in pre_freeze_warning_platform_gate['details'].get('warnings', []))), pre_freeze_warning_platform_gate
        pre_freeze_required_history_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/pre-freeze-required-history-cert').resolve(), previous_summary=previous_pre_freeze_path, require_history=True)
        pre_freeze_required_history_summary, pre_freeze_required_history_exit_code = run(pre_freeze_required_history_settings)
        assert pre_freeze_required_history_exit_code == 1, pre_freeze_required_history_summary
        pre_freeze_required_platform_gate = gate_by_id(pre_freeze_required_history_summary, 'ecosystem.platform-api-compatibility')
        assert pre_freeze_required_platform_gate['status'] == 'fail', pre_freeze_required_platform_gate
        assert pre_freeze_required_platform_gate['details']['failureEvidenceIds'] == ['platform-api.previous-contract-snapshot', 'platform-api.stable-breaking-change-check', 'platform-api.contract'], pre_freeze_required_platform_gate
        assert pre_freeze_required_platform_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.previous-contract-snapshot', 'platform-api.stable-breaking-change-check'], pre_freeze_required_platform_gate
        assert any(('stable baseline comparison is required' in failure for failure in pre_freeze_required_platform_gate['details'].get('failures', []))), pre_freeze_required_platform_gate
        assert 'warningEvidenceIds' not in pre_freeze_required_platform_gate['details'] or 'platform-api.stable-breaking-change-check' not in pre_freeze_required_platform_gate['details'].get('warningEvidenceIds', []), pre_freeze_required_platform_gate
        pre_freeze_required_matrix_row = matrix_row_by_id(workspace / 'build/pre-freeze-required-history-cert', 'platform-api-contract')
        assert pre_freeze_required_matrix_row['status'] == 'fail', pre_freeze_required_matrix_row
        assert pre_freeze_required_matrix_row['releaseBlocker'] is True, pre_freeze_required_matrix_row
        previous_contract_v3 = json.loads(json.dumps(previous_good))
        for entry in previous_contract_v3['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details']['contractVersion'] = 3
                endpoint_capabilities = {'/api/v1/apps/current': ['queue.read'], '/api/v1/apps/old': ['queue.read']}
                endpoint_access = {'/api/v1/apps/current': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}, '/api/v1/apps/old': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}
                set_stable_baseline_details(entry, ['platform.compat.extra', 'queue.read'], ['/api/v1/apps/old', '/api/v1/apps/current'], endpoint_capabilities, endpoint_access)
        previous_contract_v3_path = workspace / 'build/previous-contract-v3/summary.json'
        write_json(previous_contract_v3_path, previous_contract_v3)
        current_contract_sets_path = write_app_summary_variant('current-contract-sets', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableBaseline': {'name': '1.0', 'contractVersion': 19, 'capabilityCount': 1, 'endpointCount': 1, 'capabilities': ['queue.read'], 'endpoints': ['/api/v1/apps/current']}, 'stableBaselineCapabilities': ['queue.read'], 'stableBaselineEndpoints': ['/api/v1/apps/current'], 'stableBaselineCapabilityCount': 1, 'stableBaselineEndpointCount': 1, 'stableEndpointRequiredCapabilities': {'/api/v1/apps/current': ['queue.read']}, 'stableEndpointAppAccess': {'/api/v1/apps/current': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}, 'stableEndpointActionLabels': {'/api/v1/apps/current': 'apps.current'}})))
        contract_regression_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-regression-cert').resolve(), previous_summary=previous_contract_v3_path, app_platform_summary=current_contract_sets_path)
        contract_regression_summary, contract_regression_exit_code = run(contract_regression_settings)
        assert contract_regression_exit_code == 1, contract_regression_summary
        assert gate_by_id(contract_regression_summary, 'ecosystem.platform-api-compatibility')['status'] == 'fail'
        previous_contract_nonempty_sets = json.loads(json.dumps(previous_good))
        for entry in previous_contract_nonempty_sets['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details']['contractVersion'] = 2
                set_stable_baseline_details(entry, ['queue.read'], ['/api/v1/apps/current'], {'/api/v1/apps/current': ['queue.read']}, {'/api/v1/apps/current': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}})
        previous_contract_nonempty_sets_path = workspace / 'build/previous-contract-nonempty-sets/summary.json'
        write_json(previous_contract_nonempty_sets_path, previous_contract_nonempty_sets)
        current_contract_empty_sets_path = write_app_summary_variant('current-contract-empty-sets', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableBaseline': {'name': '1.0', 'contractVersion': 19, 'capabilityCount': 0, 'endpointCount': 0, 'capabilities': [], 'endpoints': []}, 'stableBaselineCapabilities': [], 'stableBaselineEndpoints': [], 'stableBaselineCapabilityCount': 0, 'stableBaselineEndpointCount': 0, 'stableEndpointRequiredCapabilities': {}, 'stableEndpointAppAccess': {}, 'stableEndpointActionLabels': {}})))
        empty_sets_regression_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-empty-sets-regression-cert').resolve(), previous_summary=previous_contract_nonempty_sets_path, app_platform_summary=current_contract_empty_sets_path)
        empty_sets_regression_summary, empty_sets_regression_exit_code = run(empty_sets_regression_settings)
        assert empty_sets_regression_exit_code == 1, empty_sets_regression_summary
        assert gate_by_id(empty_sets_regression_summary, 'ecosystem.platform-api-compatibility')['status'] == 'fail'

        def set_contract_count_details(entry: dict[str, Any], capability_count: int, endpoint_count: int, stable_count: int) -> None:
            contract_details = entry.setdefault('details', {})
            contract_details.pop('stableBaseline', None)
            contract_details.pop('stableBaselineCapabilities', None)
            contract_details.pop('stableBaselineEndpoints', None)
            contract_details.pop('stableBaselineCapabilityCount', None)
            contract_details.pop('stableBaselineEndpointCount', None)
            contract_details.pop('stableCapabilities', None)
            contract_details.pop('stableEndpoints', None)
            contract_details.pop('stableEndpointRequiredCapabilities', None)
            contract_details.pop('stableEndpointAppAccess', None)
            contract_details.pop('stableEndpointActionLabels', None)
            contract_details.pop('stableCapabilityCount', None)
            contract_details.pop('stableEndpointCount', None)
            contract_details.update({'contractVersion': 2, 'capabilityCount': capability_count, 'endpointCount': endpoint_count, 'stabilityCounts': {'stable': stable_count}})
        previous_contract_total_count_drop = json.loads(json.dumps(previous_good))
        for entry in previous_contract_total_count_drop['evidence']:
            if entry['id'] == 'platform-api.contract':
                set_contract_count_details(entry, 20, 80, 75)
        previous_contract_total_count_drop_path = workspace / 'build/previous-contract-total-count-drop/summary.json'
        write_json(previous_contract_total_count_drop_path, previous_contract_total_count_drop)
        current_contract_total_count_drop_path = write_app_summary_variant('current-contract-total-count-drop', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: set_contract_count_details(entry, 19, 79, 75)))
        total_count_drop_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-total-count-drop-cert').resolve(), previous_summary=previous_contract_total_count_drop_path, app_platform_summary=current_contract_total_count_drop_path)
        total_count_drop_summary, total_count_drop_exit_code = run(total_count_drop_settings)
        assert total_count_drop_exit_code == 0, total_count_drop_summary
        assert gate_by_id(total_count_drop_summary, 'ecosystem.platform-api-compatibility')['status'] == 'pass'
        current_contract_stable_count_drop_path = write_app_summary_variant('current-contract-stable-count-drop', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: set_contract_count_details(entry, 19, 79, 74)))
        stable_count_drop_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-stable-count-drop-cert').resolve(), previous_summary=previous_contract_total_count_drop_path, app_platform_summary=current_contract_stable_count_drop_path)
        stable_count_drop_summary, stable_count_drop_exit_code = run(stable_count_drop_settings)
        assert stable_count_drop_exit_code == 1, stable_count_drop_summary
        assert gate_by_id(stable_count_drop_summary, 'ecosystem.platform-api-compatibility')['status'] == 'fail'
        previous_contract_endpoint_caps = json.loads(json.dumps(previous_good))
        for entry in previous_contract_endpoint_caps['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details']['contractVersion'] = 2
                entry['details']['stableEndpointRequiredCapabilities'] = entry['details'].get('stableEndpointRequiredCapabilities', {}) | {'GET /queue': ['queue.read']}
                entry['details']['stableEndpointAppAccess'] = entry['details'].get('stableEndpointAppAccess', {}) | {'GET /queue': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}
        previous_contract_endpoint_caps_path = workspace / 'build/previous-contract-endpoint-caps/summary.json'
        write_json(previous_contract_endpoint_caps_path, previous_contract_endpoint_caps)
        current_contract_endpoint_caps_path = write_app_summary_variant('current-contract-endpoint-caps', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableEndpointRequiredCapabilities': entry.setdefault('details', {}).get('stableEndpointRequiredCapabilities', {}) | {'GET /queue': ['queue.write']}, 'stableEndpointAppAccess': entry.setdefault('details', {}).get('stableEndpointAppAccess', {}) | {'GET /queue': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}})))
        endpoint_capability_regression_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-capability-regression-cert').resolve(), previous_summary=previous_contract_endpoint_caps_path, app_platform_summary=current_contract_endpoint_caps_path)
        endpoint_capability_regression_summary, endpoint_capability_regression_exit_code = run(endpoint_capability_regression_settings)
        assert endpoint_capability_regression_exit_code == 1, endpoint_capability_regression_summary
        endpoint_capability_regression_gate = gate_by_id(endpoint_capability_regression_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_capability_regression_gate['status'] == 'fail', endpoint_capability_regression_gate
        assert 'GET /queue' in endpoint_capability_regression_gate['details']['stableEndpointCapabilityChanges'][0]['endpoint'], endpoint_capability_regression_gate
        assert endpoint_capability_regression_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_capability_regression_gate
        current_contract_endpoint_caps_missing_path = write_app_summary_variant('current-contract-endpoint-caps-missing', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableEndpointRequiredCapabilities': {endpoint: capabilities for endpoint, capabilities in entry.setdefault('details', {}).get('stableEndpointRequiredCapabilities', {}).items() if endpoint != 'GET /queue'}})))
        endpoint_capability_missing_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-capability-missing-cert').resolve(), previous_summary=previous_contract_endpoint_caps_path, app_platform_summary=current_contract_endpoint_caps_missing_path)
        endpoint_capability_missing_summary, endpoint_capability_missing_exit_code = run(endpoint_capability_missing_settings)
        assert endpoint_capability_missing_exit_code == 1, endpoint_capability_missing_summary
        endpoint_capability_missing_gate = gate_by_id(endpoint_capability_missing_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_capability_missing_gate['status'] == 'fail', endpoint_capability_missing_gate
        assert endpoint_capability_missing_gate['details']['stableEndpointRequiredCapabilitiesMissing'] == ['GET /queue'], endpoint_capability_missing_gate
        assert endpoint_capability_missing_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_capability_missing_gate
        previous_contract_endpoint_access = json.loads(json.dumps(previous_good))
        for entry in previous_contract_endpoint_access['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details']['contractVersion'] = 2
                entry['details']['stableEndpointRequiredCapabilities'] = entry['details'].get('stableEndpointRequiredCapabilities', {}) | {'GET /queue': ['queue.read']}
                entry['details']['stableEndpointAppAccess'] = entry['details'].get('stableEndpointAppAccess', {}) | {'GET /queue': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}
        previous_contract_endpoint_access_path = workspace / 'build/previous-contract-endpoint-access/summary.json'
        write_json(previous_contract_endpoint_access_path, previous_contract_endpoint_access)
        current_contract_endpoint_access_path = write_app_summary_variant('current-contract-endpoint-access', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableEndpointRequiredCapabilities': entry.setdefault('details', {}).get('stableEndpointRequiredCapabilities', {}) | {'GET /queue': ['queue.read']}, 'stableEndpointAppAccess': entry.setdefault('details', {}).get('stableEndpointAppAccess', {}) | {'GET /queue': {'appProcessPrincipalsAllowed': False, 'appBrowserPrincipalsAllowed': True}}})))
        endpoint_access_regression_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-access-regression-cert').resolve(), previous_summary=previous_contract_endpoint_access_path, app_platform_summary=current_contract_endpoint_access_path)
        endpoint_access_regression_summary, endpoint_access_regression_exit_code = run(endpoint_access_regression_settings)
        assert endpoint_access_regression_exit_code == 1, endpoint_access_regression_summary
        endpoint_access_regression_gate = gate_by_id(endpoint_access_regression_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_access_regression_gate['status'] == 'fail', endpoint_access_regression_gate
        assert 'GET /queue' in endpoint_access_regression_gate['details']['stableEndpointAccessChanges'][0]['endpoint'], endpoint_access_regression_gate
        assert endpoint_access_regression_gate['details']['stableEndpointAccessChanges'][0]['current']['appProcessPrincipalsAllowed'] is False, endpoint_access_regression_gate
        assert endpoint_access_regression_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_access_regression_gate
        current_contract_endpoint_access_missing_path = write_app_summary_variant('current-contract-endpoint-access-missing', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableEndpointAppAccess': {endpoint: access for endpoint, access in entry.setdefault('details', {}).get('stableEndpointAppAccess', {}).items() if endpoint != 'GET /queue'}})))
        endpoint_access_missing_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-access-missing-cert').resolve(), previous_summary=previous_contract_endpoint_access_path, app_platform_summary=current_contract_endpoint_access_missing_path)
        endpoint_access_missing_summary, endpoint_access_missing_exit_code = run(endpoint_access_missing_settings)
        assert endpoint_access_missing_exit_code == 1, endpoint_access_missing_summary
        endpoint_access_missing_gate = gate_by_id(endpoint_access_missing_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_access_missing_gate['status'] == 'fail', endpoint_access_missing_gate
        assert endpoint_access_missing_gate['details']['stableEndpointAppAccessMissing'] == ['GET /queue'], endpoint_access_missing_gate
        assert endpoint_access_missing_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_access_missing_gate
        previous_contract_endpoint_labels = json.loads(json.dumps(previous_good))
        for entry in previous_contract_endpoint_labels['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details']['contractVersion'] = 2
                entry['details']['stableEndpointActionLabels']['GET /queue'] = 'queue.read'
        previous_contract_endpoint_labels_path = workspace / 'build/previous-contract-endpoint-labels/summary.json'
        write_json(previous_contract_endpoint_labels_path, previous_contract_endpoint_labels)
        current_contract_endpoint_labels_path = write_app_summary_variant('current-contract-endpoint-labels', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableEndpointActionLabels': entry.setdefault('details', {}).get('stableEndpointActionLabels', {}) | {'GET /queue': 'queue.read.changed'}})))
        endpoint_label_regression_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-label-regression-cert').resolve(), previous_summary=previous_contract_endpoint_labels_path, app_platform_summary=current_contract_endpoint_labels_path)
        endpoint_label_regression_summary, endpoint_label_regression_exit_code = run(endpoint_label_regression_settings)
        assert endpoint_label_regression_exit_code == 1, endpoint_label_regression_summary
        endpoint_label_regression_gate = gate_by_id(endpoint_label_regression_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_label_regression_gate['status'] == 'fail', endpoint_label_regression_gate
        assert 'GET /queue' in endpoint_label_regression_gate['details']['stableEndpointActionLabelChanges'][0]['endpoint'], endpoint_label_regression_gate
        assert endpoint_label_regression_gate['details']['stableEndpointActionLabelChanges'][0]['current'] == 'queue.read.changed', endpoint_label_regression_gate
        assert endpoint_label_regression_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_label_regression_gate
        current_contract_endpoint_labels_missing_path = write_app_summary_variant('current-contract-endpoint-labels-missing', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).update({'contractVersion': 2, 'stableEndpointActionLabels': {endpoint: label for endpoint, label in entry.setdefault('details', {}).get('stableEndpointActionLabels', {}).items() if endpoint != 'GET /queue'}})))
        endpoint_label_missing_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-label-missing-cert').resolve(), previous_summary=previous_contract_endpoint_labels_path, app_platform_summary=current_contract_endpoint_labels_missing_path)
        endpoint_label_missing_summary, endpoint_label_missing_exit_code = run(endpoint_label_missing_settings)
        assert endpoint_label_missing_exit_code == 1, endpoint_label_missing_summary
        endpoint_label_missing_gate = gate_by_id(endpoint_label_missing_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_label_missing_gate['status'] == 'fail', endpoint_label_missing_gate
        assert endpoint_label_missing_gate['details']['stableEndpointActionLabelsMissing'] == ['GET /queue'], endpoint_label_missing_gate
        assert endpoint_label_missing_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_label_missing_gate
        concrete_baseline_endpoints = ['GET /apps/current', 'GET /apps/old']
        concrete_endpoint_capabilities = {'GET /apps/current': ['queue.read'], 'GET /apps/old': ['queue.read']}
        concrete_endpoint_access = {'GET /apps/current': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}, 'GET /apps/old': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}
        concrete_endpoint_labels = {'GET /apps/current': 'apps.current', 'GET /apps/old': 'apps.old'}
        previous_concrete_endpoint_metadata = json.loads(json.dumps(previous_good))
        for entry in previous_concrete_endpoint_metadata['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details']['contractVersion'] = 2
                set_stable_baseline_details(entry, ['queue.read'], concrete_baseline_endpoints, concrete_endpoint_capabilities, concrete_endpoint_access, concrete_endpoint_labels)
        previous_concrete_endpoint_metadata_path = workspace / 'build/previous-concrete-endpoint-metadata/summary.json'
        write_json(previous_concrete_endpoint_metadata_path, previous_concrete_endpoint_metadata)

        def write_current_concrete_endpoint_metadata(name: str, endpoint_capabilities: dict[str, list[str]], endpoint_access: dict[str, dict[str, bool]], endpoint_labels: dict[str, str]) -> Path:

            def update_contract(entry: dict[str, Any]) -> None:
                entry.setdefault('details', {})['contractVersion'] = 2
                set_stable_baseline_details(entry, ['queue.read'], concrete_baseline_endpoints, endpoint_capabilities, endpoint_access, endpoint_labels)
            return write_app_summary_variant(name, lambda value: update_evidence(value, 'platform-api.contract', update_contract))
        padded_endpoint_capability_path = write_current_concrete_endpoint_metadata('current-padded-endpoint-capabilities', {'GET /apps/current': ['queue.read'], 'GET /apps/extra': ['queue.read']}, concrete_endpoint_access, concrete_endpoint_labels)
        padded_endpoint_capability_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/padded-endpoint-capability-cert').resolve(), previous_summary=previous_concrete_endpoint_metadata_path, app_platform_summary=padded_endpoint_capability_path)
        padded_endpoint_capability_summary, padded_endpoint_capability_exit_code = run(padded_endpoint_capability_settings)
        assert padded_endpoint_capability_exit_code == 1, padded_endpoint_capability_summary
        padded_endpoint_capability_gate = gate_by_id(padded_endpoint_capability_summary, 'ecosystem.platform-api-compatibility')
        assert padded_endpoint_capability_gate['status'] == 'fail', padded_endpoint_capability_gate
        assert padded_endpoint_capability_gate['details']['stableEndpointRequiredCapabilitiesMissing'] == ['GET /apps/old'], padded_endpoint_capability_gate
        padded_endpoint_access_path = write_current_concrete_endpoint_metadata('current-padded-endpoint-access', concrete_endpoint_capabilities, {'GET /apps/current': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}, 'GET /apps/extra': {'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True}}, concrete_endpoint_labels)
        padded_endpoint_access_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/padded-endpoint-access-cert').resolve(), previous_summary=previous_concrete_endpoint_metadata_path, app_platform_summary=padded_endpoint_access_path)
        padded_endpoint_access_summary, padded_endpoint_access_exit_code = run(padded_endpoint_access_settings)
        assert padded_endpoint_access_exit_code == 1, padded_endpoint_access_summary
        padded_endpoint_access_gate = gate_by_id(padded_endpoint_access_summary, 'ecosystem.platform-api-compatibility')
        assert padded_endpoint_access_gate['status'] == 'fail', padded_endpoint_access_gate
        assert padded_endpoint_access_gate['details']['stableEndpointAppAccessMissing'] == ['GET /apps/old'], padded_endpoint_access_gate
        padded_endpoint_labels_path = write_current_concrete_endpoint_metadata('current-padded-endpoint-labels', concrete_endpoint_capabilities, concrete_endpoint_access, {'GET /apps/current': 'apps.current', 'GET /apps/extra': 'apps.extra'})
        padded_endpoint_label_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/padded-endpoint-label-cert').resolve(), previous_summary=previous_concrete_endpoint_metadata_path, app_platform_summary=padded_endpoint_labels_path)
        padded_endpoint_label_summary, padded_endpoint_label_exit_code = run(padded_endpoint_label_settings)
        assert padded_endpoint_label_exit_code == 1, padded_endpoint_label_summary
        padded_endpoint_label_gate = gate_by_id(padded_endpoint_label_summary, 'ecosystem.platform-api-compatibility')
        assert padded_endpoint_label_gate['status'] == 'fail', padded_endpoint_label_gate
        assert padded_endpoint_label_gate['details']['stableEndpointActionLabelsMissing'] == ['GET /apps/old'], padded_endpoint_label_gate
        current_contract_endpoint_labels_unavailable_path = write_app_summary_variant('current-contract-endpoint-labels-unavailable', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: entry.setdefault('details', {}).pop('stableEndpointActionLabels', None)))
        endpoint_label_unavailable_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-endpoint-label-unavailable-cert').resolve(), previous_summary=previous_contract_endpoint_labels_path, app_platform_summary=current_contract_endpoint_labels_unavailable_path, waivers={'ecosystem.platform-api-compatibility': 'Release manager attempted to waive missing current action-label metadata.', 'platform-api.stable-breaking-change-check': 'Release manager attempted to waive missing current action-label metadata.'})
        endpoint_label_unavailable_summary, endpoint_label_unavailable_exit_code = run(endpoint_label_unavailable_settings)
        assert endpoint_label_unavailable_exit_code == 1, endpoint_label_unavailable_summary
        endpoint_label_unavailable_gate = gate_by_id(endpoint_label_unavailable_summary, 'ecosystem.platform-api-compatibility')
        assert endpoint_label_unavailable_gate['status'] == 'fail', endpoint_label_unavailable_gate
        assert 'waived' not in endpoint_label_unavailable_gate['details'], endpoint_label_unavailable_gate
        assert endpoint_label_unavailable_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], endpoint_label_unavailable_gate
        assert any(('action-label metadata is unavailable' in failure for failure in endpoint_label_unavailable_gate['details'].get('failures', []))), endpoint_label_unavailable_gate
        previous_contract_endpoint_labels_unavailable = json.loads(json.dumps(previous_contract_endpoint_labels))
        for entry in previous_contract_endpoint_labels_unavailable['evidence']:
            if entry['id'] == 'platform-api.contract':
                entry['details'].pop('stableEndpointActionLabels', None)
        previous_contract_endpoint_labels_unavailable_path = workspace / 'build/previous-contract-endpoint-labels-unavailable/summary.json'
        write_json(previous_contract_endpoint_labels_unavailable_path, previous_contract_endpoint_labels_unavailable)
        previous_label_unavailable_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/previous-endpoint-label-unavailable-cert').resolve(), previous_summary=previous_contract_endpoint_labels_unavailable_path, require_history=True, waivers={'ecosystem.platform-api-compatibility': 'Release manager attempted to waive missing previous action-label metadata.', 'platform-api.stable-breaking-change-check': 'Release manager attempted to waive missing previous action-label metadata.'})
        previous_label_unavailable_summary, previous_label_unavailable_exit_code = run(previous_label_unavailable_settings)
        assert previous_label_unavailable_exit_code == 1, previous_label_unavailable_summary
        previous_label_unavailable_gate = gate_by_id(previous_label_unavailable_summary, 'ecosystem.platform-api-compatibility')
        assert previous_label_unavailable_gate['status'] == 'fail', previous_label_unavailable_gate
        assert 'waived' not in previous_label_unavailable_gate['details'], previous_label_unavailable_gate
        assert previous_label_unavailable_gate['details']['unwaivableFailureEvidenceIds'] == ['platform-api.stable-breaking-change-check'], previous_label_unavailable_gate
        assert any(('Previous stable endpoint action-label metadata is unavailable' in failure for failure in previous_label_unavailable_gate['details'].get('failures', []))), previous_label_unavailable_gate

        def set_contract_raw_endpoint_details(entry: dict[str, Any], routes: list[str], stable_count: int) -> None:
            contract_details = entry.setdefault('details', {})
            contract_details.pop('stableBaseline', None)
            contract_details.pop('stableBaselineCapabilities', None)
            contract_details.pop('stableBaselineEndpoints', None)
            contract_details.pop('stableBaselineCapabilityCount', None)
            contract_details.pop('stableBaselineEndpointCount', None)
            contract_details.pop('stableEndpoints', None)
            contract_details.pop('stableEndpointRequiredCapabilities', None)
            contract_details.pop('stableEndpointAppAccess', None)
            contract_details.pop('stableEndpointActionLabels', None)
            contract_details.update({'contractVersion': 2, 'endpointCount': len(routes), 'stabilityCounts': {'stable': stable_count}, 'endpoints': [{'method': 'GET', 'routeTemplate': route, 'actionLabel': route, 'stability': 'stable', 'appProcessPrincipalsAllowed': True, 'appBrowserPrincipalsAllowed': True} for route in routes]})
        previous_contract_raw_endpoints = json.loads(json.dumps(previous_good))
        for entry in previous_contract_raw_endpoints['evidence']:
            if entry['id'] == 'platform-api.contract':
                set_contract_raw_endpoint_details(entry, ['/apps/{appId}/old', '/apps/{appId}/current'], 2)
        previous_contract_raw_endpoints_path = workspace / 'build/previous-contract-raw-endpoints/summary.json'
        write_json(previous_contract_raw_endpoints_path, previous_contract_raw_endpoints)
        current_contract_raw_endpoint_removal_path = write_app_summary_variant('current-contract-raw-endpoint-removal', lambda value: update_evidence(value, 'platform-api.contract', lambda entry: set_contract_raw_endpoint_details(entry, ['/apps/{appId}/current', '/apps/{appId}/new'], 2)))
        raw_endpoint_removal_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/contract-raw-endpoint-removal-cert').resolve(), previous_summary=previous_contract_raw_endpoints_path, app_platform_summary=current_contract_raw_endpoint_removal_path)
        raw_endpoint_removal_summary, raw_endpoint_removal_exit_code = run(raw_endpoint_removal_settings)
        assert raw_endpoint_removal_exit_code == 1, raw_endpoint_removal_summary
        raw_endpoint_removal_gate = gate_by_id(raw_endpoint_removal_summary, 'ecosystem.platform-api-compatibility')
        assert raw_endpoint_removal_gate['status'] == 'fail', raw_endpoint_removal_gate
        assert 'GET /apps/{appId}/old' in raw_endpoint_removal_gate['summary'], raw_endpoint_removal_gate
        first_party_apps_map_path = write_app_summary_variant('first-party-apps-map', lambda value: update_evidence(value, 'app-platform.first-party', lambda entry: entry.setdefault('details', {}).update({'apps': {'queue-manager': {}, 'publisher': {}, 'site-publisher': {}, 'profile-publisher': {}, 'feed-reader': {}, 'social-inbox': {}, 'trust-graph': {}}})))
        first_party_apps_map_summary, first_party_apps_map_exit_code = run_with_previous('first-party-apps-map-cert', app_platform_summary=first_party_apps_map_path)
        assert first_party_apps_map_exit_code == 0, first_party_apps_map_summary
        assert gate_by_id(first_party_apps_map_summary, 'ecosystem.first-party-apps')['status'] == 'pass'
        first_party_missing_path = write_app_summary_variant('first-party-missing', lambda value: update_evidence(value, 'app-platform.first-party', lambda entry: entry.setdefault('details', {}).update({'apps': ['queue-manager', 'publisher']})))
        first_party_missing_summary, first_party_missing_exit_code = run_with_previous('first-party-missing-cert', app_platform_summary=first_party_missing_path)
        assert first_party_missing_exit_code == 1, first_party_missing_summary
        assert gate_by_id(first_party_missing_summary, 'ecosystem.first-party-apps')['status'] == 'fail'
        reference_missing_path = write_app_summary_variant('reference-missing', lambda value: update_evidence(value, 'reference-apps.content', lambda entry: entry.update({'status': 'missing'})))
        reference_missing_summary, reference_missing_exit_code = run_with_previous('reference-missing-cert', app_platform_summary=reference_missing_path)
        assert reference_missing_exit_code == 1, reference_missing_summary
        assert gate_by_id(reference_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        feed_reader_missing_path = write_app_summary_variant('feed-reader-missing', lambda value: update_evidence(value, 'reference-app.feed-reader', lambda entry: entry.update({'status': 'missing'})))
        feed_reader_missing_summary, feed_reader_missing_exit_code = run_with_previous('feed-reader-missing-cert', app_platform_summary=feed_reader_missing_path)
        assert feed_reader_missing_exit_code == 1, feed_reader_missing_summary
        assert gate_by_id(feed_reader_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        feed_reader_subscription_missing_path = write_app_summary_variant('feed-reader-subscriptions-missing', lambda value: update_evidence(value, 'reference-app.feed-reader-subscriptions', lambda entry: entry.update({'status': 'missing'})))
        feed_reader_subscription_missing_summary, feed_reader_subscription_missing_exit_code = run_with_previous('feed-reader-subscriptions-missing-cert', app_platform_summary=feed_reader_subscription_missing_path)
        assert feed_reader_subscription_missing_exit_code == 1, feed_reader_subscription_missing_summary
        assert gate_by_id(feed_reader_subscription_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        trust_graph_missing_path = write_app_summary_variant('trust-graph-missing', lambda value: update_evidence(value, 'reference-app.trust-graph', lambda entry: entry.update({'status': 'missing'})))
        trust_graph_missing_summary, trust_graph_missing_exit_code = run_with_previous('trust-graph-missing-cert', app_platform_summary=trust_graph_missing_path)
        assert trust_graph_missing_exit_code == 1, trust_graph_missing_summary
        assert gate_by_id(trust_graph_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        content_fetch_missing_path = write_app_summary_variant('content-fetch-missing', lambda value: update_evidence(value, 'app-platform.content-fetch', lambda entry: entry.update({'status': 'missing'})))
        content_fetch_missing_summary, content_fetch_missing_exit_code = run_with_previous('content-fetch-missing-cert', app_platform_summary=content_fetch_missing_path)
        assert content_fetch_missing_exit_code == 1, content_fetch_missing_summary
        assert gate_by_id(content_fetch_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        content_subscription_missing_path = write_app_summary_variant('content-subscriptions-missing', lambda value: update_evidence(value, 'app-platform.content-subscriptions', lambda entry: entry.update({'status': 'missing'})))
        content_subscription_missing_summary, content_subscription_missing_exit_code = run_with_previous('content-subscriptions-missing-cert', app_platform_summary=content_subscription_missing_path)
        assert content_subscription_missing_exit_code == 1, content_subscription_missing_summary
        assert gate_by_id(content_subscription_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        subscription_scheduler_missing_path = write_app_summary_variant('subscription-scheduler-missing', lambda value: update_evidence(value, 'network-content.subscription-scheduler', lambda entry: entry.update({'status': 'missing'})))
        subscription_scheduler_missing_summary, subscription_scheduler_missing_exit_code = run_with_previous('subscription-scheduler-missing-cert', app_platform_summary=subscription_scheduler_missing_path)
        assert subscription_scheduler_missing_exit_code == 1, subscription_scheduler_missing_summary
        assert gate_by_id(subscription_scheduler_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        trust_preview_missing_path = write_app_summary_variant('trust-preview-missing', lambda value: update_evidence(value, 'app-platform.trust-graph-preview', lambda entry: entry.update({'status': 'missing'})))
        trust_preview_missing_summary, trust_preview_missing_exit_code = run_with_previous('trust-preview-missing-cert', app_platform_summary=trust_preview_missing_path)
        assert trust_preview_missing_exit_code == 1, trust_preview_missing_summary
        assert gate_by_id(trust_preview_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        trust_signing_missing_path = write_app_summary_variant('trust-signing-missing', lambda value: update_evidence(value, 'app-platform.trust-statement-signing', lambda entry: entry.update({'status': 'missing'})))
        trust_signing_missing_summary, trust_signing_missing_exit_code = run_with_previous('trust-signing-missing-cert', app_platform_summary=trust_signing_missing_path)
        assert trust_signing_missing_exit_code == 1, trust_signing_missing_summary
        assert gate_by_id(trust_signing_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        social_inbox_missing_path = write_app_summary_variant('social-inbox-missing', lambda value: update_evidence(value, 'reference-app.social-inbox', lambda entry: entry.update({'status': 'missing'})))
        social_inbox_missing_summary, social_inbox_missing_exit_code = run_with_previous('social-inbox-missing-cert', app_platform_summary=social_inbox_missing_path)
        assert social_inbox_missing_exit_code == 1, social_inbox_missing_summary
        assert gate_by_id(social_inbox_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        social_message_signing_missing_path = write_app_summary_variant('social-message-signing-missing', lambda value: update_evidence(value, 'app-platform.social-message-signing', lambda entry: entry.update({'status': 'missing'})))
        social_message_signing_missing_summary, social_message_signing_missing_exit_code = run_with_previous('social-message-signing-missing-cert', app_platform_summary=social_message_signing_missing_path)
        assert social_message_signing_missing_exit_code == 1, social_message_signing_missing_summary
        assert gate_by_id(social_message_signing_missing_summary, 'ecosystem.reference-content-apps')['status'] == 'fail'
        trusted_review_fail_path = write_app_summary_variant('trusted-review-fail', lambda value: update_evidence(value, 'app-review.trusted-receipts', lambda entry: entry.update({'status': 'fail'})))
        trusted_review_fail_summary, trusted_review_fail_exit_code = run_with_previous('trusted-review-fail-cert', app_platform_summary=trusted_review_fail_path)
        assert trusted_review_fail_exit_code == 1, trusted_review_fail_summary
        assert gate_by_id(trusted_review_fail_summary, 'ecosystem.app-review-trust')['status'] == 'fail'
        missing_review_governance_ids = {'app-review.governance', 'app-review.reviewer-key-lifecycle', 'app-review.transparency-log', 'app-review.review-history-api', 'app-review.first-party-review-chain'}
        missing_review_governance_path = write_app_summary_variant('missing-review-governance', lambda value: value.update({'evidence': [item for item in value['evidence'] if item.get('id') not in missing_review_governance_ids]}))
        missing_review_governance_items = app_platform_evidence(missing_review_governance_path, workspace, out_dir, 'release-candidate')
        missing_review_governance_by_id = {item.id: item for item in missing_review_governance_items}
        for evidence_id in missing_review_governance_ids:
            assert missing_review_governance_by_id[evidence_id].status == 'missing', missing_review_governance_by_id
        missing_review_governance_summary, missing_review_governance_exit_code = run_with_previous('missing-review-governance-cert', app_platform_summary=missing_review_governance_path)
        assert missing_review_governance_exit_code == 1, missing_review_governance_summary
        missing_review_governance_gate = gate_by_id(missing_review_governance_summary, 'ecosystem.app-review-trust')
        assert missing_review_governance_gate['status'] == 'fail', missing_review_governance_gate
        for evidence_id in missing_review_governance_ids:
            assert evidence_id in missing_review_governance_gate['details']['failureEvidenceIds'], missing_review_governance_gate
        rollback_fail_path = write_app_summary_variant('rollback-fail', lambda value: update_evidence(value, 'app-update.rollback', lambda entry: entry.update({'status': 'fail'})))
        rollback_fail_summary, rollback_fail_exit_code = run_with_previous('rollback-fail-cert', app_platform_summary=rollback_fail_path)
        assert rollback_fail_exit_code == 1, rollback_fail_summary
        assert gate_by_id(rollback_fail_summary, 'ecosystem.app-update-rollback')['status'] == 'fail'
        scheduler_fail_path = write_app_summary_variant('scheduler-fail', lambda value: update_evidence(value, 'app-update.scheduler', lambda entry: entry.update({'status': 'fail'})))
        scheduler_fail_summary, scheduler_fail_exit_code = run_with_previous('scheduler-fail-cert', app_platform_summary=scheduler_fail_path)
        assert scheduler_fail_exit_code == 1, scheduler_fail_summary
        assert gate_by_id(scheduler_fail_summary, 'ecosystem.app-update-rollback')['status'] == 'fail'
        vault_missing_capability_path = write_app_summary_variant('vault-missing-capability', lambda value: update_evidence(value, 'app-vault.capabilities', lambda entry: entry.setdefault('details', {}).update({'capabilities': ['vault.secrets.read']})))
        vault_missing_capability_summary, vault_missing_capability_exit_code = run_with_previous('vault-missing-capability-cert', app_platform_summary=vault_missing_capability_path)
        assert vault_missing_capability_exit_code == 1, vault_missing_capability_summary
        assert gate_by_id(vault_missing_capability_summary, 'ecosystem.app-vault')['status'] == 'fail'
        waived_vault_evidence_summary, waived_vault_evidence_exit_code = run_with_previous('waived-vault-evidence-cert', app_platform_summary=vault_missing_capability_path, waivers={'app-vault.capabilities': 'Release manager accepted vault evidence gap.'})
        assert waived_vault_evidence_exit_code == 0, waived_vault_evidence_summary
        waived_vault_gate = gate_by_id(waived_vault_evidence_summary, 'ecosystem.app-vault')
        assert waived_vault_gate['status'] == 'warn', waived_vault_gate
        assert waived_vault_gate['releaseBlocker'] is False, waived_vault_gate
        assert waived_vault_gate['details']['waived'] is True, waived_vault_gate
        assert waived_vault_gate['details']['waivedEvidenceIds'] == ['app-vault.capabilities'], waived_vault_gate
        waived_vault_row = matrix_row_by_id(workspace / 'build/waived-vault-evidence-cert', 'app-vault-and-generated-documents')
        assert waived_vault_row['status'] == 'warn', waived_vault_row
        assert waived_vault_row['releaseBlocker'] is False, waived_vault_row
        assert 'app-vault.capabilities' in waived_vault_row['waiverIds'], waived_vault_row
        waived_vault_clean_summary, waived_vault_clean_exit_code = run_with_previous('waived-vault-clean-history-cert', app_platform_summary=vault_missing_capability_path, previous_summary=previous_matrix_good_path, waivers={'app-vault.capabilities': 'Release manager accepted vault evidence gap.'})
        assert waived_vault_clean_exit_code == 0, waived_vault_clean_summary
        assert waived_vault_clean_summary['status'] == 'warn', waived_vault_clean_summary
        assert waived_vault_clean_summary['promotionDecision'] == 'PASS WITH WARNINGS', waived_vault_clean_summary
        assert waived_vault_clean_summary['releaseCandidatePassed'] is True, waived_vault_clean_summary
        assert waived_vault_clean_summary['ecosystemRcGate']['status'] == 'warn', waived_vault_clean_summary
        assert waived_vault_clean_summary['ecosystemRcGate']['waiverCount'] == 1, waived_vault_clean_summary
        waived_vault_rc_row = matrix_row_by_id(workspace / 'build/waived-vault-clean-history-cert', ECOSYSTEM_RC_MATRIX_ROW_ID)
        assert waived_vault_rc_row['status'] == 'warn', waived_vault_rc_row
        assert waived_vault_rc_row['releaseBlocker'] is False, waived_vault_rc_row
        assert 'app-vault.capabilities' in waived_vault_rc_row['waiverIds'], waived_vault_rc_row
        vault_missing_redaction_path = write_app_summary_variant('vault-missing-redaction', lambda value: update_evidence(value, 'app-vault.capabilities', lambda entry: entry.setdefault('details', {}).pop('redaction', None)))
        vault_missing_redaction_summary, vault_missing_redaction_exit_code = run_with_previous('vault-missing-redaction-cert', app_platform_summary=vault_missing_redaction_path)
        assert vault_missing_redaction_exit_code == 1, vault_missing_redaction_summary
        assert gate_by_id(vault_missing_redaction_summary, 'ecosystem.app-vault')['status'] == 'fail'
        sandbox_best_effort_path = write_app_summary_variant('sandbox-best-effort', lambda value: update_evidence(value, 'apphost.sandbox-provider', lambda entry: entry.setdefault('details', {}).update({'supportLevel': 'best-effort'})))
        sandbox_best_effort_summary, sandbox_best_effort_exit_code = run_with_previous('sandbox-best-effort-cert', app_platform_summary=sandbox_best_effort_path)
        assert sandbox_best_effort_exit_code == 1, sandbox_best_effort_summary
        assert gate_by_id(sandbox_best_effort_summary, 'ecosystem.sandbox-provider')['status'] == 'fail'
        waived_sandbox_evidence_summary, waived_sandbox_evidence_exit_code = run_with_previous('waived-sandbox-evidence-cert', app_platform_summary=sandbox_best_effort_path, waivers={'apphost.sandbox-provider': 'Release manager accepted sandbox provider gap.'})
        assert waived_sandbox_evidence_exit_code == 0, waived_sandbox_evidence_summary
        waived_sandbox_evidence_gate = gate_by_id(waived_sandbox_evidence_summary, 'ecosystem.sandbox-provider')
        assert waived_sandbox_evidence_gate['status'] == 'warn', waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate['releaseBlocker'] is False, waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate['details']['waived'] is True, waived_sandbox_evidence_gate
        assert waived_sandbox_evidence_gate['details']['waivedEvidenceIds'] == ['apphost.sandbox-provider'], waived_sandbox_evidence_gate
        legacy_removed_path = write_app_summary_variant('legacy-wave-removed', lambda value: value.update({'evidence': [entry for entry in value['evidence'] if entry.get('id') != 'legacy-admin.removal-wave-1']}))
        legacy_removed_summary, legacy_removed_exit_code = run_with_previous('legacy-wave-removed-cert', app_platform_summary=legacy_removed_path)
        assert legacy_removed_exit_code == 1, legacy_removed_summary
        assert gate_by_id(legacy_removed_summary, 'ecosystem.legacy-retirement')['status'] == 'fail'
        legacy_wave_two_removed_path = write_app_summary_variant('legacy-wave-two-removed', lambda value: value.update({'evidence': [entry for entry in value['evidence'] if entry.get('id') != 'legacy-admin.removal-wave-2']}))
        legacy_wave_two_removed_summary, legacy_wave_two_removed_exit_code = run_with_previous('legacy-wave-two-removed-cert', app_platform_summary=legacy_wave_two_removed_path)
        assert legacy_wave_two_removed_exit_code == 1, legacy_wave_two_removed_summary
        assert gate_by_id(legacy_wave_two_removed_summary, 'ecosystem.legacy-retirement')['status'] == 'fail'
        legacy_wave_three_removed_path = write_app_summary_variant('legacy-wave-three-removed', lambda value: value.update({'evidence': [entry for entry in value['evidence'] if entry.get('id') != 'legacy-admin.removal-wave-3']}))
        legacy_wave_three_removed_summary, legacy_wave_three_removed_exit_code = run_with_previous('legacy-wave-three-removed-cert', app_platform_summary=legacy_wave_three_removed_path)
        assert legacy_wave_three_removed_exit_code == 1, legacy_wave_three_removed_summary
        assert gate_by_id(legacy_wave_three_removed_summary, 'ecosystem.legacy-retirement')['status'] == 'fail'
        legacy_wave_four_removed_path = write_app_summary_variant('legacy-wave-four-removed', lambda value: value.update({'evidence': [entry for entry in value['evidence'] if entry.get('id') != 'legacy-admin.removal-wave-4']}))
        legacy_wave_four_removed_summary, legacy_wave_four_removed_exit_code = run_with_previous('legacy-wave-four-removed-cert', app_platform_summary=legacy_wave_four_removed_path)
        assert legacy_wave_four_removed_exit_code == 1, legacy_wave_four_removed_summary
        assert gate_by_id(legacy_wave_four_removed_summary, 'ecosystem.legacy-retirement')['status'] == 'fail'
        legacy_wave_five_removed_path = write_app_summary_variant('legacy-wave-five-removed', lambda value: value.update({'evidence': [entry for entry in value['evidence'] if entry.get('id') != 'legacy-admin.removal-wave-5']}))
        legacy_wave_five_removed_summary, legacy_wave_five_removed_exit_code = run_with_previous('legacy-wave-five-removed-cert', app_platform_summary=legacy_wave_five_removed_path)
        assert legacy_wave_five_removed_exit_code == 1, legacy_wave_five_removed_summary
        assert gate_by_id(legacy_wave_five_removed_summary, 'ecosystem.legacy-retirement')['status'] == 'fail'
        waiver_file_path = workspace / 'docs/release-waivers/self-test.json'
        write_json(waiver_file_path, {'version': 1, 'release': 'self-test', 'waivers': [{'id': 'ecosystem.sandbox-provider', 'evidenceId': 'ecosystem.sandbox-provider', 'status': 'approved', 'approvedBy': 'release-manager', 'reason': f'token=hunter2 accepted for fixture {workspace}/secret', 'expiresAt': '2099-01-01T00:00:00Z', 'allowReleaseCandidate': True}]})
        waived_sandbox_summary, waived_sandbox_exit_code = run_with_previous('waived-sandbox-cert', app_platform_summary=sandbox_best_effort_path, waiver_files=(waiver_file_path,))
        assert waived_sandbox_exit_code == 0, waived_sandbox_summary
        assert waived_sandbox_summary['status'] == 'warn', waived_sandbox_summary
        assert waived_sandbox_summary['waivers'] == {}, waived_sandbox_summary
        assert len(waived_sandbox_summary['waiverRecords']) == 1, waived_sandbox_summary
        waived_sandbox_gate = gate_by_id(waived_sandbox_summary, 'ecosystem.sandbox-provider')
        assert waived_sandbox_gate['status'] == 'warn', waived_sandbox_gate
        assert waived_sandbox_gate['details']['waived'] is True, waived_sandbox_gate
        waived_report = (workspace / 'build/waived-sandbox-cert' / REPORT_FILE_NAME).read_text(encoding='utf-8')
        waived_encoded = json.dumps(waived_sandbox_summary, sort_keys=True) + waived_report
        for forbidden in ('hunter2', str(workspace)):
            assert forbidden not in waived_encoded, f'structured waiver leaked {forbidden}'
        dashboard_waiver_file_path = workspace / 'docs/release-waivers/dashboard-schema.json'
        write_json(dashboard_waiver_file_path, {'schemaVersion': 1, 'releaseId': 'self-test', 'waivers': [{'id': 'waiver-ecosystem-sandbox-provider-dashboard-schema', 'evidenceId': 'ecosystem.sandbox-provider', 'severity': 'blocker', 'scope': 'release-candidate', 'rationale': 'Release manager accepted the sandbox provider evidence gap.', 'approvedBy': 'release-manager', 'owner': 'release-engineering', 'createdAt': '2026-06-24T00:00:00Z', 'expiresAt': '2099-01-01T00:00:00Z', 'references': ['self-test']}]})
        dashboard_waived_summary, dashboard_waived_exit_code = run_with_previous('dashboard-waiver-schema-cert', app_platform_summary=sandbox_best_effort_path, waiver_files=(dashboard_waiver_file_path,))
        assert dashboard_waived_exit_code == 0, dashboard_waived_summary
        assert dashboard_waived_summary['status'] == 'warn', dashboard_waived_summary
        assert len(dashboard_waived_summary['waiverRecords']) == 1, dashboard_waived_summary
        dashboard_waived_record = dashboard_waived_summary['waiverRecords'][0]
        assert dashboard_waived_record['allowReleaseCandidate'] is True, dashboard_waived_record
        assert dashboard_waived_record['reason'] == 'Release manager accepted the sandbox provider evidence gap.', dashboard_waived_record
        dashboard_waived_gate = gate_by_id(dashboard_waived_summary, 'ecosystem.sandbox-provider')
        assert dashboard_waived_gate['status'] == 'warn', dashboard_waived_gate
        assert dashboard_waived_gate['details']['waived'] is True, dashboard_waived_gate
        malformed_rc_waiver_file_path = workspace / 'docs/release-waivers/nonboolean.json'
        write_json(malformed_rc_waiver_file_path, {'version': 1, 'waivers': [{'id': 'ecosystem.sandbox-provider', 'evidenceId': 'ecosystem.sandbox-provider', 'status': 'approved', 'approvedBy': 'release-manager', 'reason': 'Malformed release-candidate flag.', 'expiresAt': '2099-01-01T00:00:00Z', 'allowReleaseCandidate': 'false'}]})
        malformed_rc_waiver_summary, malformed_rc_waiver_exit_code = run_with_previous('malformed-rc-waiver-cert', app_platform_summary=sandbox_best_effort_path, waiver_files=(malformed_rc_waiver_file_path,))
        assert malformed_rc_waiver_exit_code == 1, malformed_rc_waiver_summary
        assert gate_by_id(malformed_rc_waiver_summary, 'ecosystem.waivers')['status'] == 'fail'
        malformed_sandbox_gate = gate_by_id(malformed_rc_waiver_summary, 'ecosystem.sandbox-provider')
        assert malformed_sandbox_gate['status'] == 'fail', malformed_sandbox_gate
        assert 'waived' not in malformed_sandbox_gate['details'], malformed_sandbox_gate
        malformed_waiver_redaction_file_path = workspace / 'docs/release-waivers/redaction.json'
        write_json(malformed_waiver_redaction_file_path, {'version': 1, 'waivers': [{'id': 'ecosystem.sandbox-provider', 'evidenceId': 'ecosystem.sandbox-provider', 'status': f'token=hunter2 {workspace}/status', 'approvedBy': 'release-manager', 'reason': 'Malformed status and expiry should remain sanitized.', 'expiresAt': f'token=expires-secret {workspace}/expires', 'allowReleaseCandidate': True}]})
        malformed_waiver_redaction_summary, malformed_waiver_redaction_exit_code = run_with_previous('malformed-waiver-redaction-cert', app_platform_summary=sandbox_best_effort_path, waiver_files=(malformed_waiver_redaction_file_path,))
        assert malformed_waiver_redaction_exit_code == 1, malformed_waiver_redaction_summary
        malformed_waiver_redaction_report = (workspace / 'build/malformed-waiver-redaction-cert' / REPORT_FILE_NAME).read_text(encoding='utf-8')
        malformed_waiver_redaction_encoded = json.dumps(malformed_waiver_redaction_summary, sort_keys=True) + malformed_waiver_redaction_report
        for forbidden in ('hunter2', 'expires-secret', str(workspace)):
            assert forbidden not in malformed_waiver_redaction_encoded, f'malformed waiver leaked {forbidden}'
        expired_waiver_file_path = workspace / 'docs/release-waivers/expired.json'
        write_json(expired_waiver_file_path, {'version': 1, 'waivers': [{'id': 'ecosystem.sandbox-provider', 'evidenceId': 'ecosystem.sandbox-provider', 'status': 'approved', 'approvedBy': 'release-manager', 'reason': 'Expired waiver.', 'expiresAt': '2000-01-01T00:00:00Z', 'allowReleaseCandidate': True}]})
        expired_waiver_summary, expired_waiver_exit_code = run_with_previous('expired-waiver-cert', app_platform_summary=sandbox_best_effort_path, waiver_files=(expired_waiver_file_path,))
        assert expired_waiver_exit_code == 1, expired_waiver_summary
        assert gate_by_id(expired_waiver_summary, 'ecosystem.waivers')['status'] == 'fail'
        wrong_mode_extended = interop_evidence('interop.extended', settings.interop_smoke_summary, False, 'extended', workspace, out_dir)
        assert wrong_mode_extended.status == 'warn', wrong_mode_extended
        assert wrong_mode_extended.details['expectedMode'] == 'extended', wrong_mode_extended
        assert wrong_mode_extended.details['mode'] == 'smoke', wrong_mode_extended
        assert wrong_mode_extended.details['modeMatches'] is False, wrong_mode_extended
        missing_extended_flow_path = workspace / 'build/interop-extended-missing-flow/summary.json'
        missing_extended_flow = read_json(settings.interop_extended_summary)
        assert missing_extended_flow is not None
        missing_extended_flow['flows'].pop('persistent_request_replay', None)
        write_json(missing_extended_flow_path, missing_extended_flow)
        missing_extended_flow_item = interop_evidence('interop.extended', missing_extended_flow_path, False, 'extended', workspace, out_dir)
        assert missing_extended_flow_item.status == 'warn', missing_extended_flow_item
        assert 'persistent_request_replay' in missing_extended_flow_item.details['missingRequiredFlows']
        collect_perf_path = workspace / 'build/perf-collect/summary.json'
        collect_perf = read_json(settings.perf_smoke_summary)
        assert collect_perf is not None
        collect_perf['mode'] = 'collect'
        collect_perf['status'] = 'warning'
        write_json(collect_perf_path, collect_perf)
        collect_perf_item = perf_evidence(collect_perf_path, True, workspace, out_dir)
        assert collect_perf_item.status == 'fail', collect_perf_item
        assert collect_perf_item.details['expectedMode'] == 'smoke', collect_perf_item
        assert collect_perf_item.details['mode'] == 'collect', collect_perf_item
        assert collect_perf_item.details['modeMatches'] is False, collect_perf_item
        collect_perf_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/collect-perf-cert').resolve(), perf_smoke_summary=collect_perf_path)
        collect_perf_summary, collect_perf_exit_code = run(collect_perf_settings)
        assert collect_perf_exit_code == 1, collect_perf_summary
        assert collect_perf_summary['status'] == 'fail', collect_perf_summary
        assert collect_perf_summary['releaseCandidatePassed'] is False, collect_perf_summary
        pr_app_summary_path = workspace / 'build/app-platform-pr/summary.json'
        pr_app_summary = read_json(settings.app_platform_summary)
        assert pr_app_summary is not None
        pr_app_summary['mode'] = 'pr'
        pr_app_summary['status'] = 'warn'
        write_json(pr_app_summary_path, pr_app_summary)
        pr_app_items = app_platform_evidence(pr_app_summary_path, workspace, out_dir, 'release-candidate')
        assert all((item.status == 'fail' for item in pr_app_items if item.required_for_release_candidate)), pr_app_items
        assert pr_app_items[0].details['expectedMode'] == 'release-candidate', pr_app_items
        assert pr_app_items[0].details['mode'] == 'pr', pr_app_items
        assert pr_app_items[0].details['modeMatches'] is False, pr_app_items
        pr_app_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/pr-app-cert').resolve(), app_platform_summary=pr_app_summary_path)
        pr_app_cert_summary, pr_app_exit_code = run(pr_app_settings)
        assert pr_app_exit_code == 1, pr_app_cert_summary
        assert pr_app_cert_summary['status'] == 'fail', pr_app_cert_summary
        assert pr_app_cert_summary['releaseCandidatePassed'] is False, pr_app_cert_summary
        missing_update_evidence_path = workspace / 'build/app-platform-missing-update/summary.json'
        missing_update_summary = read_json(settings.app_platform_summary)
        assert missing_update_summary is not None
        missing_update_summary['evidence'] = [item for item in missing_update_summary['evidence'] if item.get('id') not in {'app-update.lifecycle', 'app-update.scheduler', 'app-update.rollback', 'app-update.data-migration-contract'}]
        write_json(missing_update_evidence_path, missing_update_summary)
        missing_update_items = app_platform_evidence(missing_update_evidence_path, workspace, out_dir, 'release-candidate')
        missing_update_by_id = {item.id: item for item in missing_update_items}
        assert missing_update_by_id['app-update.lifecycle'].status == 'missing', missing_update_by_id
        assert missing_update_by_id['app-update.scheduler'].status == 'missing', missing_update_by_id
        assert missing_update_by_id['app-update.rollback'].status == 'missing', missing_update_by_id
        assert missing_update_by_id['app-update.data-migration-contract'].status == 'missing', missing_update_by_id
        missing_update_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/missing-update-cert').resolve(), app_platform_summary=missing_update_evidence_path)
        missing_update_cert_summary, missing_update_exit_code = run(missing_update_settings)
        assert missing_update_exit_code == 1, missing_update_cert_summary
        assert missing_update_cert_summary['status'] == 'fail', missing_update_cert_summary
        assert missing_update_cert_summary['releaseCandidatePassed'] is False, missing_update_cert_summary
        missing_update_row = matrix_row_by_id(workspace / 'build/missing-update-cert', 'app-update')
        assert missing_update_row['status'] == 'fail', missing_update_row
        assert missing_update_row['releaseBlocker'] is True, missing_update_row
        stale_artifact = out_dir / 'artifacts/stale-from-previous-run.txt'
        stale_artifact.write_text('old evidence\n', encoding='utf-8')
        rerun_summary, rerun_exit_code = run(settings)
        assert rerun_exit_code == 0, rerun_summary
        assert not stale_artifact.exists(), stale_artifact
        assert 'stale-from-previous-run.txt' not in json.dumps(rerun_summary, sort_keys=True)
        repo_tmp_path = workspace / 'build/tmp-release-certification/release-certification-summary.json'
        assert scrub_text(str(repo_tmp_path), workspace, out_dir) == '<repo>/build/tmp-release-certification/release-certification-summary.json'
        with tempfile.TemporaryDirectory(prefix='cryptad-cert-symlink-target-') as target_name:
            with tempfile.TemporaryDirectory(prefix='cryptad-cert-symlink-parent-') as link_parent_name:
                symlink_root = Path(link_parent_name) / 'repo-link'
                try:
                    symlink_root.symlink_to(Path(target_name), target_is_directory=True)
                except (NotImplementedError, OSError):
                    symlink_root = None
                if symlink_root is not None:
                    symlink_workspace = symlink_root / 'repo'
                    symlink_out_dir = symlink_workspace / 'build/release-certification'
                    symlink_path = symlink_workspace / 'build/tmp-release-certification/release-certification-summary.json'
                    assert scrub_text(str(symlink_path), symlink_workspace, symlink_out_dir) == '<repo>/build/tmp-release-certification/release-certification-summary.json'
        assert normalize_redacted_separators('<repo>\\build\\tmp-release-certification\\release-certification-summary.json') == '<repo>/build/tmp-release-certification/release-certification-summary.json'
        windows_scrubbed = scrub_text('keys at D:\\release\\signing.pem and \\\\builder\\share\\certs\\catalog.pem', workspace, out_dir)
        assert 'D:\\release' not in windows_scrubbed, windows_scrubbed
        assert '\\\\builder\\share' not in windows_scrubbed, windows_scrubbed
        assert '<path>/signing.pem' in windows_scrubbed, windows_scrubbed
        assert '<path>/catalog.pem' in windows_scrubbed, windows_scrubbed
        file_uri_scrubbed = scrub_text('metadata file:///home/alice/signing/key.pem file:///D:/keys/catalog.pem', workspace, out_dir)
        assert '/home/alice/signing' not in file_uri_scrubbed, file_uri_scrubbed
        assert 'D:/keys' not in file_uri_scrubbed, file_uri_scrubbed
        assert 'file://<path>/key.pem' in file_uri_scrubbed, file_uri_scrubbed
        assert 'file://<path>/catalog.pem' in file_uri_scrubbed, file_uri_scrubbed
        route_scrubbed = scrub_text('/apps/install /apps/cert-smoke/runtime /api/v1/diagnostics /mnt/secrets/signing/key.pem', workspace, out_dir)
        assert '/apps/install' in route_scrubbed, route_scrubbed
        assert '/apps/cert-smoke/runtime' in route_scrubbed, route_scrubbed
        assert '/api/v1/diagnostics' in route_scrubbed, route_scrubbed
        assert '/mnt/secrets/signing/key.pem' not in route_scrubbed, route_scrubbed
        assert '<path>/key.pem' in route_scrubbed, route_scrubbed
        colon_labeled_path = scrub_text('Picked up JAVA_TOOL_OPTIONS: -javaagent:/home/runner/work/_temp/agent.jar workspace:/home/runner/work/cryptad/cryptad/report.json', workspace, out_dir)
        assert '/home/runner/' not in colon_labeled_path, colon_labeled_path
        assert '-javaagent:<path>/agent.jar' in colon_labeled_path, colon_labeled_path
        assert 'workspace:<path>/report.json' in colon_labeled_path, colon_labeled_path
        signing_metadata = sanitize_value({'privateKeyPresent': False, 'privateKeySource': 'missing', 'publicKeyPresent': True, 'publicKeySource': 'environment', 'secretMaterialRedacted': True, 'privateKey': 'actual-secret', 'privateKeyFile': '/mnt/secrets/signing/key.pem', 'token': 'runtime-token', 'path': '/apps/cert-smoke/runtime'}, workspace, out_dir)
        assert signing_metadata['privateKeyPresent'] is False, signing_metadata
        assert signing_metadata['privateKeySource'] == 'missing', signing_metadata
        assert signing_metadata['publicKeyPresent'] is True, signing_metadata
        assert signing_metadata['publicKeySource'] == 'environment', signing_metadata
        assert signing_metadata['secretMaterialRedacted'] is True, signing_metadata
        assert signing_metadata['privateKey'] == '<redacted>', signing_metadata
        assert signing_metadata['privateKeyFile'] == '<redacted>', signing_metadata
        assert signing_metadata['token'] == '<redacted>', signing_metadata
        assert signing_metadata['path'] == '/apps/cert-smoke/runtime', signing_metadata
        vault_metadata = sanitize_value({'capabilities': ['vault.secrets.read', 'vault.secrets.write', 'vault.identities.read', 'vault.identities.create', 'vault.identities.use', 'vault.identities.manage'], 'secretValue': 'stored-secret', 'identityPrivateKey': 'private-identity-key', 'identitySeed': 'identity-seed', 'recoveryPhrase': 'alpha beta gamma', 'mnemonicPhrase': 'delta epsilon zeta', 'accountMnemonic': 'eta theta iota', 'publicIdentityId': 'identity-public-id'}, workspace, out_dir)
        assert vault_metadata['capabilities'][0] == 'vault.secrets.read', vault_metadata
        assert vault_metadata['secretValue'] == '<redacted>', vault_metadata
        assert vault_metadata['identityPrivateKey'] == '<redacted>', vault_metadata
        assert vault_metadata['identitySeed'] == '<redacted>', vault_metadata
        assert vault_metadata['recoveryPhrase'] == '<redacted>', vault_metadata
        assert vault_metadata['mnemonicPhrase'] == '<redacted>', vault_metadata
        assert vault_metadata['accountMnemonic'] == '<redacted>', vault_metadata
        assert vault_metadata['publicIdentityId'] == 'identity-public-id', vault_metadata
        vault_scrubbed = scrub_text('{"identitySeed":"seed-secret","recoveryPhrase":"alpha beta","mnemonicPhrase":"delta epsilon","accountMnemonic":"eta theta","secretValue":"vault-secret"} capability=vault.identities.use', workspace, out_dir)
        for forbidden in ('seed-secret', 'alpha beta', 'delta epsilon', 'eta theta', 'vault-secret'):
            assert forbidden not in vault_scrubbed, vault_scrubbed
        assert 'vault.identities.use' in vault_scrubbed, vault_scrubbed
        signature_scrubbed = scrub_text('signature.value.base64=raw-signature signature.algorithm=Ed25519', workspace, out_dir)
        assert 'raw-signature' not in signature_scrubbed, signature_scrubbed
        assert 'Ed25519' in signature_scrubbed, signature_scrubbed
        body_label_scrubbed = scrub_text('raw trust statement body: signed-trust-document\nraw message body: private-social-body\nrequest body: form-password=secret\nraw feed body: <script>alert(1)</script>', workspace, out_dir)
        for forbidden in ('signed-trust-document', 'private-social-body', 'form-password=secret', '<script>alert(1)</script>'):
            assert forbidden not in body_label_scrubbed, body_label_scrubbed
        assert 'raw trust statement body: <redacted>' in body_label_scrubbed, body_label_scrubbed
        assert 'raw message body: <redacted>' in body_label_scrubbed, body_label_scrubbed
        pem_scrubbed = scrub_text('-----BEGIN OPENSSH PRIVATE KEY-----\nopenssh-private-key-body\n-----END OPENSSH PRIVATE KEY-----\npublic reviewer key id remains', workspace, out_dir)
        for forbidden in ('BEGIN OPENSSH PRIVATE KEY', 'openssh-private-key-body', 'END OPENSSH PRIVATE KEY'):
            assert forbidden not in pem_scrubbed, pem_scrubbed
        assert 'public reviewer key id remains' in pem_scrubbed, pem_scrubbed
        truncated_pem_scrubbed = scrub_text('before\n-----BEGIN OPENSSH PRIVATE KEY-----\ntruncated-openssh-private-key-body\nmore-private-key-body', workspace, out_dir)
        for forbidden in ('BEGIN OPENSSH PRIVATE KEY', 'truncated-openssh-private-key-body', 'more-private-key-body'):
            assert forbidden not in truncated_pem_scrubbed, truncated_pem_scrubbed
        assert 'before' in truncated_pem_scrubbed, truncated_pem_scrubbed
        credential_scrubbed = scrub_text('Authorization: Bearer report-secret\nCookie: session=abc; csrf=def\n{"token":"json-secret","authorization":"Bearer json-secret","password":"pw"} authorization=Bearer inline-secret rawMessageBody=private-social-body rawFetchedBody=private-fetched-body CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64=base64-secret privateKeyBase64=key-secret clientSecret=client-secret api_password=api-secret privateKeyPresent=false', workspace, out_dir)
        for forbidden in ('Bearer report-secret', 'session=abc', 'csrf=def', 'json-secret', '"pw"', 'inline-secret', 'base64-secret', 'key-secret', 'client-secret', 'api-secret', 'private-social-body', 'private-fetched-body'):
            assert forbidden not in credential_scrubbed, credential_scrubbed
        assert 'Authorization: <redacted>' in credential_scrubbed, credential_scrubbed
        assert 'Cookie: <redacted>' in credential_scrubbed, credential_scrubbed
        assert '"token":"<redacted>"' in credential_scrubbed, credential_scrubbed
        assert 'authorization=<redacted>' in credential_scrubbed, credential_scrubbed
        assert 'privateKeyPresent=false' in credential_scrubbed, credential_scrubbed
        external_out_dir = Path(temp_name) / 'external-cert'
        external_settings = dataclasses.replace(settings, out_dir=external_out_dir.resolve())
        external_summary, external_exit_code = run(external_settings)
        assert external_exit_code == 0, external_summary
        assert external_summary['summaryPath'].startswith('<workdir>/'), external_summary
        assert external_summary['reportPath'].startswith('<workdir>/'), external_summary
        assert external_summary['ecosystemMatrixPath'].startswith('<workdir>/'), external_summary
        assert (external_out_dir / SUMMARY_FILE_NAME).is_file(), external_summary
        assert (external_out_dir / ECOSYSTEM_MATRIX_FILE_NAME).is_file(), external_summary
        assert str(external_out_dir) not in json.dumps(external_summary, sort_keys=True), external_summary
        missing_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/missing-cert').resolve(), interop_smoke_summary=workspace / 'build/missing-interop/summary.json')
        missing_summary, missing_exit_code = run(missing_settings)
        assert missing_exit_code == 1, missing_summary
        assert missing_summary['status'] == 'fail', missing_summary
        assert missing_summary['releaseCandidatePassed'] is False, missing_summary
        malformed_path = workspace / 'build/malformed-interop/summary.json'
        malformed_path.parent.mkdir(parents=True, exist_ok=True)
        malformed_path.write_text('{"status": "success"', encoding='utf-8')
        malformed_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/malformed-cert').resolve(), interop_smoke_summary=malformed_path)
        malformed_summary, malformed_exit_code = run(malformed_settings)
        assert malformed_exit_code == 1, malformed_summary
        assert malformed_summary['status'] == 'fail', malformed_summary
        malformed_interop = next((item for item in malformed_summary['evidence'] if item['id'] == 'interop.smoke'))
        assert malformed_interop['status'] == 'missing', malformed_interop
        assert (malformed_settings.out_dir / REPORT_FILE_NAME).is_file(), malformed_summary
        assert not any((artifact.endswith('/interop-smoke-summary.json') for artifact in malformed_summary['copiedArtifacts'])), malformed_summary
        pr_missing_settings = dataclasses.replace(missing_settings, out_dir=(workspace / 'build/pr-missing-cert').resolve(), mode='pr')
        pr_missing_summary, pr_missing_exit_code = run(pr_missing_settings)
        assert pr_missing_exit_code == 0, pr_missing_summary
        assert pr_missing_summary['status'] == 'warn', pr_missing_summary
        assert pr_missing_summary['releaseCandidatePassed'] is False, pr_missing_summary
        assert pr_missing_summary['promotionDecision'] == 'FAIL', pr_missing_summary
        nightly_missing_settings = dataclasses.replace(missing_settings, out_dir=(workspace / 'build/nightly-missing-cert').resolve(), mode='nightly')
        nightly_missing_summary, nightly_missing_exit_code = run(nightly_missing_settings)
        assert nightly_missing_exit_code == 0, nightly_missing_summary
        assert nightly_missing_summary['status'] == 'warn', nightly_missing_summary
        assert nightly_missing_summary['releaseCandidatePassed'] is False, nightly_missing_summary
        assert nightly_missing_summary['promotionDecision'] == 'FAIL', nightly_missing_summary
        failing_perf = read_json(settings.perf_smoke_summary)
        assert failing_perf is not None
        failing_perf['status'] = 'failure'
        failing_perf_path = workspace / 'build/failing-perf/summary.json'
        write_json(failing_perf_path, failing_perf)
        nightly_failing_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/nightly-failing-cert').resolve(), mode='nightly', perf_smoke_summary=failing_perf_path)
        nightly_failing_summary, nightly_failing_exit_code = run(nightly_failing_settings)
        assert nightly_failing_exit_code == 1, nightly_failing_summary
        assert nightly_failing_summary['status'] == 'fail', nightly_failing_summary
        assert nightly_failing_summary['releaseCandidatePassed'] is False, nightly_failing_summary
        waived_settings = dataclasses.replace(missing_settings, out_dir=(workspace / 'build/waived-cert').resolve(), waivers={'interop.smoke': 'Release manager accepted CI artifact from upstream run.'})
        waived_summary, waived_exit_code = run(waived_settings)
        assert waived_exit_code == 0, waived_summary
        assert waived_summary['status'] == 'warn', waived_summary
        assert waived_summary['waivers'] == {'interop.smoke': 'Release manager accepted CI artifact from upstream run.'}, waived_summary
        assert waived_summary['waiverRecords'][0]['source'] == 'cli', waived_summary
        waived_item = next((item for item in waived_summary['evidence'] if item['id'] == 'interop.smoke'))
        assert waived_item['details']['waived'] is True
        sensitive_reason = f'token=hunter2 USK@private/insert /mnt/secrets/signing/key.pem {workspace}/secret'
        sensitive_waived_settings = dataclasses.replace(missing_settings, out_dir=(workspace / 'build/sensitive-waived-cert').resolve(), waivers={'interop.smoke': sensitive_reason})
        sensitive_waived_summary, sensitive_waived_exit_code = run(sensitive_waived_settings)
        assert sensitive_waived_exit_code == 0, sensitive_waived_summary
        sensitive_report = (sensitive_waived_settings.out_dir / REPORT_FILE_NAME).read_text(encoding='utf-8')
        sensitive_matrix_report = (sensitive_waived_settings.out_dir / ECOSYSTEM_MATRIX_REPORT_FILE_NAME).read_text(encoding='utf-8')
        sensitive_matrix = read_json(sensitive_waived_settings.out_dir / ECOSYSTEM_MATRIX_FILE_NAME)
        sensitive_encoded = json.dumps(sensitive_waived_summary, sort_keys=True) + json.dumps(sensitive_matrix, sort_keys=True) + sensitive_report + sensitive_matrix_report
        for forbidden in ('hunter2', 'USK@private', '/mnt/secrets/signing/key.pem', str(workspace)):
            assert forbidden not in sensitive_encoded, f'waiver reason leaked {forbidden}'

        def stable_self_test_passing_domains() -> list[dict[str, Any]]:
            return [{'id': domain_id, 'status': 'pass', 'summary': 'Synthetic Stable domain row passed.', 'evidenceIds': [], 'blockers': [], 'warnings': [], 'allowedLimitations': []} for domain_id in STABLE_1_0_READINESS_DOMAIN_IDS]

        def stable_self_test_domains_with(domain_id: str, **updates: Any) -> list[dict[str, Any]]:
            domains = stable_self_test_passing_domains()
            for domain in domains:
                if domain.get('id') == domain_id:
                    domain.update(updates)
                    return domains
            raise AssertionError(f'Stable self-test domain is missing {domain_id}')

        def stable_self_test_summary(release_id: str='cryptad-production-beta-self-test', *, omitted_evidence_ids: set[str] | None=None) -> dict[str, Any]:
            omitted = omitted_evidence_ids or set()
            return {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': release_id, 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS if evidence_id not in omitted]}
        for tool_suffix, tool_value, expected_error in (('missing', None, 'tool is missing; expected stable-1.0-readiness'), ('wrong', 'other-stable-tool', 'tool must be stable-1.0-readiness')):
            stable_tool_summary = workspace / f'build/stable-readiness-{tool_suffix}-tool.json'
            stable_tool_value = stable_self_test_summary()
            if tool_value is None:
                stable_tool_value.pop('tool', None)
            else:
                stable_tool_value['tool'] = tool_value
            write_json(stable_tool_summary, stable_tool_value)
            stable_tool_items = stable_readiness_evidence(stable_tool_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
            stable_tool_gate = next((item for item in stable_tool_items if item.id == 'stable-1.0.readiness-gate'))
            assert stable_tool_gate.status == 'fail', stable_tool_gate
            assert stable_tool_gate.details['validationErrors'] == [expected_error], stable_tool_gate
        stable_warning_summary = workspace / 'build/stable-readiness-warning.json'
        stable_warning_value = stable_self_test_summary()
        stable_warning_record = {'id': 'stable-1.0.synthetic-warning', 'evidenceId': 'stable-1.0.support-feedback-readiness', 'severity': 'warning', 'summary': 'Synthetic Stable warning remains open for release-manager review.'}
        stable_warning_value['warningCount'] = 1
        stable_warning_value['warnings'] = [stable_warning_record]
        for domain in stable_warning_value['domains']:
            if isinstance(domain, dict) and domain.get('id') == 'support-feedback-readiness':
                domain['status'] = 'warn'
                domain['warnings'] = [stable_warning_record]
                break
        else:
            raise AssertionError('Stable self-test summary is missing support-feedback-readiness')
        write_json(stable_warning_summary, stable_warning_value)
        stable_warning_items = stable_readiness_evidence(stable_warning_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_warning_gate = next((item for item in stable_warning_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_warning_gate.status == 'warn', stable_warning_gate
        assert stable_warning_gate.details['warningRecordCount'] == 1, stable_warning_gate
        assert stable_warning_gate.details['domainWarningRecordCount'] == 1, stable_warning_gate
        stable_warning_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-warning-cert').resolve(), stable_readiness_summary=stable_warning_summary, stable_readiness_required=True)
        stable_warning_cert, stable_warning_exit_code = run(stable_warning_settings)
        assert stable_warning_exit_code == 0, stable_warning_cert
        stable_warning_row = matrix_row_by_id(stable_warning_settings.out_dir, 'stable-1-0-readiness')
        assert stable_warning_row['status'] == 'warn', stable_warning_row
        assert stable_warning_row['releaseBlocker'] is False, stable_warning_row
        stable_summary_status_only_warning_path = workspace / 'build/stable-readiness-status-only-summary-warning.json'
        stable_summary_status_only_warning_value = stable_self_test_summary()
        stable_summary_status_only_warning_value['status'] = 'warn'
        write_json(stable_summary_status_only_warning_path, stable_summary_status_only_warning_value)
        stable_summary_status_only_warning_items = stable_readiness_evidence(stable_summary_status_only_warning_path, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_summary_status_only_warning_gate = next((item for item in stable_summary_status_only_warning_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_summary_status_only_warning_gate.status == 'fail', stable_summary_status_only_warning_gate
        assert stable_summary_status_only_warning_gate.details['validationErrors'] == ['status is warn but no warnings or allowed limitations are reported'], stable_summary_status_only_warning_gate.details
        stable_summary_status_only_warning_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-status-only-summary-warning-cert').resolve(), stable_readiness_summary=stable_summary_status_only_warning_path, stable_readiness_required=True)
        stable_summary_status_only_warning_cert, stable_summary_status_only_warning_exit_code = run(stable_summary_status_only_warning_settings)
        assert stable_summary_status_only_warning_exit_code == 1, stable_summary_status_only_warning_cert
        stable_summary_status_only_warning_row = matrix_row_by_id(stable_summary_status_only_warning_settings.out_dir, 'stable-1-0-readiness')
        assert stable_summary_status_only_warning_row['status'] == 'fail', stable_summary_status_only_warning_row
        assert stable_summary_status_only_warning_row['releaseBlocker'] is True, stable_summary_status_only_warning_row
        stable_status_only_warning_summary = workspace / 'build/stable-readiness-status-only-domain-warning.json'
        stable_status_only_warning_value = stable_self_test_summary()
        for domain in stable_status_only_warning_value['domains']:
            if isinstance(domain, dict) and domain.get('id') == 'support-feedback-readiness':
                domain['status'] = 'warn'
                domain['summary'] = 'Synthetic Stable domain reports an unsurfaced warning.'
                break
        else:
            raise AssertionError('Stable self-test summary is missing support-feedback-readiness')
        write_json(stable_status_only_warning_summary, stable_status_only_warning_value)
        stable_status_only_warning_items = stable_readiness_evidence(stable_status_only_warning_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_status_only_warning_gate = next((item for item in stable_status_only_warning_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_status_only_warning_gate.status == 'fail', stable_status_only_warning_gate
        assert 'domain support-feedback-readiness status is warn but contains no warnings or allowed limitations' in stable_status_only_warning_gate.details['validationErrors'], stable_status_only_warning_gate
        stable_status_only_warning_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-status-only-domain-warning-cert').resolve(), stable_readiness_summary=stable_status_only_warning_summary, stable_readiness_required=True)
        stable_status_only_warning_cert, stable_status_only_warning_exit_code = run(stable_status_only_warning_settings)
        assert stable_status_only_warning_exit_code == 1, stable_status_only_warning_cert
        stable_status_only_warning_row = matrix_row_by_id(stable_status_only_warning_settings.out_dir, 'stable-1-0-readiness')
        assert stable_status_only_warning_row['status'] == 'fail', stable_status_only_warning_row
        assert stable_status_only_warning_row['releaseBlocker'] is True, stable_status_only_warning_row
        stable_warning_mismatch_summary = workspace / 'build/stable-readiness-warning-mismatch.json'
        stable_warning_mismatch_value = stable_self_test_summary()
        stable_warning_mismatch_value['warningCount'] = 1
        write_json(stable_warning_mismatch_summary, stable_warning_mismatch_value)
        stable_warning_mismatch_items = stable_readiness_evidence(stable_warning_mismatch_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_warning_mismatch_gate = next((item for item in stable_warning_mismatch_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_warning_mismatch_gate.status == 'fail', stable_warning_mismatch_gate
        assert 'warningCount is 1 but warnings contains 0 record(s)' in stable_warning_mismatch_gate.details['validationErrors'], stable_warning_mismatch_gate
        assert 'warningCount is 1 but domains contain 0 warning record(s)' in stable_warning_mismatch_gate.details['validationErrors'], stable_warning_mismatch_gate
        for failing_synthetic_evidence_id in ('stable-1.0.readiness-gate', 'stable-1.0.redaction'):
            stable_failed_reported_row_summary = stable_self_test_summary()
            for entry in stable_failed_reported_row_summary['evidence']:
                if isinstance(entry, dict) and entry.get('id') == failing_synthetic_evidence_id:
                    entry['status'] = 'fail'
                    entry['summary'] = f'{failing_synthetic_evidence_id} failed in the reported evidence row.'
                    break
            else:
                raise AssertionError(f'Stable self-test summary is missing {failing_synthetic_evidence_id}')
            stable_failed_reported_row_path = workspace / 'build' / f"stable-readiness-reported-{failing_synthetic_evidence_id.replace('.', '-')}-fail.json"
            write_json(stable_failed_reported_row_path, stable_failed_reported_row_summary)
            stable_failed_reported_row_items = stable_readiness_evidence(stable_failed_reported_row_path, True, workspace, out_dir, 'cryptad-production-beta-self-test')
            stable_failed_reported_row_item = next((item for item in stable_failed_reported_row_items if item.id == failing_synthetic_evidence_id))
            assert stable_failed_reported_row_item.status == 'fail', stable_failed_reported_row_item
            assert stable_failed_reported_row_item.details['reportedStableReadinessEvidenceStatus'] == 'fail', stable_failed_reported_row_item.details
        nested_security_drill_release_id = EvidenceItem('production-security.response-runbook', 'pass', True, 'Synthetic security response runbook evidence passed.', 'self-test', {'securityDrills': {'details': {'releaseId': 'cryptad-cert-release-candidate'}}})
        settings_without_stable_candidate = dataclasses.replace(settings, metadata={'selfTest': 'true'})
        assert stable_readiness_expected_release_id(settings_without_stable_candidate, [nested_security_drill_release_id]) == '', 'nested security drill releaseId must not bind Stable readiness'
        top_level_security_release_id = dataclasses.replace(nested_security_drill_release_id, details={**nested_security_drill_release_id.details, 'candidateReleaseId': 'cryptad-beta-explicit'})
        assert stable_readiness_expected_release_id(settings_without_stable_candidate, [top_level_security_release_id]) == '', 'production-security evidence releaseId must not implicitly bind Stable readiness'
        metadata_bound_settings = dataclasses.replace(settings_without_stable_candidate, metadata={**settings_without_stable_candidate.metadata, 'candidateReleaseId': 'cryptad-beta-metadata'})
        assert stable_readiness_expected_release_id(metadata_bound_settings, [nested_security_drill_release_id]) == 'cryptad-beta-metadata'
        stable_missing_candidate_id_summary = workspace / 'build/stable-readiness-missing-candidate-id.json'
        write_json(stable_missing_candidate_id_summary, stable_self_test_summary('cryptad-beta-from-production'))
        stable_missing_candidate_id_settings = dataclasses.replace(settings_without_stable_candidate, out_dir=(workspace / 'build/stable-missing-candidate-id-cert').resolve(), stable_readiness_summary=stable_missing_candidate_id_summary, stable_readiness_required=True)
        stable_missing_candidate_id_cert, stable_missing_candidate_id_exit_code = run(stable_missing_candidate_id_settings)
        assert stable_missing_candidate_id_exit_code == 1, stable_missing_candidate_id_cert
        stable_missing_candidate_id_row = matrix_row_by_id(stable_missing_candidate_id_settings.out_dir, 'stable-1-0-readiness')
        assert stable_missing_candidate_id_row['status'] == 'fail', stable_missing_candidate_id_row
        assert stable_missing_candidate_id_row['releaseBlocker'] is True, stable_missing_candidate_id_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_missing_candidate_id_row['issueIds'], stable_missing_candidate_id_row
        stable_missing_candidate_id_gate = next((item for item in stable_missing_candidate_id_cert['evidence'] if item['id'] == 'stable-1.0.readiness-gate'))
        assert stable_missing_candidate_id_gate['details']['validationErrors'] == ['candidate releaseId metadata is required when Stable readiness is required'], stable_missing_candidate_id_gate
        stable_metadata_bound_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-metadata-bound-cert').resolve(), metadata={**settings.metadata, 'candidateReleaseId': 'cryptad-beta-from-production'}, stable_readiness_summary=stable_missing_candidate_id_summary, stable_readiness_required=True)
        stable_metadata_bound_cert, stable_metadata_bound_exit_code = run(stable_metadata_bound_settings)
        assert stable_metadata_bound_exit_code == 0, stable_metadata_bound_cert
        stable_metadata_bound_row = matrix_row_by_id(stable_metadata_bound_settings.out_dir, 'stable-1-0-readiness')
        assert stable_metadata_bound_row['status'] == 'pass', stable_metadata_bound_row
        assert stable_metadata_bound_row['releaseBlocker'] is False, stable_metadata_bound_row
        stable_missing_summary_waived_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-missing-summary-waived-cert').resolve(), stable_readiness_summary=None, stable_readiness_required=True, waivers={'stable-1-0-readiness': 'Attempted row waiver for missing Stable readiness.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix waiver for missing Stable readiness.'})
        stable_missing_summary_waived_cert, stable_missing_summary_waived_exit_code = run(stable_missing_summary_waived_settings)
        assert stable_missing_summary_waived_exit_code == 1, stable_missing_summary_waived_cert
        stable_missing_summary_waived_row = matrix_row_by_id(stable_missing_summary_waived_settings.out_dir, 'stable-1-0-readiness')
        assert stable_missing_summary_waived_row['status'] == 'fail', stable_missing_summary_waived_row
        assert stable_missing_summary_waived_row['releaseBlocker'] is True, stable_missing_summary_waived_row
        assert stable_missing_summary_waived_row.get('waiverIds') == [], stable_missing_summary_waived_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_missing_summary_waived_row['issueIds'], stable_missing_summary_waived_row
        assert stable_missing_summary_waived_row['details']['unwaivableIssueIds'] == ['matrix.stable-readiness.redaction-failed'], stable_missing_summary_waived_row
        assert stable_missing_summary_waived_row['details']['unwaivableRedactionEvidenceIds'] == ['stable-1.0.redaction'], stable_missing_summary_waived_row

        def assert_required_stable_mode_failed(cert: dict[str, Any], exit_code: int, case_settings: Settings) -> None:
            assert exit_code == 1, cert
            assert cert['status'] == 'fail', cert
            assert cert['promotionDecision'] == 'FAIL', cert
            assert cert['releaseCandidatePassed'] is False, cert
            assert cert['ecosystemMatrixStatus'] == 'fail', cert
            stable_row = matrix_row_by_id(case_settings.out_dir, STABLE_1_0_READINESS_MATRIX_ROW_ID)
            assert stable_row['status'] == 'fail', stable_row
            assert stable_row['releaseBlocker'] is True, stable_row
        for stable_required_mode in ('pr', 'nightly'):
            stable_required_missing_settings = dataclasses.replace(settings, out_dir=(workspace / f'build/stable-required-missing-{stable_required_mode}-cert').resolve(), mode=stable_required_mode, stable_readiness_summary=None, stable_readiness_required=True)
            stable_required_missing_cert, stable_required_missing_exit_code = run(stable_required_missing_settings)
            assert_required_stable_mode_failed(stable_required_missing_cert, stable_required_missing_exit_code, stable_required_missing_settings)
        stable_required_not_ready_summary = workspace / 'build/stable-readiness-required-not-ready.json'
        stable_required_not_ready_value = stable_self_test_summary()
        stable_required_not_ready_value.update({'status': 'fail', 'decision': 'not-ready', 'stableReady': False, 'blockerCount': 1, 'blockers': [{'id': 'stable-required-self-test-blocker', 'evidenceId': 'stable-1.0.readiness-gate', 'summary': 'Synthetic Stable readiness blocker.'}]})
        write_json(stable_required_not_ready_summary, stable_required_not_ready_value)
        for stable_required_mode in ('pr', 'nightly'):
            stable_required_not_ready_settings = dataclasses.replace(settings, out_dir=(workspace / f'build/stable-required-not-ready-{stable_required_mode}-cert').resolve(), mode=stable_required_mode, stable_readiness_summary=stable_required_not_ready_summary, stable_readiness_required=True)
            stable_required_not_ready_cert, stable_required_not_ready_exit_code = run(stable_required_not_ready_settings)
            assert_required_stable_mode_failed(stable_required_not_ready_cert, stable_required_not_ready_exit_code, stable_required_not_ready_settings)
        stable_release_mismatch_summary = workspace / 'build/stable-readiness-release-mismatch.json'
        write_json(stable_release_mismatch_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-beta-old', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_release_mismatch_items = stable_readiness_evidence(stable_release_mismatch_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_release_mismatch_gate = next((item for item in stable_release_mismatch_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_release_mismatch_gate.status == 'fail', stable_release_mismatch_gate
        assert stable_release_mismatch_gate.details['validationErrors'] == ['releaseId must match candidate cryptad-production-beta-self-test; summary releaseId is cryptad-beta-old'], stable_release_mismatch_gate.details
        stable_release_mismatch_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-release-mismatch-cert').resolve(), metadata={**settings.metadata, 'candidateReleaseId': 'cryptad-production-beta-self-test'}, stable_readiness_summary=stable_release_mismatch_summary, stable_readiness_required=True)
        stable_release_mismatch_cert, stable_release_mismatch_exit_code = run(stable_release_mismatch_settings)
        assert stable_release_mismatch_exit_code == 1, stable_release_mismatch_cert
        stable_release_mismatch_row = matrix_row_by_id(stable_release_mismatch_settings.out_dir, 'stable-1-0-readiness')
        assert stable_release_mismatch_row['status'] == 'fail', stable_release_mismatch_row
        assert stable_release_mismatch_row['releaseBlocker'] is True, stable_release_mismatch_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_release_mismatch_row['issueIds'], stable_release_mismatch_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_release_mismatch_row['issueIds'], stable_release_mismatch_row
        stable_missing_domains_summary = workspace / 'build/stable-readiness-missing-domains.json'
        write_json(stable_missing_domains_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_missing_domains_items = stable_readiness_evidence(stable_missing_domains_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_missing_domains_gate = next((item for item in stable_missing_domains_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_missing_domains_gate.status == 'fail', stable_missing_domains_gate
        assert stable_missing_domains_gate.details['validationErrors'] == ['domains must be a non-empty list'], stable_missing_domains_gate.details
        stable_missing_domains_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-missing-domains-cert').resolve(), stable_readiness_summary=stable_missing_domains_summary, stable_readiness_required=True)
        stable_missing_domains_cert, stable_missing_domains_exit_code = run(stable_missing_domains_settings)
        assert stable_missing_domains_exit_code == 1, stable_missing_domains_cert
        stable_missing_domains_row = matrix_row_by_id(stable_missing_domains_settings.out_dir, 'stable-1-0-readiness')
        assert stable_missing_domains_row['status'] == 'fail', stable_missing_domains_row
        assert stable_missing_domains_row['releaseBlocker'] is True, stable_missing_domains_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_missing_domains_row['issueIds'], stable_missing_domains_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_missing_domains_row['issueIds'], stable_missing_domains_row
        stable_truncated_domains_summary = workspace / 'build/stable-readiness-truncated-domains.json'
        stable_truncated_domains_value = stable_self_test_summary()
        stable_truncated_domains_value['domains'] = [{'id': 'stub-domain', 'status': 'pass', 'summary': 'Synthetic truncated Stable domain row.', 'evidenceIds': [], 'blockers': [], 'warnings': [], 'allowedLimitations': []}]
        write_json(stable_truncated_domains_summary, stable_truncated_domains_value)
        stable_truncated_domains_items = stable_readiness_evidence(stable_truncated_domains_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_truncated_domains_gate = next((item for item in stable_truncated_domains_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_truncated_domains_gate.status == 'fail', stable_truncated_domains_gate
        assert any((error.startswith('domains are missing required IDs:') for error in stable_truncated_domains_gate.details['validationErrors'])), stable_truncated_domains_gate.details
        stable_truncated_domains_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-truncated-domains-cert').resolve(), stable_readiness_summary=stable_truncated_domains_summary, stable_readiness_required=True)
        stable_truncated_domains_cert, stable_truncated_domains_exit_code = run(stable_truncated_domains_settings)
        assert stable_truncated_domains_exit_code == 1, stable_truncated_domains_cert
        stable_truncated_domains_row = matrix_row_by_id(stable_truncated_domains_settings.out_dir, 'stable-1-0-readiness')
        assert stable_truncated_domains_row['status'] == 'fail', stable_truncated_domains_row
        assert stable_truncated_domains_row['releaseBlocker'] is True, stable_truncated_domains_row
        stable_failed_domain_summary = workspace / 'build/stable-readiness-failed-domain.json'
        write_json(stable_failed_domain_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_domains_with('production-beta-state', status='fail', summary='Synthetic failed Stable domain row.'), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_failed_domain_items = stable_readiness_evidence(stable_failed_domain_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_failed_domain_gate = next((item for item in stable_failed_domain_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_failed_domain_gate.status == 'fail', stable_failed_domain_gate
        assert stable_failed_domain_gate.details['validationErrors'] == ['domain production-beta-state status is fail'], stable_failed_domain_gate.details
        stable_malformed_allowed_domain_summary = workspace / 'build/stable-readiness-malformed-domain-allowed-limitation.json'
        write_json(stable_malformed_allowed_domain_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_domains_with('production-beta-state', summary='Synthetic passed Stable domain row with malformed allowed limitation.', allowedLimitations=[1]), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_malformed_allowed_domain_items = stable_readiness_evidence(stable_malformed_allowed_domain_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_malformed_allowed_domain_gate = next((item for item in stable_malformed_allowed_domain_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_malformed_allowed_domain_gate.status == 'fail', stable_malformed_allowed_domain_gate
        assert stable_malformed_allowed_domain_gate.details['validationErrors'] == ['domain production-beta-state allowedLimitations[0] must be an object'], stable_malformed_allowed_domain_gate.details
        stable_malformed_allowed_domain_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-malformed-domain-allowed-limitation-cert').resolve(), stable_readiness_summary=stable_malformed_allowed_domain_summary, stable_readiness_required=True)
        stable_malformed_allowed_domain_cert, stable_malformed_allowed_domain_exit_code = run(stable_malformed_allowed_domain_settings)
        assert stable_malformed_allowed_domain_exit_code == 1, stable_malformed_allowed_domain_cert
        stable_malformed_allowed_domain_row = matrix_row_by_id(stable_malformed_allowed_domain_settings.out_dir, 'stable-1-0-readiness')
        assert stable_malformed_allowed_domain_row['status'] == 'fail', stable_malformed_allowed_domain_row
        assert stable_malformed_allowed_domain_row['releaseBlocker'] is True, stable_malformed_allowed_domain_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_malformed_allowed_domain_row['issueIds'], stable_malformed_allowed_domain_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_malformed_allowed_domain_row['issueIds'], stable_malformed_allowed_domain_row
        hidden_allowed_limitation = {'id': 'stable-1.0.self-test-hidden-allowed-limitation', 'title': 'Hidden self-test allowed Stable limitation', 'category': 'ui-polish-accessibility-warning', 'classification': 'allowed-for-stable-1.0', 'status': 'open', 'summary': 'Synthetic domain-scoped Stable limitation.', 'evidenceIds': ['stable-1.0.known-limitations'], 'boundedBy': 'Self-test release manager bound for a non-blocking Stable limitation.'}
        hidden_allowed_domain_summary = {'domains': stable_self_test_domains_with('known-limitations', status='warn', allowedLimitations=[hidden_allowed_limitation]), 'allowedLimitations': []}
        hidden_allowed_domain_errors = stable_readiness_domain_errors(hidden_allowed_domain_summary)
        assert hidden_allowed_domain_errors == ['domain known-limitations allowedLimitations[0] is not present in top-level allowedLimitations'], hidden_allowed_domain_errors
        passing_domain_with_limitation_summary = {'domains': stable_self_test_domains_with('known-limitations', status='pass', allowedLimitations=[hidden_allowed_limitation]), 'allowedLimitations': [hidden_allowed_limitation]}
        passing_domain_with_limitation_errors = stable_readiness_domain_errors(passing_domain_with_limitation_summary)
        assert passing_domain_with_limitation_errors == ['domain known-limitations status is pass but contains 1 allowed limitation(s)'], passing_domain_with_limitation_errors
        stable_domain_blocker_summary = workspace / 'build/stable-readiness-domain-blocker.json'
        write_json(stable_domain_blocker_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_domains_with('production-beta-state', summary='Synthetic Stable domain row with hidden blocker.', blockers=[{'id': 'stable-self-test-domain-blocker', 'evidenceId': 'stable-1.0.production-beta-state', 'summary': 'Synthetic Stable domain blocker.'}]), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_domain_blocker_items = stable_readiness_evidence(stable_domain_blocker_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_domain_blocker_gate = next((item for item in stable_domain_blocker_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_domain_blocker_gate.status == 'fail', stable_domain_blocker_gate
        assert stable_domain_blocker_gate.details['validationErrors'] == ['domain production-beta-state contains 1 blocker(s)'], stable_domain_blocker_gate.details
        stable_domain_blocker_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-domain-blocker-cert').resolve(), stable_readiness_summary=stable_domain_blocker_summary, stable_readiness_required=True)
        stable_domain_blocker_cert, stable_domain_blocker_exit_code = run(stable_domain_blocker_settings)
        assert stable_domain_blocker_exit_code == 1, stable_domain_blocker_cert
        stable_domain_blocker_row = matrix_row_by_id(stable_domain_blocker_settings.out_dir, 'stable-1-0-readiness')
        assert stable_domain_blocker_row['status'] == 'fail', stable_domain_blocker_row
        assert stable_domain_blocker_row['releaseBlocker'] is True, stable_domain_blocker_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_domain_blocker_row['issueIds'], stable_domain_blocker_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_domain_blocker_row['issueIds'], stable_domain_blocker_row
        stable_missing_redaction_summary = workspace / 'build/stable-readiness-missing-redaction.json'
        write_json(stable_missing_redaction_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': []})
        stable_items = stable_readiness_evidence(stable_missing_redaction_summary, True, workspace, out_dir)
        stable_statuses = {item.id: item.status for item in stable_items}
        assert stable_statuses['stable-1.0.readiness-gate'] == 'fail', stable_statuses
        assert stable_statuses['stable-1.0.redaction'] == 'fail', stable_statuses
        stable_redaction_waived_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-redaction-waived-cert').resolve(), stable_readiness_summary=stable_missing_redaction_summary, stable_readiness_required=True, waivers={'stable-1-0-readiness': 'Attempted row waiver for Stable redaction failure.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix issue waiver for Stable redaction failure.'})
        stable_redaction_waived_summary, stable_redaction_waived_exit_code = run(stable_redaction_waived_settings)
        assert stable_redaction_waived_exit_code == 1, stable_redaction_waived_summary
        stable_redaction_waived_row = matrix_row_by_id(stable_redaction_waived_settings.out_dir, 'stable-1-0-readiness')
        assert stable_redaction_waived_row['status'] == 'fail', stable_redaction_waived_row
        assert stable_redaction_waived_row['releaseBlocker'] is True, stable_redaction_waived_row
        assert stable_redaction_waived_row.get('waiverIds') == [], stable_redaction_waived_row
        assert stable_redaction_waived_row['details']['unwaivableRedactionEvidenceIds'] == ['stable-1.0.redaction'], stable_redaction_waived_row
        assert stable_redaction_waived_row['details']['unwaivableIssueIds'] == ['matrix.stable-readiness.redaction-failed'], stable_redaction_waived_row
        stable_redaction_warn_summary = workspace / 'build/stable-readiness-redaction-warn.json'
        stable_redaction_warn_value = stable_self_test_summary()
        for entry in stable_redaction_warn_value['evidence']:
            if isinstance(entry, dict) and entry.get('id') == 'stable-1.0.redaction':
                entry['status'] = 'warn'
                entry['summary'] = 'Synthetic Stable redaction warning.'
                break
        else:
            raise AssertionError('Stable self-test summary is missing stable-1.0.redaction')
        write_json(stable_redaction_warn_summary, stable_redaction_warn_value)
        stable_redaction_warn_items = stable_readiness_evidence(stable_redaction_warn_summary, True, workspace, out_dir, 'cryptad-production-beta-self-test')
        stable_redaction_warn_statuses = {item.id: item.status for item in stable_redaction_warn_items}
        assert stable_redaction_warn_statuses['stable-1.0.redaction'] == 'warn', stable_redaction_warn_statuses
        stable_redaction_warn_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-redaction-warn-cert').resolve(), stable_readiness_summary=stable_redaction_warn_summary, stable_readiness_required=True)
        stable_redaction_warn_cert, stable_redaction_warn_exit_code = run(stable_redaction_warn_settings)
        assert stable_redaction_warn_exit_code == 1, stable_redaction_warn_cert
        stable_redaction_warn_row = matrix_row_by_id(stable_redaction_warn_settings.out_dir, 'stable-1-0-readiness')
        assert stable_redaction_warn_row['status'] == 'fail', stable_redaction_warn_row
        assert stable_redaction_warn_row['releaseBlocker'] is True, stable_redaction_warn_row
        assert stable_redaction_warn_row['details']['unwaivableRedactionEvidenceIds'] == ['stable-1.0.redaction'], stable_redaction_warn_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_redaction_warn_row['issueIds'], stable_redaction_warn_row
        stable_redaction_count_summary = workspace / 'build/stable-readiness-redaction-count.json'
        write_json(stable_redaction_count_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findingCount': 1}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_redaction_count_items = stable_readiness_evidence(stable_redaction_count_summary, True, workspace, out_dir)
        stable_redaction_count_statuses = {item.id: item.status for item in stable_redaction_count_items}
        assert stable_redaction_count_statuses['stable-1.0.readiness-gate'] == 'fail', stable_redaction_count_statuses
        assert stable_redaction_count_statuses['stable-1.0.redaction'] == 'fail', stable_redaction_count_statuses
        stable_redaction_count_redaction_item = next((item for item in stable_redaction_count_items if item.id == 'stable-1.0.redaction'))
        assert evidence_item_has_unwaivable_redaction_findings(stable_redaction_count_redaction_item), stable_redaction_count_redaction_item
        assert stable_redaction_count_redaction_item.details['redaction']['findingCount'] == 1, stable_redaction_count_redaction_item
        stable_redaction_count_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-redaction-count-cert').resolve(), stable_readiness_summary=stable_redaction_count_summary, stable_readiness_required=True, waivers={'stable-1.0.redaction': 'Attempted evidence waiver for Stable redaction finding count.', 'stable-1-0-readiness': 'Attempted row waiver for Stable redaction finding count.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix waiver for Stable redaction finding count.'})
        stable_redaction_count_cert, stable_redaction_count_exit_code = run(stable_redaction_count_settings)
        assert stable_redaction_count_exit_code == 1, stable_redaction_count_cert
        stable_redaction_count_row = matrix_row_by_id(stable_redaction_count_settings.out_dir, 'stable-1-0-readiness')
        assert stable_redaction_count_row['status'] == 'fail', stable_redaction_count_row
        assert stable_redaction_count_row['releaseBlocker'] is True, stable_redaction_count_row
        assert stable_redaction_count_row.get('waiverIds') == [], stable_redaction_count_row
        assert stable_redaction_count_row['details']['unwaivableRedactionEvidenceIds'] == ['stable-1.0.redaction'], stable_redaction_count_row
        assert 'evidence.stable-1.0.redaction' in stable_redaction_count_row['issueIds'], stable_redaction_count_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_redaction_count_row['issueIds'], stable_redaction_count_row
        for critical_count_value, critical_count_suffix in ((1, 'critical-count'), (0.5, 'fractional-critical-count')):
            stable_redaction_critical_count_summary = workspace / f'build/stable-readiness-redaction-{critical_count_suffix}.json'
            stable_redaction_critical_count_value = read_json(stable_redaction_count_summary) or {}
            stable_redaction_critical_count_value['redaction'] = {'status': 'pass', 'findings': [], 'findingCount': 0, 'criticalFindingCount': critical_count_value}
            write_json(stable_redaction_critical_count_summary, stable_redaction_critical_count_value)
            stable_redaction_critical_count_items = stable_readiness_evidence(stable_redaction_critical_count_summary, True, workspace, out_dir)
            stable_redaction_critical_count_statuses = {item.id: item.status for item in stable_redaction_critical_count_items}
            assert stable_redaction_critical_count_statuses['stable-1.0.readiness-gate'] == 'fail', stable_redaction_critical_count_statuses
            assert stable_redaction_critical_count_statuses['stable-1.0.redaction'] == 'fail', stable_redaction_critical_count_statuses
            stable_redaction_critical_count_redaction_item = next((item for item in stable_redaction_critical_count_items if item.id == 'stable-1.0.redaction'))
            assert evidence_item_has_unwaivable_redaction_findings(stable_redaction_critical_count_redaction_item), stable_redaction_critical_count_redaction_item
            assert stable_redaction_critical_count_redaction_item.details['redaction']['criticalFindingCount'] == critical_count_value, stable_redaction_critical_count_redaction_item
            stable_redaction_critical_count_settings = dataclasses.replace(settings, out_dir=(workspace / f'build/stable-redaction-{critical_count_suffix}-cert').resolve(), stable_readiness_summary=stable_redaction_critical_count_summary, stable_readiness_required=True, waivers={'stable-1.0.redaction': 'Attempted evidence waiver for Stable critical redaction count.', 'stable-1-0-readiness': 'Attempted row waiver for Stable critical redaction count.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix waiver for Stable critical redaction count.'})
            stable_redaction_critical_count_cert, stable_redaction_critical_count_exit_code = run(stable_redaction_critical_count_settings)
            assert stable_redaction_critical_count_exit_code == 1, stable_redaction_critical_count_cert
            stable_redaction_critical_count_row = matrix_row_by_id(stable_redaction_critical_count_settings.out_dir, 'stable-1-0-readiness')
            assert stable_redaction_critical_count_row['status'] == 'fail', stable_redaction_critical_count_row
            assert stable_redaction_critical_count_row['releaseBlocker'] is True, stable_redaction_critical_count_row
            assert stable_redaction_critical_count_row.get('waiverIds') == [], stable_redaction_critical_count_row
            assert stable_redaction_critical_count_row['details']['unwaivableRedactionEvidenceIds'] == ['stable-1.0.redaction'], stable_redaction_critical_count_row
            assert 'evidence.stable-1.0.redaction' in stable_redaction_critical_count_row['issueIds'], stable_redaction_critical_count_row
            assert 'matrix.stable-readiness.redaction-failed' in stable_redaction_critical_count_row['issueIds'], stable_redaction_critical_count_row
        stable_redaction_raw_flag_summary = workspace / 'build/stable-readiness-redaction-raw-flag.json'
        stable_redaction_raw_flag_value = read_json(stable_redaction_count_summary) or {}
        stable_redaction_raw_flag_value['redaction'] = {'status': 'pass', 'findingCount': 0, 'findings': [], 'rawBodiesStored': True}
        write_json(stable_redaction_raw_flag_summary, stable_redaction_raw_flag_value)
        stable_redaction_raw_flag_items = stable_readiness_evidence(stable_redaction_raw_flag_summary, True, workspace, out_dir)
        stable_redaction_raw_flag_statuses = {item.id: item.status for item in stable_redaction_raw_flag_items}
        assert stable_redaction_raw_flag_statuses['stable-1.0.readiness-gate'] == 'fail', stable_redaction_raw_flag_statuses
        assert stable_redaction_raw_flag_statuses['stable-1.0.redaction'] == 'fail', stable_redaction_raw_flag_statuses
        stable_redaction_raw_flag_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-redaction-raw-flag-cert').resolve(), stable_readiness_summary=stable_redaction_raw_flag_summary, stable_readiness_required=True)
        stable_redaction_raw_flag_cert, stable_redaction_raw_flag_exit_code = run(stable_redaction_raw_flag_settings)
        assert stable_redaction_raw_flag_exit_code == 1, stable_redaction_raw_flag_cert
        stable_redaction_raw_flag_row = matrix_row_by_id(stable_redaction_raw_flag_settings.out_dir, 'stable-1-0-readiness')
        assert stable_redaction_raw_flag_row['status'] == 'fail', stable_redaction_raw_flag_row
        assert stable_redaction_raw_flag_row['releaseBlocker'] is True, stable_redaction_raw_flag_row
        assert 'evidence.stable-1.0.redaction' in stable_redaction_raw_flag_row['issueIds'], stable_redaction_raw_flag_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_redaction_raw_flag_row['issueIds'], stable_redaction_raw_flag_row
        stable_excluded_from_evidence_summary = workspace / 'build/stable-readiness-excluded-from-evidence-redaction.json'
        stable_excluded_from_evidence_value = read_json(stable_redaction_count_summary) or {}
        stable_excluded_from_evidence_value['redaction'] = {'status': 'pass', 'findingCount': 0, 'findings': [], 'rawBackupPayloadsExcludedFromEvidence': False}
        write_json(stable_excluded_from_evidence_summary, stable_excluded_from_evidence_value)
        stable_excluded_from_evidence_items = stable_readiness_evidence(stable_excluded_from_evidence_summary, True, workspace, out_dir)
        stable_excluded_from_evidence_statuses = {item.id: item.status for item in stable_excluded_from_evidence_items}
        assert stable_excluded_from_evidence_statuses['stable-1.0.readiness-gate'] == 'fail', stable_excluded_from_evidence_statuses
        assert stable_excluded_from_evidence_statuses['stable-1.0.redaction'] == 'fail', stable_excluded_from_evidence_statuses
        stable_excluded_from_evidence_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-excluded-from-evidence-redaction-cert').resolve(), stable_readiness_summary=stable_excluded_from_evidence_summary, stable_readiness_required=True)
        stable_excluded_from_evidence_cert, stable_excluded_from_evidence_exit_code = run(stable_excluded_from_evidence_settings)
        assert stable_excluded_from_evidence_exit_code == 1, stable_excluded_from_evidence_cert
        stable_excluded_from_evidence_row = matrix_row_by_id(stable_excluded_from_evidence_settings.out_dir, 'stable-1-0-readiness')
        assert stable_excluded_from_evidence_row['status'] == 'fail', stable_excluded_from_evidence_row
        assert stable_excluded_from_evidence_row['releaseBlocker'] is True, stable_excluded_from_evidence_row
        assert 'evidence.stable-1.0.redaction' in stable_excluded_from_evidence_row['issueIds'], stable_excluded_from_evidence_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_excluded_from_evidence_row['issueIds'], stable_excluded_from_evidence_row
        stable_redaction_fractional_count_summary = workspace / 'build/stable-readiness-redaction-fractional-count.json'
        write_json(stable_redaction_fractional_count_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findingCount': 0.5}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_redaction_fractional_count_items = stable_readiness_evidence(stable_redaction_fractional_count_summary, True, workspace, out_dir)
        stable_redaction_fractional_count_statuses = {item.id: item.status for item in stable_redaction_fractional_count_items}
        assert stable_redaction_fractional_count_statuses['stable-1.0.readiness-gate'] == 'fail', stable_redaction_fractional_count_statuses
        assert stable_redaction_fractional_count_statuses['stable-1.0.redaction'] == 'fail', stable_redaction_fractional_count_statuses
        stable_redaction_fractional_count_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-redaction-fractional-count-cert').resolve(), stable_readiness_summary=stable_redaction_fractional_count_summary, stable_readiness_required=True)
        stable_redaction_fractional_count_cert, stable_redaction_fractional_count_exit_code = run(stable_redaction_fractional_count_settings)
        assert stable_redaction_fractional_count_exit_code == 1, stable_redaction_fractional_count_cert
        stable_redaction_fractional_count_row = matrix_row_by_id(stable_redaction_fractional_count_settings.out_dir, 'stable-1-0-readiness')
        assert stable_redaction_fractional_count_row['status'] == 'fail', stable_redaction_fractional_count_row
        assert stable_redaction_fractional_count_row['releaseBlocker'] is True, stable_redaction_fractional_count_row
        assert 'evidence.stable-1.0.redaction' in stable_redaction_fractional_count_row['issueIds'], stable_redaction_fractional_count_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_redaction_fractional_count_row['issueIds'], stable_redaction_fractional_count_row
        stable_malformed_redaction_findings_summary = workspace / 'build/stable-readiness-malformed-redaction-findings.json'
        write_json(stable_malformed_redaction_findings_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': 'malformed-redaction-proof'}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_malformed_redaction_findings_items = stable_readiness_evidence(stable_malformed_redaction_findings_summary, True, workspace, out_dir)
        stable_malformed_redaction_findings_statuses = {item.id: item.status for item in stable_malformed_redaction_findings_items}
        assert stable_malformed_redaction_findings_statuses['stable-1.0.readiness-gate'] == 'fail', stable_malformed_redaction_findings_statuses
        assert stable_malformed_redaction_findings_statuses['stable-1.0.redaction'] == 'fail', stable_malformed_redaction_findings_statuses
        stable_malformed_redaction_findings_details = next((item.details for item in stable_malformed_redaction_findings_items if item.id == 'stable-1.0.redaction'))
        assert stable_malformed_redaction_findings_details['validationErrors'] == ['findings is not a list'], stable_malformed_redaction_findings_details
        stable_malformed_redaction_findings_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-malformed-redaction-findings-cert').resolve(), stable_readiness_summary=stable_malformed_redaction_findings_summary, stable_readiness_required=True)
        stable_malformed_redaction_findings_cert, stable_malformed_redaction_findings_exit_code = run(stable_malformed_redaction_findings_settings)
        assert stable_malformed_redaction_findings_exit_code == 1, stable_malformed_redaction_findings_cert
        stable_malformed_redaction_findings_row = matrix_row_by_id(stable_malformed_redaction_findings_settings.out_dir, 'stable-1-0-readiness')
        assert stable_malformed_redaction_findings_row['status'] == 'fail', stable_malformed_redaction_findings_row
        assert stable_malformed_redaction_findings_row['releaseBlocker'] is True, stable_malformed_redaction_findings_row
        assert 'evidence.stable-1.0.redaction' in stable_malformed_redaction_findings_row['issueIds'], stable_malformed_redaction_findings_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_malformed_redaction_findings_row['issueIds'], stable_malformed_redaction_findings_row
        stable_malformed_row_redaction_findings_summary = workspace / 'build/stable-readiness-malformed-row-redaction-findings.json'
        malformed_row_redaction_evidence_id = 'stable-1.0.production-beta-state'
        write_json(stable_malformed_row_redaction_findings_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'redactionFindings': 'not-a-list'} if evidence_id == malformed_row_redaction_evidence_id else {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_malformed_row_items = stable_readiness_evidence(stable_malformed_row_redaction_findings_summary, True, workspace, out_dir)
        stable_malformed_row_statuses = {item.id: item.status for item in stable_malformed_row_items}
        assert stable_malformed_row_statuses[malformed_row_redaction_evidence_id] == 'fail', stable_malformed_row_statuses
        stable_malformed_row_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-malformed-row-redaction-cert').resolve(), stable_readiness_summary=stable_malformed_row_redaction_findings_summary, stable_readiness_required=True, waivers={'stable-1-0-readiness': 'Attempted row waiver for malformed Stable row redaction failure.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix issue waiver for malformed row redaction failure.'})
        stable_malformed_row_cert, stable_malformed_row_exit_code = run(stable_malformed_row_settings)
        assert stable_malformed_row_exit_code == 1, stable_malformed_row_cert
        stable_malformed_row = matrix_row_by_id(stable_malformed_row_settings.out_dir, 'stable-1-0-readiness')
        assert stable_malformed_row['status'] == 'fail', stable_malformed_row
        assert stable_malformed_row['releaseBlocker'] is True, stable_malformed_row
        assert stable_malformed_row.get('waiverIds') == [], stable_malformed_row
        assert malformed_row_redaction_evidence_id in stable_malformed_row['details']['unwaivableRedactionEvidenceIds'], stable_malformed_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_malformed_row['issueIds'], stable_malformed_row
        stable_nested_redaction_summary = workspace / 'build/stable-readiness-nested-redaction.json'
        nested_redaction_evidence_id = 'stable-1.0.production-beta-state'
        write_json(stable_nested_redaction_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'redaction': {'status': 'pass', 'findings': [{'kind': 'stable-readiness-fixture', 'summary': 'Synthetic nested Stable evidence redaction finding.'}]}} if evidence_id == nested_redaction_evidence_id else {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_nested_items = stable_readiness_evidence(stable_nested_redaction_summary, True, workspace, out_dir)
        stable_nested_statuses = {item.id: item.status for item in stable_nested_items}
        assert stable_nested_statuses[nested_redaction_evidence_id] == 'fail', stable_nested_statuses
        stable_nested_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-nested-redaction-cert').resolve(), stable_readiness_summary=stable_nested_redaction_summary, stable_readiness_required=True, waivers={'stable-1-0-readiness': 'Attempted row waiver for nested Stable redaction failure.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix issue waiver for nested Stable redaction failure.'})
        stable_nested_cert, stable_nested_exit_code = run(stable_nested_settings)
        assert stable_nested_exit_code == 1, stable_nested_cert
        stable_nested_row = matrix_row_by_id(stable_nested_settings.out_dir, 'stable-1-0-readiness')
        assert stable_nested_row['status'] == 'fail', stable_nested_row
        assert stable_nested_row['releaseBlocker'] is True, stable_nested_row
        assert stable_nested_row.get('waiverIds') == [], stable_nested_row
        assert nested_redaction_evidence_id in stable_nested_row['details']['unwaivableRedactionEvidenceIds'], stable_nested_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_nested_row['issueIds'], stable_nested_row
        stable_direct_detail_redaction_summary = workspace / 'build/stable-readiness-direct-detail-redaction.json'
        direct_detail_redaction_evidence_id = 'stable-1.0.production-beta-state'
        stable_direct_detail_redaction_value = stable_self_test_summary()
        for entry in stable_direct_detail_redaction_value['evidence']:
            if isinstance(entry, dict) and entry.get('id') == direct_detail_redaction_evidence_id:
                entry['details'] = {'rawBackupPayloadsExcludedFromEvidence': False}
                break
        else:
            raise AssertionError(f'Stable self-test summary is missing {direct_detail_redaction_evidence_id}')
        write_json(stable_direct_detail_redaction_summary, stable_direct_detail_redaction_value)
        stable_direct_detail_redaction_items = stable_readiness_evidence(stable_direct_detail_redaction_summary, True, workspace, out_dir)
        stable_direct_detail_redaction_statuses = {item.id: item.status for item in stable_direct_detail_redaction_items}
        assert stable_direct_detail_redaction_statuses[direct_detail_redaction_evidence_id] == 'fail', stable_direct_detail_redaction_statuses
        assert stable_direct_detail_redaction_statuses['stable-1.0.redaction'] == 'fail', stable_direct_detail_redaction_statuses
        stable_direct_detail_redaction_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-direct-detail-redaction-cert').resolve(), stable_readiness_summary=stable_direct_detail_redaction_summary, stable_readiness_required=True, waivers={'stable-1-0-readiness': 'Attempted row waiver for direct Stable detail redaction failure.', 'matrix.stable-readiness.redaction-failed': 'Attempted matrix issue waiver for direct Stable detail redaction failure.'})
        stable_direct_detail_redaction_cert, stable_direct_detail_redaction_exit_code = run(stable_direct_detail_redaction_settings)
        assert stable_direct_detail_redaction_exit_code == 1, stable_direct_detail_redaction_cert
        stable_direct_detail_redaction_row = matrix_row_by_id(stable_direct_detail_redaction_settings.out_dir, 'stable-1-0-readiness')
        assert stable_direct_detail_redaction_row['status'] == 'fail', stable_direct_detail_redaction_row
        assert stable_direct_detail_redaction_row['releaseBlocker'] is True, stable_direct_detail_redaction_row
        assert stable_direct_detail_redaction_row.get('waiverIds') == [], stable_direct_detail_redaction_row
        assert direct_detail_redaction_evidence_id in stable_direct_detail_redaction_row['details']['unwaivableRedactionEvidenceIds'], stable_direct_detail_redaction_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_direct_detail_redaction_row['issueIds'], stable_direct_detail_redaction_row
        for signal_name, signal_value in (('redactionFindings', [{'kind': 'stable-readiness-self-test'}]), ('findingCount', 1), ('privateInsertUrisStored', True)):
            stable_top_level_row_redaction_summary = workspace / f'build/stable-readiness-top-level-row-{signal_name}.json'
            stable_top_level_row_redaction_value = stable_self_test_summary()
            for entry in stable_top_level_row_redaction_value['evidence']:
                if isinstance(entry, dict) and entry.get('id') == direct_detail_redaction_evidence_id:
                    entry[signal_name] = signal_value
                    break
            else:
                raise AssertionError(f'Stable self-test summary is missing {direct_detail_redaction_evidence_id}')
            write_json(stable_top_level_row_redaction_summary, stable_top_level_row_redaction_value)
            stable_top_level_row_redaction_items = stable_readiness_evidence(stable_top_level_row_redaction_summary, True, workspace, out_dir)
            stable_top_level_row_redaction_statuses = {item.id: item.status for item in stable_top_level_row_redaction_items}
            assert stable_top_level_row_redaction_statuses[direct_detail_redaction_evidence_id] == 'fail', stable_top_level_row_redaction_statuses
            assert stable_top_level_row_redaction_statuses['stable-1.0.redaction'] == 'fail', stable_top_level_row_redaction_statuses
        stable_sanitized_false_summary = workspace / 'build/stable-readiness-sanitized-false.json'
        stable_sanitized_false_value = stable_self_test_summary()
        for entry in stable_sanitized_false_value['evidence']:
            if isinstance(entry, dict) and entry.get('id') == 'stable-1.0.redaction':
                entry['details'] = {'localPathsSanitized': False}
                break
        else:
            raise AssertionError('Stable self-test summary is missing stable-1.0.redaction')
        write_json(stable_sanitized_false_summary, stable_sanitized_false_value)
        stable_sanitized_false_items = stable_readiness_evidence(stable_sanitized_false_summary, True, workspace, out_dir)
        stable_sanitized_false_statuses = {item.id: item.status for item in stable_sanitized_false_items}
        assert stable_sanitized_false_statuses['stable-1.0.readiness-gate'] == 'fail', stable_sanitized_false_statuses
        assert stable_sanitized_false_statuses['stable-1.0.redaction'] == 'fail', stable_sanitized_false_statuses
        stable_sanitized_false_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-sanitized-false-cert').resolve(), stable_readiness_summary=stable_sanitized_false_summary, stable_readiness_required=True)
        stable_sanitized_false_cert, stable_sanitized_false_exit_code = run(stable_sanitized_false_settings)
        assert stable_sanitized_false_exit_code == 1, stable_sanitized_false_cert
        stable_sanitized_false_row = matrix_row_by_id(stable_sanitized_false_settings.out_dir, 'stable-1-0-readiness')
        assert stable_sanitized_false_row['status'] == 'fail', stable_sanitized_false_row
        assert stable_sanitized_false_row['releaseBlocker'] is True, stable_sanitized_false_row
        stable_sensitive_stored_summary = workspace / 'build/stable-readiness-sensitive-stored.json'
        stable_sensitive_stored_value = stable_self_test_summary()
        for entry in stable_sensitive_stored_value['evidence']:
            if isinstance(entry, dict) and entry.get('id') == 'stable-1.0.redaction':
                entry['details'] = {'privateInsertUrisStored': True}
                break
        else:
            raise AssertionError('Stable self-test summary is missing stable-1.0.redaction')
        write_json(stable_sensitive_stored_summary, stable_sensitive_stored_value)
        stable_sensitive_stored_items = stable_readiness_evidence(stable_sensitive_stored_summary, True, workspace, out_dir)
        stable_sensitive_stored_statuses = {item.id: item.status for item in stable_sensitive_stored_items}
        assert stable_sensitive_stored_statuses['stable-1.0.readiness-gate'] == 'fail', stable_sensitive_stored_statuses
        assert stable_sensitive_stored_statuses['stable-1.0.redaction'] == 'fail', stable_sensitive_stored_statuses
        stable_sensitive_stored_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-sensitive-stored-cert').resolve(), stable_readiness_summary=stable_sensitive_stored_summary, stable_readiness_required=True)
        stable_sensitive_stored_cert, stable_sensitive_stored_exit_code = run(stable_sensitive_stored_settings)
        assert stable_sensitive_stored_exit_code == 1, stable_sensitive_stored_cert
        stable_sensitive_stored_row = matrix_row_by_id(stable_sensitive_stored_settings.out_dir, 'stable-1-0-readiness')
        assert stable_sensitive_stored_row['status'] == 'fail', stable_sensitive_stored_row
        assert stable_sensitive_stored_row['releaseBlocker'] is True, stable_sensitive_stored_row
        stable_missing_schema_summary = workspace / 'build/stable-readiness-missing-schema-version.json'
        write_json(stable_missing_schema_summary, {'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_missing_schema_items = stable_readiness_evidence(stable_missing_schema_summary, True, workspace, out_dir)
        stable_missing_schema_statuses = {item.id: item.status for item in stable_missing_schema_items}
        assert stable_missing_schema_statuses['stable-1.0.readiness-gate'] == 'fail', stable_missing_schema_statuses
        stable_missing_schema_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-missing-schema-cert').resolve(), stable_readiness_summary=stable_missing_schema_summary, stable_readiness_required=True)
        stable_missing_schema_cert, stable_missing_schema_exit_code = run(stable_missing_schema_settings)
        assert stable_missing_schema_exit_code == 1, stable_missing_schema_cert
        stable_missing_schema_row = matrix_row_by_id(stable_missing_schema_settings.out_dir, 'stable-1-0-readiness')
        assert stable_missing_schema_row['status'] == 'fail', stable_missing_schema_row
        assert stable_missing_schema_row['releaseBlocker'] is True, stable_missing_schema_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_missing_schema_row['issueIds'], stable_missing_schema_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_missing_schema_row['issueIds'], stable_missing_schema_row
        stable_invalid_decision_summary = workspace / 'build/stable-readiness-invalid-decision.json'
        write_json(stable_invalid_decision_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ship-it', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ship-it', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_invalid_decision_items = stable_readiness_evidence(stable_invalid_decision_summary, True, workspace, out_dir)
        stable_invalid_decision_statuses = {item.id: item.status for item in stable_invalid_decision_items}
        assert stable_invalid_decision_statuses['stable-1.0.readiness-gate'] == 'fail', stable_invalid_decision_statuses
        stable_invalid_decision_details = next((item.details for item in stable_invalid_decision_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_invalid_decision_details['validationErrors'] == ['decision must be ready, ready-with-allowed-limitations, or not-ready'], stable_invalid_decision_details
        stable_invalid_decision_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-invalid-decision-cert').resolve(), stable_readiness_summary=stable_invalid_decision_summary, stable_readiness_required=True)
        stable_invalid_decision_cert, stable_invalid_decision_exit_code = run(stable_invalid_decision_settings)
        assert stable_invalid_decision_exit_code == 1, stable_invalid_decision_cert
        stable_invalid_decision_row = matrix_row_by_id(stable_invalid_decision_settings.out_dir, 'stable-1-0-readiness')
        assert stable_invalid_decision_row['status'] == 'fail', stable_invalid_decision_row
        assert stable_invalid_decision_row['releaseBlocker'] is True, stable_invalid_decision_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_invalid_decision_row['issueIds'], stable_invalid_decision_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_invalid_decision_row['issueIds'], stable_invalid_decision_row
        stable_remaining_blockers_summary = workspace / 'build/stable-readiness-remaining-blockers.json'
        write_json(stable_remaining_blockers_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 1, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 1, 'domains': stable_self_test_passing_domains(), 'blockers': [{'id': 'stable-self-test-blocker', 'evidenceId': 'stable-1.0.test'}], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [{'id': 'stable-self-test-disallowed'}], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_remaining_items = stable_readiness_evidence(stable_remaining_blockers_summary, True, workspace, out_dir)
        stable_remaining_statuses = {item.id: item.status for item in stable_remaining_items}
        assert stable_remaining_statuses['stable-1.0.readiness-gate'] == 'fail', stable_remaining_statuses
        stable_remaining_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-remaining-blockers-cert').resolve(), stable_readiness_summary=stable_remaining_blockers_summary, stable_readiness_required=True)
        stable_remaining_cert, stable_remaining_exit_code = run(stable_remaining_settings)
        assert stable_remaining_exit_code == 1, stable_remaining_cert
        stable_remaining_row = matrix_row_by_id(stable_remaining_settings.out_dir, 'stable-1-0-readiness')
        assert stable_remaining_row['status'] == 'fail', stable_remaining_row
        assert stable_remaining_row['releaseBlocker'] is True, stable_remaining_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_remaining_row['issueIds'], stable_remaining_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_remaining_row['issueIds'], stable_remaining_row
        stable_fractional_remaining_counts_summary = workspace / 'build/stable-readiness-fractional-remaining-counts.json'
        write_json(stable_fractional_remaining_counts_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0.5, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0.5, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_fractional_remaining_count_items = stable_readiness_evidence(stable_fractional_remaining_counts_summary, True, workspace, out_dir)
        stable_fractional_remaining_count_statuses = {item.id: item.status for item in stable_fractional_remaining_count_items}
        assert stable_fractional_remaining_count_statuses['stable-1.0.readiness-gate'] == 'fail', stable_fractional_remaining_count_statuses
        stable_fractional_remaining_count_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-fractional-remaining-counts-cert').resolve(), stable_readiness_summary=stable_fractional_remaining_counts_summary, stable_readiness_required=True)
        stable_fractional_remaining_count_cert, stable_fractional_remaining_count_exit_code = run(stable_fractional_remaining_count_settings)
        assert stable_fractional_remaining_count_exit_code == 1, stable_fractional_remaining_count_cert
        stable_fractional_remaining_count_row = matrix_row_by_id(stable_fractional_remaining_count_settings.out_dir, 'stable-1-0-readiness')
        assert stable_fractional_remaining_count_row['status'] == 'fail', stable_fractional_remaining_count_row
        assert stable_fractional_remaining_count_row['releaseBlocker'] is True, stable_fractional_remaining_count_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_fractional_remaining_count_row['issueIds'], stable_fractional_remaining_count_row
        stable_blocker_records_summary = workspace / 'build/stable-readiness-blocker-records.json'
        write_json(stable_blocker_records_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [{'id': 'stable-self-test-blocker', 'evidenceId': 'stable-1.0.readiness-gate'}], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [{'id': 'stable-self-test-disallowed'}], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_blocker_record_items = stable_readiness_evidence(stable_blocker_records_summary, True, workspace, out_dir)
        stable_blocker_record_statuses = {item.id: item.status for item in stable_blocker_record_items}
        assert stable_blocker_record_statuses['stable-1.0.readiness-gate'] == 'fail', stable_blocker_record_statuses
        stable_blocker_record_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-blocker-records-cert').resolve(), stable_readiness_summary=stable_blocker_records_summary, stable_readiness_required=True)
        stable_blocker_record_cert, stable_blocker_record_exit_code = run(stable_blocker_record_settings)
        assert stable_blocker_record_exit_code == 1, stable_blocker_record_cert
        stable_blocker_record_row = matrix_row_by_id(stable_blocker_record_settings.out_dir, 'stable-1-0-readiness')
        assert stable_blocker_record_row['status'] == 'fail', stable_blocker_record_row
        assert stable_blocker_record_row['releaseBlocker'] is True, stable_blocker_record_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_blocker_record_row['issueIds'], stable_blocker_record_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_blocker_record_row['issueIds'], stable_blocker_record_row
        stable_allowed_record_summary = workspace / 'build/stable-readiness-allowed-records.json'
        write_json(stable_allowed_record_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [{'id': 'stable-self-test-allowed', 'title': 'Self-test allowed Stable limitation', 'category': 'ui-polish-accessibility-warning', 'classification': 'allowed-for-stable-1.0', 'status': 'open', 'summary': 'Synthetic bounded Stable 1.0 limitation.', 'evidenceIds': ['stable-1.0.known-limitations'], 'boundedBy': 'Self-test release manager bound for a non-blocking Stable limitation.'}], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_allowed_record_items = stable_readiness_evidence(stable_allowed_record_summary, True, workspace, out_dir)
        stable_allowed_record_gate = next((item for item in stable_allowed_record_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_allowed_record_gate.status == 'fail', stable_allowed_record_gate
        assert stable_allowed_record_gate.details['validationErrors'] == ['allowedLimitationCount is 0 but allowedLimitations contains 1'], stable_allowed_record_gate.details
        stable_allowed_record_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-allowed-records-cert').resolve(), stable_readiness_summary=stable_allowed_record_summary, stable_readiness_required=True)
        stable_allowed_record_cert, stable_allowed_record_exit_code = run(stable_allowed_record_settings)
        assert stable_allowed_record_exit_code == 1, stable_allowed_record_cert
        stable_allowed_record_row = matrix_row_by_id(stable_allowed_record_settings.out_dir, 'stable-1-0-readiness')
        assert stable_allowed_record_row['status'] == 'fail', stable_allowed_record_row
        assert stable_allowed_record_row['releaseBlocker'] is True, stable_allowed_record_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_allowed_record_row['issueIds'], stable_allowed_record_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_allowed_record_row['issueIds'], stable_allowed_record_row
        stable_malformed_allowed_record_summary = workspace / 'build/stable-readiness-malformed-allowed-records.json'
        write_json(stable_malformed_allowed_record_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready-with-allowed-limitations', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 1, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [1], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready-with-allowed-limitations', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_malformed_allowed_record_items = stable_readiness_evidence(stable_malformed_allowed_record_summary, True, workspace, out_dir)
        stable_malformed_allowed_record_gate = next((item for item in stable_malformed_allowed_record_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_malformed_allowed_record_gate.status == 'fail', stable_malformed_allowed_record_gate
        assert stable_malformed_allowed_record_gate.details['validationErrors'] == ['allowedLimitations[0] must be an object'], stable_malformed_allowed_record_gate.details
        stable_malformed_allowed_record_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-malformed-allowed-records-cert').resolve(), stable_readiness_summary=stable_malformed_allowed_record_summary, stable_readiness_required=True)
        stable_malformed_allowed_record_cert, stable_malformed_allowed_record_exit_code = run(stable_malformed_allowed_record_settings)
        assert stable_malformed_allowed_record_exit_code == 1, stable_malformed_allowed_record_cert
        stable_malformed_allowed_record_row = matrix_row_by_id(stable_malformed_allowed_record_settings.out_dir, 'stable-1-0-readiness')
        assert stable_malformed_allowed_record_row['status'] == 'fail', stable_malformed_allowed_record_row
        assert stable_malformed_allowed_record_row['releaseBlocker'] is True, stable_malformed_allowed_record_row
        assert 'evidence.stable-1.0.readiness-gate' in stable_malformed_allowed_record_row['issueIds'], stable_malformed_allowed_record_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_malformed_allowed_record_row['issueIds'], stable_malformed_allowed_record_row
        stable_allowed_warning_summary = workspace / 'build/stable-readiness-allowed-warning.json'
        write_json(stable_allowed_warning_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 1, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [{'id': 'stable-self-test-allowed', 'title': 'Self-test allowed Stable limitation', 'category': 'ui-polish-accessibility-warning', 'classification': 'allowed-for-stable-1.0', 'status': 'open', 'summary': 'Synthetic bounded Stable 1.0 limitation.', 'evidenceIds': ['stable-1.0.known-limitations'], 'boundedBy': 'Self-test release manager bound for a non-blocking Stable limitation.'}], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]})
        stable_allowed_warning_items = stable_readiness_evidence(stable_allowed_warning_summary, True, workspace, out_dir)
        stable_allowed_warning_gate = next((item for item in stable_allowed_warning_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_allowed_warning_gate.status == 'warn', stable_allowed_warning_gate
        stable_allowed_warning_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-allowed-warning-cert').resolve(), stable_readiness_summary=stable_allowed_warning_summary, stable_readiness_required=True)
        stable_allowed_warning_cert, stable_allowed_warning_exit_code = run(stable_allowed_warning_settings)
        assert stable_allowed_warning_exit_code == 0, stable_allowed_warning_cert
        stable_allowed_warning_row = matrix_row_by_id(stable_allowed_warning_settings.out_dir, 'stable-1-0-readiness')
        assert stable_allowed_warning_row['status'] == 'warn', stable_allowed_warning_row
        assert stable_allowed_warning_row['releaseBlocker'] is False, stable_allowed_warning_row
        stable_extra_redaction_summary = workspace / 'build/stable-readiness-extra-evidence-redaction.json'
        write_json(stable_extra_redaction_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [*[{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS], {'id': 'stable-1.0.extra-redaction-fixture', 'status': 'pass', 'summary': 'Synthetic extra Stable evidence row with redaction findings.', 'details': {'redactionFindings': [{'kind': 'stable-readiness-fixture', 'summary': 'Synthetic extra Stable evidence redaction finding.'}]}}]})
        stable_extra_redaction_items = stable_readiness_evidence(stable_extra_redaction_summary, True, workspace, out_dir)
        stable_extra_redaction_statuses = {item.id: item.status for item in stable_extra_redaction_items}
        assert stable_extra_redaction_statuses['stable-1.0.readiness-gate'] == 'fail', stable_extra_redaction_statuses
        assert stable_extra_redaction_statuses['stable-1.0.redaction'] == 'fail', stable_extra_redaction_statuses
        stable_extra_redaction_details = next((item.details for item in stable_extra_redaction_items if item.id == 'stable-1.0.redaction'))
        assert stable_extra_redaction_details['validationErrors'] == ['evidence rows contain redaction findings: stable-1.0.extra-redaction-fixture'], stable_extra_redaction_details
        stable_extra_redaction_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-extra-evidence-redaction-cert').resolve(), stable_readiness_summary=stable_extra_redaction_summary, stable_readiness_required=True)
        stable_extra_redaction_cert, stable_extra_redaction_exit_code = run(stable_extra_redaction_settings)
        assert stable_extra_redaction_exit_code == 1, stable_extra_redaction_cert
        stable_extra_redaction_row = matrix_row_by_id(stable_extra_redaction_settings.out_dir, 'stable-1-0-readiness')
        assert stable_extra_redaction_row['status'] == 'fail', stable_extra_redaction_row
        assert stable_extra_redaction_row['releaseBlocker'] is True, stable_extra_redaction_row
        assert 'evidence.stable-1.0.redaction' in stable_extra_redaction_row['issueIds'], stable_extra_redaction_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_extra_redaction_row['issueIds'], stable_extra_redaction_row
        stable_extra_status_redaction_summary = workspace / 'build/stable-readiness-extra-evidence-status-redaction.json'
        write_json(stable_extra_status_redaction_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [*[{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS], {'id': 'stable-1.0.extra-status-redaction-fixture', 'status': 'pass', 'summary': 'Synthetic extra Stable evidence row with non-pass redaction status.', 'details': {'redaction': {'status': 'warn'}}}]})
        stable_extra_status_redaction_items = stable_readiness_evidence(stable_extra_status_redaction_summary, True, workspace, out_dir)
        stable_extra_status_redaction_statuses = {item.id: item.status for item in stable_extra_status_redaction_items}
        assert stable_extra_status_redaction_statuses['stable-1.0.readiness-gate'] == 'fail', stable_extra_status_redaction_statuses
        assert stable_extra_status_redaction_statuses['stable-1.0.redaction'] == 'fail', stable_extra_status_redaction_statuses
        stable_extra_status_redaction_details = next((item.details for item in stable_extra_status_redaction_items if item.id == 'stable-1.0.redaction'))
        assert stable_extra_status_redaction_details['validationErrors'] == ['evidence rows contain redaction findings: stable-1.0.extra-status-redaction-fixture'], stable_extra_status_redaction_details
        stable_extra_status_redaction_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-extra-evidence-status-redaction-cert').resolve(), stable_readiness_summary=stable_extra_status_redaction_summary, stable_readiness_required=True)
        stable_extra_status_redaction_cert, stable_extra_status_redaction_exit_code = run(stable_extra_status_redaction_settings)
        assert stable_extra_status_redaction_exit_code == 1, stable_extra_status_redaction_cert
        stable_extra_status_redaction_row = matrix_row_by_id(stable_extra_status_redaction_settings.out_dir, 'stable-1-0-readiness')
        assert stable_extra_status_redaction_row['status'] == 'fail', stable_extra_status_redaction_row
        assert stable_extra_status_redaction_row['releaseBlocker'] is True, stable_extra_status_redaction_row
        assert 'evidence.stable-1.0.redaction' in stable_extra_status_redaction_row['issueIds'], stable_extra_status_redaction_row
        assert 'matrix.stable-readiness.redaction-failed' in stable_extra_status_redaction_row['issueIds'], stable_extra_status_redaction_row
        stable_duplicate_evidence_summary = workspace / 'build/stable-readiness-duplicate-evidence.json'
        stable_duplicate_evidence_rows = [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS]
        for index, entry in enumerate(stable_duplicate_evidence_rows):
            if entry['id'] == 'stable-1.0.security-drills':
                stable_duplicate_evidence_rows.insert(index, {'id': 'stable-1.0.security-drills', 'status': 'fail', 'summary': 'Synthetic failed duplicate Stable security drills evidence.', 'details': {}})
                break
        else:
            raise AssertionError('stable-1.0.security-drills evidence missing from self-test fixture')
        write_json(stable_duplicate_evidence_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': stable_duplicate_evidence_rows})
        stable_duplicate_items = stable_readiness_evidence(stable_duplicate_evidence_summary, True, workspace, out_dir)
        stable_duplicate_statuses = {item.id: item.status for item in stable_duplicate_items}
        assert stable_duplicate_statuses['stable-1.0.readiness-gate'] == 'fail', stable_duplicate_statuses
        assert stable_duplicate_statuses['stable-1.0.security-drills'] == 'fail', stable_duplicate_statuses
        stable_duplicate_details = next((item.details for item in stable_duplicate_items if item.id == 'stable-1.0.readiness-gate'))
        assert stable_duplicate_details['validationErrors'] == ['evidence contains duplicate required IDs: stable-1.0.security-drills'], stable_duplicate_details
        stable_duplicate_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-duplicate-evidence-cert').resolve(), stable_readiness_summary=stable_duplicate_evidence_summary, stable_readiness_required=True)
        stable_duplicate_cert, stable_duplicate_exit_code = run(stable_duplicate_settings)
        assert stable_duplicate_exit_code == 1, stable_duplicate_cert
        stable_duplicate_row = matrix_row_by_id(stable_duplicate_settings.out_dir, 'stable-1-0-readiness')
        assert stable_duplicate_row['status'] == 'fail', stable_duplicate_row
        assert stable_duplicate_row['releaseBlocker'] is True, stable_duplicate_row
        assert 'evidence.stable-1.0.security-drills' in stable_duplicate_row['issueIds'], stable_duplicate_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_duplicate_row['issueIds'], stable_duplicate_row
        for omitted_stable_evidence_id in ('stable-1.0.readiness-gate', 'stable-1.0.redaction'):
            stable_missing_compact_row_summary = workspace / 'build' / f"stable-readiness-missing-{omitted_stable_evidence_id.replace('.', '-')}.json"
            write_json(stable_missing_compact_row_summary, stable_self_test_summary(omitted_evidence_ids={omitted_stable_evidence_id}))
            stable_missing_compact_items = stable_readiness_evidence(stable_missing_compact_row_summary, True, workspace, out_dir)
            stable_missing_compact_statuses = {item.id: item.status for item in stable_missing_compact_items}
            expected_missing_compact_status = 'fail' if omitted_stable_evidence_id == 'stable-1.0.readiness-gate' else 'missing'
            assert stable_missing_compact_statuses[omitted_stable_evidence_id] == expected_missing_compact_status, (omitted_stable_evidence_id, stable_missing_compact_statuses)
            stable_missing_compact_details = next((item.details for item in stable_missing_compact_items if item.id == omitted_stable_evidence_id))
            assert f'{omitted_stable_evidence_id} is missing from stable readiness evidence' in stable_missing_compact_details['validationErrors'], stable_missing_compact_details
            if omitted_stable_evidence_id != 'stable-1.0.readiness-gate':
                assert stable_missing_compact_statuses['stable-1.0.readiness-gate'] == 'fail', (omitted_stable_evidence_id, stable_missing_compact_statuses)
        stable_truncated_summary = workspace / 'build/stable-readiness-truncated.json'
        write_json(stable_truncated_summary, {'schemaVersion': 1, 'kind': 'stable-1.0-readiness', 'tool': 'stable-1.0-readiness', 'releaseId': 'cryptad-production-beta-self-test', 'status': 'pass', 'decision': 'ready', 'stableReady': True, 'blockerCount': 0, 'warningCount': 0, 'allowedLimitationCount': 0, 'disallowedLimitationCount': 0, 'domains': stable_self_test_passing_domains(), 'blockers': [], 'warnings': [], 'allowedLimitations': [], 'disallowedLimitations': [], 'redaction': {'status': 'pass', 'findings': []}, 'evidence': [{'id': evidence_id, 'status': 'pass', 'summary': f'{evidence_id} passed.', 'details': {'decision': 'ready', 'stableReady': True} if evidence_id == 'stable-1.0.readiness-gate' else {}} for evidence_id in STABLE_1_0_READINESS_EVIDENCE_IDS if evidence_id != 'stable-1.0.security-drills']})
        stable_truncated_settings = dataclasses.replace(settings, out_dir=(workspace / 'build/stable-truncated-cert').resolve(), stable_readiness_summary=stable_truncated_summary, stable_readiness_required=True, waivers={'stable-1-0-readiness': 'Attempted row waiver for truncated Stable evidence.', 'matrix.stable-readiness.evidence-not-passing': 'Attempted matrix waiver for truncated Stable evidence.'})
        stable_truncated_cert, stable_truncated_exit_code = run(stable_truncated_settings)
        assert stable_truncated_exit_code == 1, stable_truncated_cert
        stable_truncated_row = matrix_row_by_id(stable_truncated_settings.out_dir, 'stable-1-0-readiness')
        assert stable_truncated_row['status'] == 'fail', stable_truncated_row
        assert stable_truncated_row['releaseBlocker'] is True, stable_truncated_row
        assert stable_truncated_row.get('waiverIds') == [], stable_truncated_row
        assert 'evidence.stable-1.0.security-drills' in stable_truncated_row['issueIds'], stable_truncated_row
        assert 'matrix.stable-readiness.evidence-not-passing' in stable_truncated_row['issueIds'], stable_truncated_row
        assert stable_truncated_row['details']['unwaivableIssueIds'] == ['matrix.stable-readiness.evidence-not-passing'], stable_truncated_row

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test(Path(__file__).resolve().parents[2])
        print("release-certification self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"Release certification {summary['status']}: {settings.out_dir / REPORT_FILE_NAME}")
    return exit_code
