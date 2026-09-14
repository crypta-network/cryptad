"""Network-provider seams retain exact producer, member, decision and applicability checks."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch
import zipfile

import runtime_baseline_approval as approval
from original_artifact_authentication import OriginalArtifact


class ApprovalTest(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest('native protected private-state checks require isolated sudo test invocation')
        self.tmp = tempfile.TemporaryDirectory(dir='/run')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        workspace = patch.object(approval, 'WORKSPACE', self.root)
        workspace.start()
        self.addCleanup(workspace.stop)
        self.store = self.root / 'private'
        self.store.mkdir(mode=0o700)
        self.proposal = b'{"proposal":"synthetic"}'
        self.request = {'schemaVersion': 1, 'kind': 'runtime-baseline-approval-request',
            'proposalDigest': approval.digest(self.proposal), 'proposalByteDigest': approval.digest(self.proposal),
            'proposalFinishedAt': '2026-09-14T10:00:00Z', 'policyDigest': 'sha256:' + 'b' * 64,
            'scopeDigest': 'sha256:' + 'c' * 64, 'status': 'active',
            'effectiveAt': '2026-09-14T10:00:00Z', 'expiresAt': '2026-09-15T10:00:00Z',
            'producer': {'sourceCommit': 'a' * 40, 'runId': 21, 'runAttempt': 1, 'jobId': 22}}
        self.run = {'id': 11, 'run_attempt': 1, 'head_sha': 'a' * 40, 'path': approval.WORKFLOW,
            'event': 'workflow_dispatch', 'repository': {'full_name': approval.REPOSITORY},
            'actor': {'login': 'leumor'}, 'triggering_actor': {'login': 'leumor'},
            'status': 'completed', 'conclusion': 'success'}
        self.job = {'id': 12, 'name': approval.JOB, 'head_sha': 'a' * 40, 'conclusion': 'success',
            'started_at': '2026-09-14T10:01:00Z', 'completed_at': '2026-09-14T10:02:00Z'}
        self.context = 'f' * 64
        self.history = [{'state': 'approved', 'comment': approval.decision_comment(self.context),
            'environments': [{'name': approval.ENVIRONMENT}],
            'user': {'login': 'reviewer', 'id': 23, 'type': 'User'}}]
        self.permission = {'permission': 'maintain', 'user': {'id': 23}}
        self.proof = [{'verificationResult': {'signature': {'certificate': {'runInvocationURI':
            'https://github.com/crypta-network/cryptad/actions/runs/11/attempts/1'}}}}]
        self.coords = {'repository': approval.REPOSITORY, 'sourceFamily': 'runtime-baseline-approval',
            'sourceCommit': 'a' * 40, 'runId': 11, 'runAttempt': 1, 'jobId': 12,
            'jobName': approval.JOB, 'artifactId': 15, 'artifactName': 'runtime-baseline-approval-11-1',
            'artifactDigest': 'sha256:' + 'd' * 64, 'artifactSize': 100}
        self.env = {'GITHUB_ACTIONS': 'true', 'GITHUB_JOB': approval.JOB, 'GITHUB_SHA': 'a' * 40,
                    'GITHUB_RUN_ID': '11', 'GITHUB_RUN_ATTEMPT': '1'}
        self.preparation_coords = {**self.coords, 'sourceFamily': 'runtime-baseline-proposal',
            'runId': 21, 'jobId': 22, 'jobName': 'prepare-runtime-baseline',
            'artifactName': 'runtime-baseline-proposal-21-1'}
        self.anchor = None
        self.kwargs = {'proposal_digest': self.request['proposalDigest'],
            'proposal_byte_digest': self.request['proposalByteDigest'],
            'proposal_finished_at': self.request['proposalFinishedAt'],
            'cutoff': '2026-09-14T11:00:00Z', 'reviewed_source_commit': 'a' * 40, 'private_store': self.store}

    def gh(self, args, env):
        if args[0] == 'attestation':
            if Path(args[2]).name == approval.PROPOSAL_MEMBER:
                result = copy.deepcopy(self.proof)
                result[0]['verificationResult']['signature']['certificate']['runInvocationURI'] = 'https://github.com/crypta-network/cryptad/actions/runs/21/attempts/1'
                return result
            return self.proof
        endpoint = args[-1]
        if endpoint.endswith('/approvals'):
            return self.history
        if '/jobs?' in endpoint:
            return [{'jobs': [self.job]}]
        if endpoint.endswith('/permission'):
            return self.permission
        return self.run

    def original(self, coordinates, root):
        name = approval.PROPOSAL_MEMBER if coordinates['sourceFamily'] == 'runtime-baseline-proposal' else approval.MEMBER
        value = self.anchor if name == approval.PROPOSAL_MEMBER else self.decision
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr(name, approval._bytes(value))
        completed = '2026-09-14T10:00:30Z' if name == approval.PROPOSAL_MEMBER else self.job['completed_at']
        return OriginalArtifact(output.getvalue(), coordinates, completed)

    def prepare(self):
        if self.anchor is None:
            env = {**self.env, 'GITHUB_JOB': 'prepare-runtime-baseline', 'GITHUB_RUN_ID': '21'}
            with patch.dict(os.environ, env), patch.object(approval.secrets, 'token_hex', return_value=self.context):
                self.anchor = approval.prepare_request(self.proposal, self.request, self.store)

    def produce(self):
        self.prepare()
        with patch.dict(os.environ, self.env), patch.object(approval, '_gh', side_effect=self.gh), \
                patch.object(approval, '_environment', return_value={}), \
                patch.object(approval, 'authenticate_original', side_effect=self.original):
            return approval.produce_approval(self.preparation_coords, self.root, private_store=self.store)

    def verify(self, decision=None, **kwargs):
        self.decision = self.produce() if decision is None else decision
        with patch.object(approval, 'authenticate_original', side_effect=self.original), \
                patch.object(approval, '_gh', side_effect=self.gh), patch.object(approval, '_environment', return_value={}):
            return approval.authenticate_approval(self.coords, self.root, **{**self.kwargs, **kwargs})

    def test_actual_producer_and_original_member_verifier_return_immutable_decision(self):
        verified = self.verify()
        result = verified.decision()
        self.assertEqual(result['approvalCompletedBy'], self.job['completed_at'])
        self.assertNotIn('reviewedAt', result)
        result['reviewer']['login'] = 'changed'
        self.assertEqual(verified.decision()['reviewer']['login'], 'reviewer')
        with self.assertRaises(approval.ApprovalError):
            verified._payload = b'{}'
        with self.assertRaises(approval.ApprovalError):
            approval.AuthenticatedApproval(None, {})

    def test_revoked_selection_still_checks_original_references_and_approval(self):
        for marker in ('revoked', 'superseded'):
            for invalid_reference in (False, True):
                with self.subTest(marker=marker, invalid_reference=invalid_reference):
                    self.setUp()
                    self.test_selected_baseline_authenticates_approval_in_fresh_scratch_directory(marker, invalid_reference)

    def test_selected_baseline_authenticates_approval_in_fresh_scratch_directory(self, marker=None, invalid_reference=False):
        import runtime_baseline_admission as admission
        import runtime_reference_ledger as ledger
        from test_runtime_baseline_admission import originals, vector

        campaign, rows, policy = vector()
        references = originals(rows)
        proposal = admission.prepare_proposal(campaign, references, policy)
        self.proposal = admission.encode(proposal)
        self.request.update(proposalDigest=admission.digest(proposal),
            proposalByteDigest=admission.byte_digest(self.proposal),
            proposalFinishedAt=proposal['finishedAt'], policyDigest=admission.digest(policy),
            scopeDigest=admission.digest(campaign['scope']))
        self.decision = self.produce()
        if marker:
            (self.store / (self.context + '.' + marker)).touch(mode=0o400)
        selection = {'schemaVersion': 1, 'approvalContext': self.context, 'approvalOrigin': self.coords,
            'selectedAt': '2026-09-14T10:03:00Z', 'role': 'candidate-sender', 'scope': campaign['scope'],
            'proposalDigest': admission.digest(proposal), 'policyDigest': admission.digest(policy),
            'baselineDigest': proposal['baselineSemanticDigest']}
        observations = self.store / 'observations'
        observations.mkdir(mode=0o700)
        for row in rows:
            path = observations / (row['experimentId'] + '.json')
            path.write_bytes(admission.encode({'syntheticReference': row['experimentId']}))
            path.chmod(0o400)
        scratch = self.root / 'selection-scratch'
        scratch.mkdir(mode=0o700)
        self.assertFalse((scratch / 'approval').exists())
        read_proposal = approval.read_private_proposal
        authenticate_approval = approval.authenticate_approval
        # Isolate previously verified reference inputs; run proposal recomputation and the real
        # approval member, attestation, review, and private-file checks through selection admission.
        with patch.object(approval, 'PRIVATE_STORE', self.store), \
                patch.object(approval, 'read_private_proposal',
                    side_effect=lambda context, private_store=self.store: read_proposal(context, private_store)), \
                patch.object(ledger, 'verify_complete') as complete, \
                patch.object(admission, 'authenticate_observation', side_effect=(
                    admission.AdmissionError('runtime-baseline-original-snapshot-mismatch') if invalid_reference else references)) as original_references, \
                patch.object(approval, 'authenticate_approval',
                    side_effect=lambda *args, **kwargs: authenticate_approval(*args, private_store=self.store, **kwargs)), \
                patch.object(approval, 'authenticate_original', side_effect=self.original), \
                patch.object(approval, '_gh', side_effect=self.gh), \
                patch.object(approval, '_environment', return_value={}):
            if marker:
                error = admission.AdmissionError if invalid_reference else approval.ApprovalError
                code = 'runtime-baseline-original-snapshot-mismatch' if invalid_reference else 'runtime-approval-context-revoked-or-superseded'
                with self.assertRaisesRegex(error, '^' + code + '$'):
                    admission.authenticate_selected(selection, scratch, cutoff=self.kwargs['cutoff'])
                self.assertEqual(1 if invalid_reference else len(references), original_references.call_count)
                complete.assert_called_once_with(campaign, [row['experimentId'] for row in rows])
                return
            rebuilt, approved, observed = admission.authenticate_selected(
                selection, scratch, cutoff=self.kwargs['cutoff'])
        complete.assert_called_once_with(campaign, [row['experimentId'] for row in rows])
        self.assertEqual(proposal, rebuilt)
        self.assertEqual(references, observed)
        self.assertEqual('reviewer', approved.decision()['reviewer']['login'])
        self.assertEqual(0o700, (scratch / 'approval').stat().st_mode & 0o777)

    def test_review_and_producer_failures_are_not_approval(self):
        changes = [lambda: self.history[0].update(state='rejected'),
            lambda: self.history[0].update(comment='approve other bytes'),
            lambda: self.history[0]['user'].update(login='leumor'),
            lambda: self.permission.update(permission='read'),
            lambda: self.run.update(run_attempt=2),
            lambda: self.run.update(path='other.yml'),
            lambda: self.job.update(name='other-job'),
            lambda: self.history[0]['environments'][0].update(name='other-environment')]
        for change in changes:
            with self.subTest(change=change):
                self.setUp()
                change()
                with self.assertRaises(approval.ApprovalError):
                    self.produce()

    def test_wrong_original_attestation_attempt_rejects(self):
        decision = self.produce()
        self.proof[0]['verificationResult']['signature']['certificate']['runInvocationURI'] += '2'
        with self.assertRaisesRegex(approval.ApprovalError, 'attested-attempt'):
            self.verify(decision)

    def test_exact_proposal_policy_and_cutoff_binding(self):
        decision = self.produce()
        with self.assertRaisesRegex(approval.ApprovalError, 'proposal-binding'):
            self.verify(decision, proposal_digest='sha256:' + '0' * 64)
        with self.assertRaisesRegex(approval.ApprovalError, 'not-currently-applicable'):
            self.verify(decision, cutoff='2026-09-16T00:00:00Z')
        decision['approvalContext'] = '0' * 64
        with self.assertRaisesRegex(approval.ApprovalError, 'proposal-binding'):
            self.verify(decision)

    def test_original_job_integrity_errors_are_not_approval_expiry(self):
        for family in ('runtime-baseline-approval', 'runtime-baseline-proposal'):
            with self.subTest(family=family):
                self.setUp()
                decision = self.produce()
                original = self.original
                def inconsistent_job(coordinates, root):
                    value = original(coordinates, root)
                    if coordinates['sourceFamily'] == family:
                        return OriginalArtifact(value.content, value.coordinates, '2026-09-14T10:03:00Z')
                    return value
                with patch.object(self, 'original', side_effect=inconsistent_job):
                    with self.assertRaisesRegex(approval.ApprovalError, '^runtime-approval-original-job-integrity-invalid$'):
                        self.verify(decision)
                    # Expiry cannot hide a simultaneous original-job integrity failure.
                    with self.assertRaisesRegex(approval.ApprovalError, '^runtime-approval-original-job-integrity-invalid$'):
                        self.verify(decision, cutoff='2026-09-16T00:00:00Z')
                    for marker in ('revoked', 'superseded'):
                        path = self.store / (self.context + '.' + marker)
                        path.touch(mode=0o400)
                        with self.assertRaisesRegex(approval.ApprovalError, '^runtime-approval-original-job-integrity-invalid$'):
                            self.verify(decision)
                        path.unlink()

    def test_revocation_does_not_hide_private_bytes_or_selected_scope_substitution(self):
        decision = self.produce()
        (self.store / (self.context + '.revoked')).touch(mode=0o400)
        for arguments in ({'expected_policy_digest': 'sha256:' + '0' * 64},
                          {'expected_scope_digest': 'sha256:' + '0' * 64},
                          {'expected_context': '0' * 64}):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(approval.ApprovalError, '^runtime-approval-selected-scope-mismatch$'):
                    self.verify(decision, **arguments)
        path = self.store / (self.context + '.proposal.json')
        path.write_bytes(self.proposal + b' ')
        with self.assertRaisesRegex(approval.ApprovalError, '^runtime-approval-private-proposal-substituted$'):
            self.verify(decision)

    def test_status_revocation_and_conflicting_history_fail(self):
        for status in ('revoked', 'superseded'):
            self.setUp()
            self.request['status'] = status
            self.history[0]['comment'] = approval.decision_comment(self.context)
            with self.assertRaisesRegex(approval.ApprovalError, 'not-currently-applicable'):
                self.verify()
        self.setUp()
        decision = self.produce()
        self.history.append(copy.deepcopy(self.history[0]))
        with self.assertRaisesRegex(approval.ApprovalError, 'decision-missing'):
            self.verify(decision)

    def test_unreviewed_producer_and_substituted_bytes_reject(self):
        with self.assertRaises(approval.ApprovalError):
            approval.prepare_request(self.proposal, self.request, self.store)
        self.proposal += b' '
        with self.assertRaisesRegex(approval.ApprovalError, 'proposal-substituted'):
            self.produce()

    def test_public_artifacts_and_decision_comment_do_not_disclose_private_hashes(self):
        decision = self.produce()
        public = approval._bytes(self.anchor) + approval._bytes(decision) + approval.decision_comment(self.context).encode()
        for field in ('proposalDigest', 'proposalByteDigest', 'policyDigest', 'scopeDigest'):
            self.assertNotIn(self.request[field].encode(), public)
        self.assertNotIn(b'reviewer', public)

    def test_private_root_missing_rebound_and_world_readable_fail(self):
        decision = self.produce()
        record = self.store / (self.context + '.json')
        record.chmod(0o644)
        with self.assertRaisesRegex(approval.ApprovalError, 'private-request-untrusted'):
            self.verify(decision)
        record.unlink()
        with self.assertRaisesRegex(approval.ApprovalError, 'private-request-unavailable'):
            self.verify(decision)

    def test_exact_private_proposal_retention_rejects_changed_bytes(self):
        self.prepare()
        self.assertEqual(approval.read_private_proposal(self.context, self.store), self.proposal)
        path = self.store / (self.context + '.proposal.json')
        path.write_bytes(b'{"proposal":"substituted"}')
        with self.assertRaisesRegex(approval.ApprovalError, 'private-proposal-substituted'):
            approval.read_private_proposal(self.context, self.store)

    def test_wrong_role_and_previous_approval_run_cannot_rebind_private_context(self):
        self.permission = {'permission': 'write', 'role_name': 'write', 'user': {'id': 23}}
        with self.assertRaisesRegex(approval.ApprovalError, 'reviewer-role'):
            self.produce()
        self.setUp()
        decision = self.produce()
        decision['preparationOrigin']['runId'] = 19
        with self.assertRaisesRegex(approval.ApprovalError, 'original-selection'):
            self.verify(decision)

    def test_operator_deny_marker_preserves_bytes_and_blocks_current_use(self):
        for marker in ('revoked', 'superseded'):
            with self.subTest(marker=marker):
                self.setUp()
                decision = self.produce()
                original = (self.store / (self.context + '.proposal.json')).read_bytes()
                (self.store / (self.context + '.' + marker)).touch(mode=0o400)
                with self.assertRaisesRegex(approval.ApprovalError, 'revoked-or-superseded'):
                    self.verify(decision)
                with self.assertRaisesRegex(approval.ApprovalError, 'revoked-or-superseded'):
                    self.produce()
                self.assertEqual(approval.read_private_proposal(self.context, self.store), original)

    def test_prepare_cli_isolates_each_original_reference_scratch_directory(self):
        # Original network/provider seam only: real proposal collect, exact private preparation,
        # file confinement and public projection execute through the fixed CLI.
        import cross_version_supervisor_authority as supervisor
        import runtime_baseline_admission as admission
        import runtime_reference_ledger as ledger
        from test_runtime_baseline_admission import vector, originals
        campaign, rows, policy = vector()
        with patch.object(approval, 'PRIVATE_STORE', self.store):
            (self.store / 'observations').mkdir(mode=0o700)
            with ledger._campaign(campaign, policy=policy, create=True) as (directory, _):
                for index, row in enumerate(rows):
                    ledger._write_new(directory / f'attempt-{index:02d}.json', {
                        'schemaVersion': 1, 'kind': 'runtime-reference-attempt-started',
                        'campaignDigest': admission.digest(campaign), 'index': index,
                        'experimentId': row['experimentId'], 'startedAt': row['startedAt']})
                    ledger._write_new(self.store / 'observations' / (row['experimentId'] + '.json'), {
                        'plan': {'experimentId': row['experimentId']},
                        'authorization': {'runtimeReference': campaign}, 'checkpoint': {'status': 'complete'},
                        'events': [{'wallTime': row['startedAt'], 'runtimeEvidence': {'series': row['series'], 'policy': policy}},
                                   {'kind': 'finish', 'wallTime': row['finishedAt'], 'outcome': 'pass'}]})
        config_path = self.root / 'preparation.json'
        paths = {name: self.root / (name + '.json') for name in ('campaign', 'policy', 'request', 'bundle0', 'bundle1')}
        config = {'campaignPath': str(paths['campaign']), 'policyPath': str(paths['policy']),
            'requestPath': str(paths['request']), 'observations': [
                {'coordinates': {'index': index}, 'bundlePath': str(paths['bundle' + str(index)])}
                for index in range(2)]}
        records = {config_path: config, paths['campaign']: campaign, paths['policy']: policy,
            paths['request']: {key: self.request[key] for key in ('status', 'effectiveAt', 'expiresAt')},
            paths['bundle0']: {'index': 0}, paths['bundle1']: {'index': 1}}
        for path, value in records.items():
            path.write_bytes(approval._bytes(value))
            path.chmod(0o600)
        configuration = approval._configuration
        prepare = approval.prepare_request
        seen = []

        def authenticate(coordinates, bundle, scratch, *, cutoff):
            self.assertEqual(coordinates['index'], bundle['index'])
            (scratch / '0').mkdir(parents=True)
            seen.append(scratch)
            return originals(rows)[bundle['index']]

        def selected(path, maximum=65536):
            return configuration(config_path if str(path).endswith('runtime-baseline-preparation.json') else path, maximum)

        env = {**self.env, 'GITHUB_JOB': 'prepare-runtime-baseline', 'GITHUB_RUN_ID': '21'}
        output = io.StringIO()
        with patch.dict(os.environ, env), patch.object(approval, 'PRIVATE_STORE', self.store), patch.object(supervisor, 'installed_identity', return_value={'sourceCommit': 'a' * 40}), \
                patch.object(approval, '_configuration', side_effect=selected), \
                patch.object(approval, '_environment', return_value={}), \
                patch.object(approval, '_gh', return_value=[{'jobs': [{'id': 22, 'name': 'prepare-runtime-baseline', 'head_sha': 'a' * 40}]}]), \
                patch.object(admission, 'authenticate_observation', side_effect=authenticate), \
                patch.object(approval, 'prepare_request', side_effect=lambda raw, request: prepare(raw, request, self.store)), \
                redirect_stdout(output):
            approval.main(['prepare'])
        self.assertEqual(len(set(seen)), 2)
        anchor = json.loads(output.getvalue())
        proposal = json.loads(approval.read_private_proposal(anchor['approvalContext'], self.store))
        self.assertEqual(len(proposal['attemptLedger']), 2)
        self.assertIsNone(proposal['baseline']['review'])
        self.assertEqual(proposal['campaign'], campaign)


if __name__ == '__main__':
    unittest.main()
