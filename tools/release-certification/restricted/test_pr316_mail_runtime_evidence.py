"""Offline tests for the closed PR-316 private/public evidence boundary."""
from __future__ import annotations

import copy
import json
import unittest

import pr316_mail_runtime_evidence as evidence


DIGEST = 'sha256:' + 'a' * 64
FORWARD_OPERATION = '1' * 32
REPLY_OPERATION = '2' * 32
FORWARD_MESSAGE = '3' * 64
REPLY_MESSAGE = '4' * 64
FORWARD_REFERENCE = 'CHK@' + 'A' * 43 + ',' + 'B' * 43 + ',' + 'C' * 7 + '/mail.json'
REPLY_REFERENCE = 'CHK@' + 'D' * 43 + ',' + 'E' * 43 + ',' + 'F' * 7 + '/mail.json'


def context(role, suffix, observed):
    selected = int(suffix, 16)
    digest = lambda offset: 'sha256:' + format((selected + offset) % 16, 'x') * 64
    return {
        'role': role, 'roleEpochDigest': digest(0),
        'daemonEpochDigest': digest(1),
        'workerEpochDigest': digest(2),
        'managerInvocation': suffix * 32,
        'originDigest': digest(3),
        'sessionDigest': digest(4),
        'sessionExpiryDigest': digest(5),
        'observedMonotonicNs': observed}


def command(index, role, name, status, **fields):
    return {'kind': 'mail-command', 'role': role, 'command': name,
            'requestId': f'request-{index}', 'status': status,
            'observedMonotonicNs': 100 * index, **fields}


def fixture():
    commands = [
        command(1, 'candidate-sender', 'status', 'initialize-required'),
        command(2, 'candidate-recipient', 'status', 'initialize-required'),
        command(3, 'candidate-sender', 'initialize', 'ready'),
        command(4, 'candidate-recipient', 'initialize', 'ready'),
        command(5, 'candidate-sender', 'confirm-send', 'inserted',
                operation=FORWARD_OPERATION, reference=FORWARD_REFERENCE),
        command(6, 'candidate-recipient', 'import-reference', 'accepted',
                reference=FORWARD_REFERENCE, messageId=FORWARD_MESSAGE),
        command(7, 'candidate-recipient', 'read', 'verified-local-copy',
                messageId=FORWARD_MESSAGE),
        command(8, 'candidate-sender', 'import-reference', 'wrong-recipient',
                reference=FORWARD_REFERENCE),
        command(9, 'candidate-recipient', 'import-reference', 'duplicate',
                reference=FORWARD_REFERENCE),
        command(10, 'candidate-recipient', 'import-reference', 'duplicate',
                reference=FORWARD_REFERENCE),
        command(11, 'candidate-recipient', 'import-reference', 'duplicate',
                reference=FORWARD_REFERENCE),
        command(12, 'candidate-recipient', 'confirm-send', 'inserted',
                operation=REPLY_OPERATION, reference=REPLY_REFERENCE),
        command(13, 'candidate-sender', 'import-reference', 'accepted',
                reference=REPLY_REFERENCE, messageId=REPLY_MESSAGE),
        command(14, 'candidate-sender', 'read', 'verified-local-copy',
                messageId=REPLY_MESSAGE),
        command(15, 'candidate-sender', 'status', 'ready',
                operations=[FORWARD_OPERATION], messageIds=[REPLY_MESSAGE]),
        command(16, 'candidate-recipient', 'status', 'ready',
                operations=[REPLY_OPERATION], messageIds=[FORWARD_MESSAGE]),
    ]
    for row, observed in zip(commands[9:],
                             (1100, 1300, 1400, 1500, 1600, 1700, 1710),
                             strict=True):
        row['observedMonotonicNs'] = observed
    milestone_times = (550, 650, 750, 850, 950, 1050, 1150,
                       1250, 1350, 1450, 1550, 1650, 1750)
    milestones = [
        {'name': name, 'observedMonotonicNs': observed}
        for name, observed in zip(evidence.MILESTONES, milestone_times, strict=True)]
    return {
        'schemaVersion': 1, 'kind': evidence.PRIVATE_KIND,
        'contract': evidence.CONTRACT,
        'executionClass': evidence.EXECUTION_CLASS,
        'selectionDigest': DIGEST,
        'window': {'startedMonotonicNs': 1, 'finishedMonotonicNs': 2000},
        'contexts': {
            'senderInitial': context('candidate-sender', '1', 10),
            'recipientInitial': context('candidate-recipient', '2', 20),
            'recipientAfterWorkerRestart': {
                **context('candidate-recipient', '2', 1000),
                'workerEpochDigest': 'sha256:' + '9' * 64,
                'sessionDigest': 'sha256:' + '8' * 64},
            'recipientAfterRoleRestart': context('candidate-recipient', '5', 1200)},
        'directions': {
            'senderToRecipient': {
                'operation': FORWARD_OPERATION,
                'queueIdentifier': 'app-document-mail-prototype-' + FORWARD_OPERATION,
                'reference': FORWARD_REFERENCE, 'messageId': FORWARD_MESSAGE,
                'outboxMembershipObserved': True, 'inboxMembershipObserved': True},
            'recipientToSender': {
                'operation': REPLY_OPERATION,
                'queueIdentifier': 'app-document-mail-prototype-' + REPLY_OPERATION,
                'reference': REPLY_REFERENCE, 'messageId': REPLY_MESSAGE,
                'outboxMembershipObserved': True, 'inboxMembershipObserved': True}},
        'commands': commands, 'milestones': milestones,
        'privacySurfaces': {
            phase: {name: True for name in evidence.PRIVACY_SURFACES}
            for phase in evidence.PRIVACY_PHASES},
        'uncertainOutcome': False}


class PrivateEvidenceTests(unittest.TestCase):
    def test_validates_complete_native_associations(self):
        value = fixture()
        self.assertEqual(value, evidence.validate_private_observation(value))
        self.assertEqual(value, evidence.decode_private(
            json.dumps(value, separators=(',', ':')).encode()))

    def test_accepts_retry_evidence_for_both_full_send_windows(self):
        value = fixture()
        value['window'] = {key: observed * 1000
                           for key, observed in value['window'].items()}
        for context_value in value['contexts'].values():
            context_value['observedMonotonicNs'] *= 1000
        for milestone in value['milestones']:
            milestone['observedMonotonicNs'] *= 1000
        for row in value['commands']:
            row['observedMonotonicNs'] *= 1000

        forward_confirm, reply_confirm = value['commands'][4], value['commands'][11]
        for row in (forward_confirm, reply_confirm):
            row['status'] = 'queued'
            row.pop('reference')
        forward_retries = [command(1000 + index, 'candidate-sender',
            'retry', 'queued', operation=FORWARD_OPERATION) for index in range(300)]
        reply_retries = [command(2000 + index, 'candidate-recipient',
            'retry', 'queued', operation=REPLY_OPERATION) for index in range(300)]
        for index, row in enumerate(forward_retries, 1):
            row['observedMonotonicNs'] = 500000 + index
        for index, row in enumerate(reply_retries, 1):
            row['observedMonotonicNs'] = 1400000 + index
        forward_insert = command(3000, 'candidate-sender', 'retry', 'inserted',
            operation=FORWARD_OPERATION, reference=FORWARD_REFERENCE)
        forward_insert['observedMonotonicNs'] = 500500
        reply_insert = command(3001, 'candidate-recipient', 'retry', 'inserted',
            operation=REPLY_OPERATION, reference=REPLY_REFERENCE)
        reply_insert['observedMonotonicNs'] = 1400500
        commands = value['commands']
        value['commands'] = (commands[:5] + forward_retries + [forward_insert]
                             + commands[5:12] + reply_retries + [reply_insert]
                             + commands[12:])
        raw = json.dumps(value, separators=(',', ':')).encode()

        self.assertEqual(618, len(value['commands']))
        self.assertGreater(len(raw), 65536)
        self.assertLessEqual(len(raw), evidence.MAX_PRIVATE_BYTES)
        self.assertEqual(value, evidence.decode_private(raw))

    def test_rejects_every_broken_private_association(self):
        mutations = []
        changed = fixture()
        changed['directions']['senderToRecipient']['queueIdentifier'] += '-wrong'
        mutations.append(changed)
        changed = fixture()
        changed['commands'][5]['reference'] = REPLY_REFERENCE
        mutations.append(changed)
        changed = fixture()
        changed['commands'][6]['messageId'] = REPLY_MESSAGE
        mutations.append(changed)
        changed = fixture()
        changed['commands'][14]['operations'] = []
        mutations.append(changed)
        changed = fixture()
        changed['contexts']['recipientAfterWorkerRestart']['workerEpochDigest'] = \
            changed['contexts']['recipientInitial']['workerEpochDigest']
        mutations.append(changed)
        changed = fixture()
        changed['milestones'][7], changed['milestones'][8] = \
            changed['milestones'][8], changed['milestones'][7]
        mutations.append(changed)
        changed = fixture()
        changed['privacySurfaces']['final']['candidate-recipient:support'] = False
        mutations.append(changed)
        changed = fixture()
        changed['commands'][5]['observedMonotonicNs'], changed['commands'][6][
            'observedMonotonicNs'] = (changed['commands'][6]['observedMonotonicNs'],
                                      changed['commands'][5]['observedMonotonicNs'])
        mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                evidence.validate_private_observation(value)

    def test_decode_rejects_duplicate_members_and_oversize(self):
        raw = json.dumps(fixture(), separators=(',', ':')).encode()
        duplicate = raw.replace(b'{"schemaVersion":1,',
                                b'{"schemaVersion":1,"schemaVersion":1,', 1)
        with self.assertRaisesRegex(ValueError, 'duplicate-field'):
            evidence.decode_private(duplicate)
        with self.assertRaisesRegex(ValueError, 'bytes-invalid'):
            evidence.decode_private(b'x' * (evidence.MAX_PRIVATE_BYTES + 1))

    def test_schema_rejects_secret_or_text_canary_fields(self):
        for key in ('session', 'password', 'body', 'card', 'fingerprint', 'approval'):
            value = fixture()
            value[key] = key + '-private-canary'
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.validate_private_observation(value)


class ProjectionTests(unittest.TestCase):
    def test_public_projection_is_closed_and_identifier_free(self):
        value = fixture()
        result = evidence.public_projection(
            value, source_identity_digest='sha256:' + 'b' * 64,
            selection_digest=DIGEST, cleanup_verified=True,
            guest_stopped=True, watcher_finished=True, privacy_verified=True)
        self.assertEqual('observed', result['status'])
        self.assertTrue(result['installedMailFlowObserved'])
        self.assertTrue(result['privacyCanarySurfacesObserved'])
        for field in ('installedWorkloadAcceptanceSatisfied',
                      'historicalPr315AcceptanceTransferred',
                      'finiteNativeAcceptance', 'originalProtectedAuthority',
                      'independentSecurityReview', 'releaseEligible', 'phaseComplete'):
            self.assertIs(False, result[field])
        raw = json.dumps(result, sort_keys=True)
        for canary in (FORWARD_REFERENCE, REPLY_REFERENCE, FORWARD_OPERATION,
                       REPLY_OPERATION, FORWARD_MESSAGE, REPLY_MESSAGE,
                       'session-private', 'body-private'):
            self.assertNotIn(canary, raw)

    def test_missing_terminal_fact_closes_all_observation_flags(self):
        result = evidence.public_projection(
            fixture(), source_identity_digest='sha256:' + 'b' * 64,
            selection_digest=DIGEST, cleanup_verified=True,
            guest_stopped=False, watcher_finished=True, privacy_verified=True)
        self.assertEqual('incomplete', result['status'])
        self.assertTrue(all(result[key] is False for key in evidence.PUBLIC_FLAGS))

    def test_failure_projection_never_copies_untrusted_reason(self):
        canary = 'CHK@PRIVATE-SECRET'
        result = evidence.failed_projection(canary)
        self.assertEqual(['private-evidence-invalid'], result['reasons'])
        self.assertNotIn(canary, json.dumps(result))

    def test_payload_scan_decodes_enclosing_json_base64_and_form_encoding(self):
        canary = evidence.SYNTHETIC_TEXTS[0]
        payload = json.dumps({'body': canary}, separators=(',', ':')).encode()
        import base64
        import urllib.parse
        form = urllib.parse.urlencode({
            'command': 'save-draft',
            'payloadBase64': base64.b64encode(payload).decode()}).encode()
        self.assertTrue(evidence.payload_exposed(form))
        self.assertFalse(evidence.payload_exposed(b'{"safe":true}'))

    def test_identity_and_selection_helpers_close_their_inputs(self):
        identity = {key: key + '-value' for key in evidence.SOURCE_IDENTITY_FIELDS}
        self.assertRegex(evidence.source_identity_digest(identity), r'^sha256:[0-9a-f]{64}$')
        with self.assertRaises(ValueError):
            evidence.source_identity_digest({**identity, 'extra': 'value'})
        plan = {'nodes': []}
        plan_digest = evidence.canonical_digest(plan)
        authorization = {'executionClass': evidence.EXECUTION_CLASS,
                         'planDigest': plan_digest,
                         'selectionDigest': evidence.canonical_digest({
                             'executionClass': evidence.EXECUTION_CLASS,
                             'planDigest': plan_digest})}
        self.assertEqual(authorization['selectionDigest'],
                         evidence.selection_digest(plan, authorization))


if __name__ == '__main__':
    unittest.main()
