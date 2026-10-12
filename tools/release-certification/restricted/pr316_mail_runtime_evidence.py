"""Closed validation and public projection for the PR-316 installed Mail lane.

The private observation contains only synthetic causal identifiers and bound epoch
commitments. Browser credentials, form passwords, contact material and message text
are never evidence fields. This module is side-effect free and grants no PR-315 case
or campaign credit.
"""
from __future__ import annotations

import hashlib
import base64
import binascii
import json
import re
import urllib.parse


EXECUTION_CLASS = 'pr316-installed-mail-runtime-v1'
CONTRACT = 'pr316-installed-mail-runtime-v1'
PRIVATE_KIND = 'pr316-private-mail-causal-observation'
PUBLIC_KIND = 'pr316-installed-mail-runtime'
PRIVATE_FILENAME = 'pr316-mail-flow.private.json'
MAX_PRIVATE_BYTES = 65536
SYNTHETIC_TEXTS = (
    'PUBLIC SYNTHETIC CRYPTA MAIL PROTOTYPE DEMONSTRATION',
    'PUBLIC SYNTHETIC CRYPTA MAIL PROTOTYPE REPLY')

SOURCE_IDENTITY_FIELDS = (
    'helperSourceCommit', 'helperSourceTree', 'bundleIdentity', 'testKitDigest',
    'profileDigest', 'bootClosureDigest', 'preparedImageDigest',
    'fixtureManifestDigest', 'productDigest')
ROLES = ('candidate-sender', 'candidate-recipient')
CONTEXT_NAMES = ('senderInitial', 'recipientInitial',
                 'recipientAfterWorkerRestart', 'recipientAfterRoleRestart')
MILESTONES = (
    'sender-inserted', 'recipient-accepted', 'recipient-read',
    'wrong-recipient', 'duplicate-before-worker-restart', 'worker-restart',
    'duplicate-after-worker-restart', 'role-restart',
    'duplicate-after-role-restart', 'recipient-inserted', 'sender-accepted',
    'sender-read', 'final-status')
CONTEXT_FIELDS = frozenset({
    'role', 'roleEpochDigest', 'daemonEpochDigest', 'workerEpochDigest',
    'managerInvocation', 'originDigest', 'sessionDigest',
    'sessionExpiryDigest', 'observedMonotonicNs'})
DIRECTION_FIELDS = frozenset({
    'operation', 'queueIdentifier', 'reference', 'messageId',
    'outboxMembershipObserved', 'inboxMembershipObserved'})
COMMAND_BASE_FIELDS = frozenset({
    'kind', 'role', 'command', 'requestId', 'status', 'observedMonotonicNs'})
COMMAND_OPTIONAL_FIELDS = frozenset({
    'operation', 'reference', 'messageId', 'operations', 'messageIds'})
PRIVATE_FIELDS = frozenset({
    'schemaVersion', 'kind', 'contract', 'executionClass', 'selectionDigest',
    'window', 'contexts', 'directions', 'commands', 'milestones',
    'privacySurfaces', 'uncertainOutcome'})
PUBLIC_FLAGS = (
    'namespaceTransportObserved', 'installedMailFlowObserved',
    'insertFetchDecryptObserved', 'wrongRecipientObserved',
    'duplicateBeforeWorkerRestart', 'duplicateAfterWorkerRestart',
    'duplicateAfterRoleRestart', 'workerRestartObserved',
    'roleRestartObserved', 'replyObserved', 'cleanupVerified', 'guestStopped',
    'watcherFinished', 'privacyCanarySurfacesObserved')
PRIVACY_PHASES = ('beforeWorkerRestart', 'final')
PRIVACY_SURFACES = tuple(
    role + ':' + surface
    for role in ROLES
    for surface in ('appLogs', 'appAudit', 'support', 'queue', 'diagnostics'))

_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_OPERATION = re.compile(r'[0-9a-f]{32}')
_MESSAGE = re.compile(r'[0-9a-f]{64}')
_REQUEST = re.compile(r'[^\r\n]{1,256}')
_STATUS = re.compile(r'[a-z][a-z0-9-]{0,63}')
_COMMAND = re.compile(r'[a-z][a-z0-9-]{0,63}')
_CHK = re.compile(
    r'CHK@[A-Za-z0-9~-]{43},[A-Za-z0-9~-]{43},[A-Za-z0-9~-]{7}'
    r'(?:/[A-Za-z0-9._-]{1,64})?')


def canonical_digest(value):
    """Return the repository's canonical JSON SHA-256 identifier."""
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     allow_nan=False).encode()
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def payload_exposed(data, canaries=SYNTHETIC_TEXTS):
    """Find fixed synthetic text through bounded raw, URL, JSON and Base64 decoding."""
    if not isinstance(data, bytes) or len(data) > 8 * 1024 * 1024:
        raise ValueError('pr316-privacy-surface-size-invalid')
    needles = tuple(value.encode('utf-8') for value in canaries)
    pending, seen, consumed = [(data, 0)], set(), 0
    while pending:
        value, depth = pending.pop()
        marker = (value, depth)
        if marker in seen:
            continue
        seen.add(marker)
        consumed += len(value)
        if len(seen) > 256 or consumed > 32 * 1024 * 1024:
            raise ValueError('pr316-privacy-surface-budget')
        if any(needle in value for needle in needles):
            return True
        if depth >= 4:
            continue
        try:
            text = value.decode('utf-8')
        except UnicodeError:
            text = None
        if text is not None:
            unquoted = urllib.parse.unquote_to_bytes(text.replace('+', ' '))
            if unquoted != value:
                pending.append((unquoted, depth + 1))
            try:
                decoded_json = json.loads(text)
            except (ValueError, TypeError):
                decoded_json = None
            stack = [decoded_json]
            while stack:
                selected = stack.pop()
                if isinstance(selected, str):
                    pending.append((selected.encode('utf-8'), depth + 1))
                elif isinstance(selected, dict):
                    stack.extend(selected.values())
                elif isinstance(selected, list):
                    stack.extend(selected)
            for field in text.replace(';', '&').split('&'):
                if '=' in field:
                    pending.append((field.split('=', 1)[1].encode('ascii', 'ignore'),
                                    depth + 1))
        compact = value.strip()
        if 4 <= len(compact) <= 8 * 1024 * 1024 and len(compact) % 4 == 0:
            try:
                decoded = base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError):
                decoded = None
            if decoded is not None and decoded != compact:
                pending.append((decoded, depth + 1))
    return False


def decode_private(raw):
    """Decode bounded UTF-8 JSON while rejecting duplicate object members."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PRIVATE_BYTES:
        raise ValueError('pr316-private-bytes-invalid')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('pr316-private-duplicate-field')
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ValueError('pr316-private-number-invalid')))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('pr316-private-json-invalid') from None
    return validate_private_observation(value)


def source_identity_digest(identity):
    """Digest the exact host-verified source/product identity used by PR-316."""
    if not isinstance(identity, dict) or set(identity) != set(SOURCE_IDENTITY_FIELDS):
        raise ValueError('pr316-source-identity-invalid')
    if any(not isinstance(identity[key], str) or not identity[key]
           for key in SOURCE_IDENTITY_FIELDS):
        raise ValueError('pr316-source-identity-invalid')
    return canonical_digest({key: identity[key] for key in SOURCE_IDENTITY_FIELDS})


def selection_digest(plan, authorization):
    """Require the existing authorization to bind the exact PR-316 plan bytes."""
    if (not isinstance(plan, dict) or not isinstance(authorization, dict)
            or authorization.get('executionClass') != EXECUTION_CLASS):
        raise ValueError('pr316-selection-class-invalid')
    plan_digest = canonical_digest(plan)
    digest = canonical_digest({
        'executionClass': EXECUTION_CLASS, 'planDigest': plan_digest})
    if (authorization.get('planDigest') != plan_digest
            or authorization.get('selectionDigest') != digest):
        raise ValueError('pr316-selection-digest-invalid')
    return digest


def _exact(value, fields, code):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(code)
    return value


def _digest(value, code):
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _positive_time(value, code):
    if type(value) is not int or value <= 0:
        raise ValueError(code)
    return value


def _context(name, value):
    _exact(value, CONTEXT_FIELDS, 'pr316-context-shape-invalid')
    expected_role = 'candidate-sender' if name == 'senderInitial' else 'candidate-recipient'
    if value['role'] != expected_role:
        raise ValueError('pr316-context-role-invalid')
    for key in ('roleEpochDigest', 'daemonEpochDigest', 'workerEpochDigest',
                'originDigest', 'sessionDigest', 'sessionExpiryDigest'):
        _digest(value[key], 'pr316-context-digest-invalid')
    if re.fullmatch(r'[0-9a-f]{32}', str(value['managerInvocation'])) is None:
        raise ValueError('pr316-context-invocation-invalid')
    _positive_time(value['observedMonotonicNs'], 'pr316-context-time-invalid')
    return value


def _direction(value):
    _exact(value, DIRECTION_FIELDS, 'pr316-direction-shape-invalid')
    if (_OPERATION.fullmatch(str(value['operation'])) is None
            or value['queueIdentifier'] != 'app-document-mail-prototype-' + value['operation']
            or _CHK.fullmatch(str(value['reference'])) is None
            or _MESSAGE.fullmatch(str(value['messageId'])) is None
            or value['outboxMembershipObserved'] is not True
            or value['inboxMembershipObserved'] is not True):
        raise ValueError('pr316-direction-invalid')
    return value


def _command(value):
    if (not isinstance(value, dict)
            or not COMMAND_BASE_FIELDS <= set(value)
            or not set(value) <= COMMAND_BASE_FIELDS | COMMAND_OPTIONAL_FIELDS):
        raise ValueError('pr316-command-shape-invalid')
    if (value['kind'] != 'mail-command' or value['role'] not in ROLES
            or _COMMAND.fullmatch(str(value['command'])) is None
            or _REQUEST.fullmatch(str(value['requestId'])) is None
            or _STATUS.fullmatch(str(value['status'])) is None):
        raise ValueError('pr316-command-invalid')
    _positive_time(value['observedMonotonicNs'], 'pr316-command-time-invalid')
    if 'operation' in value and _OPERATION.fullmatch(str(value['operation'])) is None:
        raise ValueError('pr316-command-operation-invalid')
    if 'reference' in value and _CHK.fullmatch(str(value['reference'])) is None:
        raise ValueError('pr316-command-reference-invalid')
    if 'messageId' in value and _MESSAGE.fullmatch(str(value['messageId'])) is None:
        raise ValueError('pr316-command-message-invalid')
    for key, pattern in (('operations', _OPERATION), ('messageIds', _MESSAGE)):
        if key in value and (not isinstance(value[key], list) or len(value[key]) > 128
                             or len(set(value[key])) != len(value[key])
                             or any(pattern.fullmatch(str(item)) is None
                                    for item in value[key])):
            raise ValueError('pr316-command-status-identifiers-invalid')
    return value


def _matching(commands, role, command, status, **fields):
    return [row for row in commands
            if row['role'] == role and row['command'] == command
            and row['status'] == status
            and all(row.get(key) == value for key, value in fields.items())]


def _validate_associations(commands, directions):
    forward, reply = directions['senderToRecipient'], directions['recipientToSender']
    forward_insert = [row for row in commands if row['role'] == 'candidate-sender'
                      and row['command'] in {'confirm-send', 'retry'}
                      and row['status'] == 'inserted'
                      and row.get('operation') == forward['operation']
                      and row.get('reference') == forward['reference']]
    if len(forward_insert) != 1:
        raise ValueError('pr316-forward-insert-association-invalid')
    forward_accept = _matching(commands, 'candidate-recipient', 'import-reference', 'accepted',
                               reference=forward['reference'], messageId=forward['messageId'])
    if len(forward_accept) != 1:
        raise ValueError('pr316-forward-import-association-invalid')
    forward_read = _matching(commands, 'candidate-recipient', 'read', 'verified-local-copy',
                             messageId=forward['messageId'])
    if len(forward_read) != 1:
        raise ValueError('pr316-forward-read-association-invalid')
    wrong = _matching(commands, 'candidate-sender', 'import-reference', 'wrong-recipient',
                      reference=forward['reference'])
    if len(wrong) != 1:
        raise ValueError('pr316-wrong-recipient-association-invalid')
    duplicates = _matching(commands, 'candidate-recipient', 'import-reference', 'duplicate',
                           reference=forward['reference'])
    if len(duplicates) != 3:
        raise ValueError('pr316-duplicate-association-invalid')
    reply_insert = [row for row in commands if row['role'] == 'candidate-recipient'
                    and row['command'] in {'confirm-send', 'retry'}
                    and row['status'] == 'inserted'
                    and row.get('operation') == reply['operation']
                    and row.get('reference') == reply['reference']]
    if len(reply_insert) != 1:
        raise ValueError('pr316-reply-insert-association-invalid')
    reply_accept = _matching(commands, 'candidate-sender', 'import-reference', 'accepted',
                             reference=reply['reference'], messageId=reply['messageId'])
    if len(reply_accept) != 1:
        raise ValueError('pr316-reply-import-association-invalid')
    reply_read = _matching(commands, 'candidate-sender', 'read', 'verified-local-copy',
                           messageId=reply['messageId'])
    if len(reply_read) != 1:
        raise ValueError('pr316-reply-read-association-invalid')
    final = {}
    for role in ROLES:
        rows = [row for row in commands if row['role'] == role
                and row['command'] == 'status' and row['status'] == 'ready'
                and 'operations' in row and 'messageIds' in row]
        if not rows:
            raise ValueError('pr316-final-status-invalid')
        final[role] = rows[-1]
    if (forward['operation'] not in final['candidate-sender']['operations']
            or forward['messageId'] not in final['candidate-recipient']['messageIds']
            or reply['operation'] not in final['candidate-recipient']['operations']
            or reply['messageId'] not in final['candidate-sender']['messageIds']):
        raise ValueError('pr316-durable-membership-invalid')
    return {'forwardInsert': forward_insert[0], 'forwardAccept': forward_accept[0],
            'forwardRead': forward_read[0], 'wrongRecipient': wrong[0],
            'duplicates': duplicates, 'replyInsert': reply_insert[0],
            'replyAccept': reply_accept[0], 'replyRead': reply_read[0],
            'final': final}


def validate_private_observation(value):
    """Validate a complete private causal record and return a detached copy."""
    _exact(value, PRIVATE_FIELDS, 'pr316-private-shape-invalid')
    if (value['schemaVersion'] != 1 or value['kind'] != PRIVATE_KIND
            or value['contract'] != CONTRACT
            or value['executionClass'] != EXECUTION_CLASS
            or value['uncertainOutcome'] is not False):
        raise ValueError('pr316-private-contract-invalid')
    _digest(value['selectionDigest'], 'pr316-private-selection-invalid')
    window = _exact(value['window'], ('startedMonotonicNs', 'finishedMonotonicNs'),
                    'pr316-window-shape-invalid')
    started = _positive_time(window['startedMonotonicNs'], 'pr316-window-invalid')
    finished = _positive_time(window['finishedMonotonicNs'], 'pr316-window-invalid')
    if started >= finished:
        raise ValueError('pr316-window-invalid')
    contexts = _exact(value['contexts'], CONTEXT_NAMES, 'pr316-contexts-invalid')
    for name in CONTEXT_NAMES:
        _context(name, contexts[name])
    initial, worker, role = (contexts[name] for name in CONTEXT_NAMES[1:])
    if (initial['roleEpochDigest'] != worker['roleEpochDigest']
            or initial['daemonEpochDigest'] != worker['daemonEpochDigest']
            or initial['workerEpochDigest'] == worker['workerEpochDigest']
            or initial['sessionDigest'] == worker['sessionDigest']
            or worker['roleEpochDigest'] == role['roleEpochDigest']
            or worker['daemonEpochDigest'] == role['daemonEpochDigest']
            or worker['workerEpochDigest'] == role['workerEpochDigest']
            or worker['sessionDigest'] == role['sessionDigest']
            or worker['managerInvocation'] == role['managerInvocation']):
        raise ValueError('pr316-restart-context-invalid')
    directions = _exact(value['directions'], ('senderToRecipient', 'recipientToSender'),
                        'pr316-directions-invalid')
    for direction in directions.values():
        _direction(direction)
    if directions['senderToRecipient']['reference'] == directions['recipientToSender']['reference']:
        raise ValueError('pr316-direction-reference-reused')
    commands = value['commands']
    if not isinstance(commands, list) or not 16 <= len(commands) <= 128:
        raise ValueError('pr316-command-count-invalid')
    commands = [_command(row) for row in commands]
    command_times = [row['observedMonotonicNs'] for row in commands]
    request_ids = [row['requestId'] for row in commands]
    if (command_times != sorted(command_times) or len(set(command_times)) != len(command_times)
            or len(set(request_ids)) != len(request_ids)
            or not started <= command_times[0] < command_times[-1] <= finished):
        raise ValueError('pr316-command-order-invalid')
    associations = _validate_associations(commands, directions)
    milestones = value['milestones']
    if not isinstance(milestones, list) or len(milestones) != len(MILESTONES):
        raise ValueError('pr316-milestones-invalid')
    times = []
    for expected, row in zip(MILESTONES, milestones, strict=True):
        _exact(row, ('name', 'observedMonotonicNs'), 'pr316-milestone-shape-invalid')
        if row['name'] != expected:
            raise ValueError('pr316-milestone-name-invalid')
        times.append(_positive_time(row['observedMonotonicNs'],
                                    'pr316-milestone-time-invalid'))
    if times != sorted(times) or len(set(times)) != len(times) \
            or not started <= times[0] < times[-1] <= finished:
        raise ValueError('pr316-milestone-order-invalid')
    milestone = {row['name']: row['observedMonotonicNs'] for row in milestones}
    duplicate = associations['duplicates']
    chain = [
        associations['forwardInsert']['observedMonotonicNs'],
        milestone['sender-inserted'],
        associations['forwardAccept']['observedMonotonicNs'],
        milestone['recipient-accepted'],
        associations['forwardRead']['observedMonotonicNs'],
        milestone['recipient-read'],
        associations['wrongRecipient']['observedMonotonicNs'],
        milestone['wrong-recipient'],
        duplicate[0]['observedMonotonicNs'],
        milestone['duplicate-before-worker-restart'],
        contexts['recipientAfterWorkerRestart']['observedMonotonicNs'],
        milestone['worker-restart'],
        duplicate[1]['observedMonotonicNs'],
        milestone['duplicate-after-worker-restart'],
        contexts['recipientAfterRoleRestart']['observedMonotonicNs'],
        milestone['role-restart'],
        duplicate[2]['observedMonotonicNs'],
        milestone['duplicate-after-role-restart'],
        associations['replyInsert']['observedMonotonicNs'],
        milestone['recipient-inserted'],
        associations['replyAccept']['observedMonotonicNs'],
        milestone['sender-accepted'],
        associations['replyRead']['observedMonotonicNs'],
        milestone['sender-read'],
        max(row['observedMonotonicNs'] for row in associations['final'].values()),
        milestone['final-status']]
    if (max(contexts['senderInitial']['observedMonotonicNs'],
            contexts['recipientInitial']['observedMonotonicNs']) >= command_times[0]
            or any(first >= second for first, second in zip(chain, chain[1:]))):
        raise ValueError('pr316-causal-order-invalid')
    privacy = _exact(value['privacySurfaces'], PRIVACY_PHASES,
                     'pr316-privacy-surfaces-invalid')
    for phase in PRIVACY_PHASES:
        rows = _exact(privacy[phase], PRIVACY_SURFACES,
                      'pr316-privacy-surfaces-invalid')
        if any(rows[name] is not True for name in PRIVACY_SURFACES):
            raise ValueError('pr316-privacy-surface-unobserved')
    return json.loads(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                 allow_nan=False))


def _projection(status, reasons, source_digest, selected_digest, flags):
    return {
        'schemaVersion': 1, 'kind': PUBLIC_KIND, 'contract': CONTRACT,
        'executionClass': EXECUTION_CLASS, 'status': status, 'reasons': list(reasons),
        'sourceIdentityDigest': source_digest, 'selectionDigest': selected_digest,
        'topologyRoles': 4, **flags,
        'installedWorkloadAcceptanceSatisfied': False,
        'historicalPr315AcceptanceTransferred': False,
        'finiteNativeAcceptance': False, 'originalProtectedAuthority': False,
        'independentSecurityReview': False, 'releaseEligible': False,
        'phaseComplete': False}


def public_projection(value, *, source_identity_digest, selection_digest,
                      cleanup_verified, guest_stopped, watcher_finished,
                      privacy_verified):
    """Project a verified private observation to a closed identifier-free result."""
    validate_private_observation(value)
    _digest(source_identity_digest, 'pr316-public-source-invalid')
    _digest(selection_digest, 'pr316-public-selection-invalid')
    if value['selectionDigest'] != selection_digest:
        raise ValueError('pr316-public-selection-mismatch')
    terminal = (cleanup_verified is True and guest_stopped is True
                and watcher_finished is True and privacy_verified is True)
    flags = {key: terminal for key in PUBLIC_FLAGS}
    return _projection('observed' if terminal else 'incomplete',
                       [] if terminal else ['terminal-evidence-incomplete'],
                       source_identity_digest, selection_digest, flags)


def failed_projection(reason, *, source_identity_digest=None, selection_digest=None):
    """Return a fixed failure without copying exception or private input text."""
    if not isinstance(reason, str) or re.fullmatch(r'[a-z][a-z0-9-]{1,100}', reason) is None:
        reason = 'private-evidence-invalid'
    for value in (source_identity_digest, selection_digest):
        if value is not None:
            _digest(value, 'pr316-failure-digest-invalid')
    return _projection('failed', [reason], source_identity_digest, selection_digest,
                       {key: False for key in PUBLIC_FLAGS})
