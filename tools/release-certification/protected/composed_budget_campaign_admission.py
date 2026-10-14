"""Original full-cohort admission with private root receipts and sealed capabilities.

The app journal commits component bytes before shutdown. Independent root originals become
available afterward. A stopped-service terminal context verifies and retains those originals;
only an opaque receipt identifier crosses the attested public supervisor boundary.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from cryptad_certification import composed_budget_campaign_evidence as campaign
from cryptad_certification.cross_version_evidence import digest

ROOT = Path('/var/lib/cryptad-cross-version-authority/budget-campaign')
STAGING = Path('/var/lib/cryptad-cross-version-authority/budget-campaign-staging')
_SEAL = object()
LIMIT = 16 * 1024 * 1024


def _need(condition, code):
    if not condition: raise ValueError('composed-budget-original-' + code)


def _closed(value, fields):
    _need(isinstance(value, dict) and set(value) == set(fields), 'fields-invalid')


def _raw(value, limit=LIMIT):
    _need(isinstance(value, str) and len(value) <= (limit * 4 + 2) // 3, 'byte-limit')
    try: raw = base64.b64decode(value, validate=True)
    except ValueError: _need(False, 'encoding-invalid')
    _need(0 < len(raw) <= limit, 'byte-limit')
    return raw


def _owner(name):
    _need(name in {'pr320_route_runtime_evidence', 'pr320_storage_runtime_evidence',
                  'pr320_owner_runtime_evidence', 'pr320_privacy_runtime_evidence',
                  'pr320_restart_runtime_evidence'}, 'owner-invalid')
    if Path(__file__).absolute().is_relative_to('/opt/cryptad-cross-version'):
        from pr320_original_acquisition import verified_owner
        return verified_owner(name)
    path = Path(__file__).resolve().parents[1] / 'restricted'
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(path))
        module = importlib.import_module(name)
        _need(Path(module.__file__).resolve() == path / (name + '.py'), 'owner-source-substituted')
        return module
    finally: sys.path[:] = previous


def verify_original_member(kind, raw, originals):
    """Run the exact installed owner on independent post-cleanup root originals."""
    _closed(originals, {'owner', 'private', 'selected', 'diagnostics', 'terminal', 'report',
                        'checkpoints', 'native', 'privacyOriginals', 'browser', 'artifact'})
    owner = _owner(originals['owner'])
    private_raw = _raw(originals['private'])
    private = owner.decode_private(private_raw)
    selected, diagnostics, terminal = (originals[key] for key in ('selected', 'diagnostics', 'terminal'))
    name = originals['owner']
    if name == 'pr320_route_runtime_evidence':
        _need(kind == 'route-component', 'owner-kind-substituted')
        owner.validate_originals(private, selected, diagnostics, terminal,
            owner.decode_checkpoints(_raw(originals['checkpoints'])), _raw(originals['native']))
        value = private['component']
    elif name == 'pr320_storage_runtime_evidence':
        _need(kind == 'storage-component', 'owner-kind-substituted')
        owner.decode_checkpoints(_raw(originals['checkpoints']))
        owner.validate_originals(private, selected, diagnostics, terminal, originals['report'])
        value = private['storageComponent']
    elif name == 'pr320_owner_runtime_evidence':
        _need(kind == 'legacy-attachment', 'owner-kind-substituted')
        owner.validate_originals(private, selected, diagnostics, terminal,
            owner.decode_checkpoints(_raw(originals['checkpoints'])),
            owner.decode_root_native(_raw(originals['native'])))
        value = private['composedBudgetEvidence']
    elif name == 'pr320_restart_runtime_evidence':
        _need(kind == 'legacy-attachment', 'owner-kind-substituted')
        owner.validate_originals(private, selected, diagnostics, terminal, originals['report'],
            owner.decode_checkpoints(_raw(originals['checkpoints'])))
        value = private['composedBudgetEvidence']
    else:
        _need(kind in {'installed-privacy', 'installed-browser-privacy', 'artifact-privacy'}, 'owner-kind-substituted')
        browser = owner.decode_browser(_raw(originals['browser']))
        checkpoints = owner.decode_checkpoints(_raw(originals['checkpoints']))
        _need([row['phase'] for row in checkpoints] == ['native-collected', 'browser-collected']
              and checkpoints[0]['component'] == private['component']
              and checkpoints[1]['component'] == browser, 'privacy-checkpoint-substituted')
        owner.validate_originals(private, selected, diagnostics, terminal, originals['report'],
            originals=owner.decode_originals(_raw(originals['privacyOriginals'])), browser=browser,
            native_digest='sha256:' + hashlib.sha256(private_raw).hexdigest())
        if kind == 'artifact-privacy':
            _need(_raw(originals['artifact'], campaign.MAX_MEMBER_BYTES) == raw,
                  'artifact-original-substituted')
            value = campaign._decode(raw)
            campaign.privacy.verify_artifacts(value, private['component'],
                native_digest=value['nativeMemberDigest'], source_commit=value['sourceCommit'])
            _need(value['nativeMemberDigest'] == 'sha256:' + hashlib.sha256(private_raw).hexdigest(),
                  'artifact-native-substituted')
        else: value = private if kind == 'installed-privacy' else browser
    _need(campaign._decode(raw) == value, 'component-original-substituted')
    return selected


def _read_root(path):
    from cross_version_supervisor_authority import secured, bounded_fd
    secured(path, private=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        import stat
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
              and before.st_mode & 0o077 == 0, 'receipt-not-owned')
        raw = bounded_fd(fd, LIMIT)
        after = os.fstat(fd)
        _need(all(getattr(before, key) == getattr(after, key) for key in
                  ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), 'receipt-changed')
    finally: os.close(fd)
    return campaign._decode(raw)


def capture_owned_inputs(capture, activation, plan, terminal):
    """Stage only originals issued by the owned collector in the stopped read context."""
    from pr320_original_acquisition import OwnedAcquisitionCapture
    _need(type(capture) is OwnedAcquisitionCapture, 'capture-authority-required')
    _need(os.geteuid() == 0 and Path(__file__).absolute().is_relative_to(
        Path('/opt/cryptad-cross-version')), 'installed-root-collector-required')
    terminal.require(activation)
    rows = capture.members(activation, plan, terminal)
    for row in rows:
        _stage_owned_input(row, activation, plan)
    terminal.require(activation)


def _stage_owned_input(row, activation, plan):
    member, raw, originals = row['member'], row['raw'], row['originals']
    _need(re.fullmatch(r'member-[0-9]{2}\.json', str(member)) and isinstance(raw, bytes)
          and 0 < len(raw) <= campaign.MAX_MEMBER_BYTES, 'capture-invalid')
    from cryptad_certification import composed_budget_journal_member as journal
    selected = originals['selected']
    _need(selected['plan'] == plan, 'capture-selection-substituted')
    journal.validate_selected_sources(plan, selected['authorization']['budgetSelection']['toolIdentities'])
    metadata = next((row for row in plan['budgetCampaignInputs']['members'] if row['member'] == member), None)
    _need(metadata is not None, 'capture-unselected')
    verify_original_member(metadata['kind'], raw, originals)
    value = dict(schemaVersion=1, kind='pr320-root-captured-budget-member',
        planDigest=digest(plan), rawBase64=base64.b64encode(raw).decode(), originals=originals)
    STAGING.mkdir(mode=0o700, parents=True, exist_ok=True)
    _need(not STAGING.is_symlink() and STAGING.stat().st_uid == 0
          and STAGING.stat().st_mode & 0o077 == 0, 'capture-root-not-owned')
    from cross_version_supervisor_authority import _atomic
    directory = STAGING / digest(activation).removeprefix('sha256:')
    directory.mkdir(mode=0o700, exist_ok=True)
    _need(not directory.is_symlink() and directory.stat().st_uid == 0
          and directory.stat().st_mode & 0o077 == 0, 'capture-root-not-owned')
    path = directory / member
    if path.exists():
        _need(_read_root(path) == value, 'capture-already-retained')
    else:
        _atomic(path, value)


def validate_public_receipt(value):
    _closed(value, {'schemaVersion', 'kind', 'receiptId'})
    _need(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'pr320-original-budget-member-receipt'
          and isinstance(value['receiptId'], str)
          and re.fullmatch('[0-9a-f]{32}', value['receiptId']), 'receipt-invalid')
    return value


def retain_owned_members(plan, events, checkpoint, activation, report, terminal):
    """Verify fixed root staging records during the actual stopped supervisor context."""
    from cryptad_certification import composed_budget_journal_member as journal
    from cross_version_supervisor_authority import _atomic
    _need(terminal is not None and os.geteuid() == 0 and report['operation'] == 'finish', 'terminal-required')
    terminal.require(activation)
    journal.validate_inputs(plan)
    entries = {}
    attached = [event for event in events if 'composedBudgetCampaignMember' in event]
    _need(len(attached) == len(plan['budgetCampaignInputs']['members']), 'member-roster-incomplete')
    for event in attached:
        reference = event['composedBudgetCampaignMember']
        name = reference['member']
        staged = _read_root(STAGING / digest(activation).removeprefix('sha256:') / name)
        _closed(staged, {'schemaVersion', 'kind', 'planDigest', 'rawBase64', 'originals'})
        _need(type(staged['schemaVersion']) is int and staged['schemaVersion'] == 1
              and staged['kind'] == 'pr320-root-captured-budget-member'
              and staged['planDigest'] == digest(plan), 'staging-substituted')
        raw = _raw(staged['rawBase64'], campaign.MAX_MEMBER_BYTES)
        _need(len(raw) == reference['size'] and 'sha256:' + hashlib.sha256(raw).hexdigest() == reference['digest'],
              'journal-member-substituted')
        metadata = next(row for row in plan['budgetCampaignInputs']['members'] if row['member'] == name)
        selected = verify_original_member(metadata['kind'], raw, staged['originals'])
        _need(selected['plan'] == plan, 'owner-selection-substituted')
        if activation.get('schemaVersion') == 1:
            _need(activation.get('privateConfigDigest') == digest(selected['private'])
                  and activation.get('authorizationDigest') == digest(selected['authorization']),
                  'activation-selection-substituted')
        else:
            terminal.validate_selection(activation, plan, selected['private'])
        journal.validate_selected_sources(plan, selected['authorization']['budgetSelection']['toolIdentities'])
        entries[name] = {**staged, 'activationDigest': digest(activation), 'checkpointDigest': digest(checkpoint)}
    terminal.require(activation)
    receipt = dict(schemaVersion=1, kind='pr320-original-budget-member-receipt', receiptId=uuid.uuid4().hex)
    value = dict(schemaVersion=1, kind='pr320-private-original-budget-receipt', publicReceipt=receipt,
        job=report['job'], reportDigest=digest(report), planDigest=digest(plan),
        checkpointDigest=digest(checkpoint), entries=entries)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    _need(ROOT.stat().st_uid == 0 and ROOT.stat().st_mode & 0o077 == 0 and not ROOT.is_symlink(), 'root-not-owned')
    _atomic(ROOT / (receipt['receiptId'] + '.json'), value)
    terminal.require(activation)
    return receipt


class OriginalBudgetCampaign:
    """Frozen original budget-only verdict; serialized projections cannot create this capability."""
    __slots__ = ('_raw', '_subject', '_workloads', '_provenance', '_plans')
    def __init__(self, seal, value, subject, workloads, provenance='production-artifact-comparison', *, plans):
        _need(seal is _SEAL, 'original-authority-required')
        object.__setattr__(self, '_raw', campaign.privacy._encoded(value))
        object.__setattr__(self, '_subject', campaign.privacy._encoded(subject))
        object.__setattr__(self, '_workloads', campaign.privacy._encoded(workloads))
        _need(provenance in {'source-build-comparison', 'production-artifact-comparison'}, 'provenance-invalid')
        object.__setattr__(self, '_provenance', provenance)
        object.__setattr__(self, '_plans', json.dumps(plans, sort_keys=True))
    def __setattr__(self, *_): raise ValueError('composed-budget-original-immutable')
    def coverage(self): return json.loads(self._raw)
    def bind(self, plan):
        _need(plan.get('provenanceClass') == self._provenance, 'consumer-provenance-substituted')
        node = next(row for row in plan['nodes'] if row['role'] == 'candidate-sender')
        expected = dict(productDigest=node['artifactDigest'], sourceCommit=node['sourceCommit'],
            appCohortDigest=digest(node['appDigests']),
            contractVersion=node['contractVersion'])
        selected = json.loads(self._subject)
        _need(expected == {key: value for key, value in selected.items() if key != 'workloadDigest'},
              'consumer-subject-substituted')
        from cryptad_certification.composed_budget_journal_member import validate_inputs
        workloads = json.loads(self._workloads)
        plans = json.loads(self._plans)
        _need(all(workloads.get(row['member']) == plan['workloadInputs']['scheduler']
                  for row in validate_inputs(plan)), 'consumer-workload-substituted')
        _need(all(plans.get(row['member']) == digest(plan) for row in validate_inputs(plan)),
              'consumer-selection-substituted')


def authenticate_campaign(selection, originals, scratch, *, cutoff):
    """Reauthenticate each original chain, match retained root bytes, then derive full coverage."""
    import cross_version_supervisor_authority as supervisor
    import runtime_baseline_admission as baseline
    from cryptad_certification import composed_budget_journal_member as journal
    _need(isinstance(originals, list) and 1 <= len(originals) <= 19, 'original-roster-invalid')
    members, bindings, subject, origins, provenance, plans = {}, {}, None, set(), None, {}
    previous_finish = None
    for index, original in enumerate(originals):
        _closed(original, {'coordinates', 'bundle'})
        stage = Path(scratch) / ('original-%02d' % index)
        proof = baseline.authenticate_budget_observation(original['coordinates'], original['bundle'], stage, cutoff=cutoff)
        facts = proof.values()
        from maintenance_runtime_projection import COVERAGE_FINDINGS
        _need(facts['outcome'] in {'pass', 'partial-budget-component'}
              and not (set(facts['findings']) - COVERAGE_FINDINGS -
                       ({'run-incomplete'} if facts['outcome'] == 'partial-budget-component' else set())),
              'original-journal-incomplete')
        identity = tuple(facts['origin'][key] for key in ('runId', 'runAttempt', 'jobId'))
        started, finished, as_of = (baseline.baseline._time(value) for value in
                                   (facts['startedAt'], facts['finishedAt'], cutoff))
        _need(started < finished <= as_of, 'original-clock-invalid')
        _need(identity not in origins and (previous_finish is None or started >= previous_finish),
              'original-replayed-or-overlapping')
        origins.add(identity); previous_finish = finished
        bundle = original['bundle']; plan = bundle['plan']
        current_provenance = plan['provenanceClass']
        _need(current_provenance in {'source-build-comparison', 'production-artifact-comparison'}
              and provenance in {None, current_provenance}, 'original-product-provenance-substituted')
        provenance = current_provenance
        journal.validate_selected_sources(plan, bundle['authorization']['budgetSelection']['toolIdentities'])
        receipt_stage = stage / 'receipt-report'
        receipt_stage.mkdir(mode=0o700)
        report, _ = supervisor.authenticate_report(original['coordinates'], receipt_stage)
        public = validate_public_receipt(report['budgetCampaignReceipt'])
        retained = _read_root(ROOT / (public['receiptId'] + '.json'))
        historical = {key: value for key, value in report.items() if key not in
                      {'budgetCampaignReceipt', 'budgetCampaignBaseVersion'}}
        historical['schemaVersion'] = report['budgetCampaignBaseVersion']
        _closed(retained, {'schemaVersion', 'kind', 'publicReceipt', 'job', 'reportDigest',
                           'planDigest', 'checkpointDigest', 'entries'})
        _need(type(retained['schemaVersion']) is int and retained['schemaVersion'] == 1
              and retained['kind'] == 'pr320-private-original-budget-receipt'
              and retained['publicReceipt'] == public and retained['job'] == report['job']
              and retained['reportDigest'] == digest(historical) and retained['planDigest'] == digest(plan)
              and retained['checkpointDigest'] == digest(bundle['checkpoint']), 'receipt-substituted')
        node = next(row for row in plan['nodes'] if row['role'] == 'candidate-sender')
        current = dict(productDigest=node['artifactDigest'], sourceCommit=node['sourceCommit'],
            appCohortDigest=digest(node['appDigests']),
            contractVersion=node['contractVersion'])
        _need(subject is None or subject == current, 'campaign-subject-substituted'); subject = current
        events = [event for event in bundle['events'] if 'composedBudgetCampaignMember' in event]
        _need(isinstance(retained['entries'], dict) and set(retained['entries']) ==
              {event['composedBudgetCampaignMember']['member'] for event in events},
              'receipt-roster-substituted')
        for event in events:
            reference = event['composedBudgetCampaignMember']; name = reference['member']
            _need(name not in members, 'original-member-replayed')
            entry = retained['entries'][name]
            _closed(entry, {'schemaVersion', 'kind', 'planDigest', 'rawBase64', 'originals',
                            'activationDigest', 'checkpointDigest'})
            _need(type(entry['schemaVersion']) is int and entry['schemaVersion'] == 1
                  and entry['kind'] == 'pr320-root-captured-budget-member'
                  and entry['planDigest'] == digest(plan)
                  and entry['checkpointDigest'] == digest(bundle['checkpoint'])
                  and entry['activationDigest'] == digest(bundle['activation']), 'entry-substituted')
            raw = _raw(entry['rawBase64'], campaign.MAX_MEMBER_BYTES)
            metadata = next(row for row in plan['budgetCampaignInputs']['members'] if row['member'] == name)
            selected = verify_original_member(metadata['kind'], raw, entry['originals'])
            _need(selected == {'plan': plan, 'private': bundle['privateConfig'],
                              'authorization': bundle['authorization']}
                  and len(raw) == reference['size']
                  and 'sha256:' + hashlib.sha256(raw).hexdigest() == reference['digest'], 'member-substituted')
            members[name] = raw
            plans[name] = digest(plan)
            bindings[name] = {key: metadata[key] for key in ('collectorDigest', 'configurationDigest', 'producerDigest')}
            bindings[name].update(nodeEpoch=event['nodeEpoch'], collectorEpoch=reference['collectorEpoch'],
                                  role=event['role'], observedAt=facts['finishedAt'],
                                  workloadDigest=plan['workloadInputs']['scheduler'])
            if metadata['kind'] == 'installed-browser-privacy':
                owner = _owner('pr320_privacy_runtime_evidence')
                privacy_originals = owner.decode_originals(_raw(entry['originals']['privacyOriginals']))
                browser_receipts = [row for row in privacy_originals['receipts']
                                    if row['kind'] == 'pr320-original-browser-observation']
                _need(len(browser_receipts) == 1, 'served-script-original-missing')
                _need(metadata['servedScriptDigest'] == browser_receipts[0]['packagedScriptDigest'],
                      'served-script-selected-source-substituted')
                bindings[name]['servedScriptDigest'] = browser_receipts[0]['packagedScriptDigest']
    _need(set(members) == {'member-%02d.json' % index for index in range(19)}, 'full-original-roster-incomplete')
    _need(selection['evidenceClass'] == 'installed-cohort-local-consistency', 'installed-originals-required')
    workloads = {name: bindings[name]['workloadDigest'] for name in sorted(bindings)}
    subject['workloadDigest'] = digest(workloads)
    result = campaign.derive_campaign(selection, members, expected_subject=subject, expected_bindings=bindings)
    _need(result['budgetCohortStatus'] == 'complete-local', 'full-original-cohort-incomplete')
    result.update(evidenceClass=('original-protected-budget-cohort' if provenance == 'production-artifact-comparison'
                                else 'original-protected-source-built-budget-cohort'), originalAuthentication='authenticated',
                  budgetCohortStatus='complete-original', fullAppBudgets='observed')
    return OriginalBudgetCampaign(_SEAL, result, subject, workloads, provenance, plans=plans)
