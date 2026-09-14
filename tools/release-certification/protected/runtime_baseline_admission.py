"""Original runtime reference admission and immutable, candidate-scoped comparison.

Network authentication is explicit. The calculator never fetches evidence. Private retained
supervisor inputs are checked against the original attested journal and authorization before
their numerical series can participate in a proposal.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from cryptad_certification.runtime_pressure_evidence import baseline, derive
from cryptad_certification.cross_version_evidence import digest, verify

_SEAL = object()
MAX_BYTES = 16 * 1024 * 1024
SCOPES = {'daemon-resource-regression-unchanged-app-cohort', 'same-product-repeatability'}


class AdmissionError(ValueError):
    """A fixed public code, without private source coordinates or input values."""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def byte_digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def decode(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise AdmissionError('runtime-baseline-input-budget')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AdmissionError('runtime-baseline-duplicate-key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AdmissionError('runtime-baseline-input-invalid') from None


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise AdmissionError('runtime-baseline-fields-invalid')


def validate_campaign(value, policy):
    closed(value, {'schemaVersion', 'kind', 'campaignId', 'plannedAt', 'scope', 'evidenceClass',
                   'referenceFingerprint', 'policyDigest', 'attempts', 'requiredRepetitions',
                   'timeoutSeconds', 'replacementOutcomes', 'maximumReplacements', 'concurrency'})
    baseline.validate_policy(policy)
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'runtime-reference-campaign' or value['scope'] not in SCOPES
            or not baseline.LABEL.fullmatch(str(value['campaignId']))
            or value['evidenceClass'] not in {'synthetic-local', 'operational'}
            or value['policyDigest'] != digest(policy) or value['concurrency'] != 'serial-exclusive'
            or type(value['requiredRepetitions']) is not int
            or value['requiredRepetitions'] != policy['minimumRepetitions']
            or type(value['maximumReplacements']) is not int or not 0 <= value['maximumReplacements'] <= 8
            or type(value['timeoutSeconds']) is not int or not 1 <= value['timeoutSeconds'] <= 432000
            or not isinstance(value['replacementOutcomes'], list)
            or len(set(value['replacementOutcomes'])) != len(value['replacementOutcomes'])
            or not set(value['replacementOutcomes']) <= {'cancelled', 'invalid', 'failed'}):
        raise AdmissionError('runtime-baseline-campaign-invalid')
    baseline._time(value['plannedAt'])
    closed(value['referenceFingerprint'], baseline.FINGERPRINT)
    attempts = value['attempts']
    if (not isinstance(attempts, list) or len(attempts) != value['requiredRepetitions'] + value['maximumReplacements']
            or not 1 <= len(attempts) <= 16
            or any(not isinstance(item, str) or not baseline.LABEL.fullmatch(item) for item in attempts)
            or len(set(attempts)) != len(attempts)):
        raise AdmissionError('runtime-baseline-attempt-roster-invalid')
    return value


class OriginalRuntimeObservation:
    """Frozen original series plus independently authenticated supervisor relationships."""
    __slots__ = ('_raw',)

    def __init__(self, seal, value):
        if seal is not _SEAL:
            raise AdmissionError('runtime-baseline-original-observation-required')
        object.__setattr__(self, '_raw', encode(value))

    def __setattr__(self, *_):
        raise AdmissionError('runtime-baseline-immutable')

    def values(self):
        return decode(self._raw)


def terminal_outcome(events, checkpoint):
    """Read the existing controller's terminal fault/cleanup semantics without rewriting it.

    A stopped service alone is insufficient. A partial checkpoint counts as cancelled only
    when the fixed controller recorded its interruption fault and completed owned cleanup.
    """
    if not events:
        raise AdmissionError('runtime-baseline-original-terminal-invalid')
    if checkpoint.get('status') == 'complete' and events[-1].get('kind') == 'finish':
        return 'pass'
    if events[-1].get('kind') != 'cleanup' or events[-1].get('outcome') != 'pass':
        raise AdmissionError('runtime-baseline-original-terminal-invalid')
    faults = [event for event in events if event.get('kind') == 'fault'
              and all(event.get(key) == '' for key in ('role', 'scenario', 'operation'))]
    if len(faults) == 1:
        if checkpoint.get('status') == 'failed' and faults[0].get('outcome') == 'fail':
            return 'failed'
        if checkpoint.get('status') == 'partial' and faults[0].get('outcome') == 'partial':
            return 'cancelled'
    raise AdmissionError('runtime-baseline-original-terminal-invalid')


def authenticate_observation(coordinates, bundle, scratch, *, cutoff):
    """Authenticate the original complete supervisor chain and reverify retained inputs.

    The private bundle is never an artifact authority. Its journal must reproduce the original
    checkpoint, and its selected configuration must reproduce the original authorization. Native
    product admission remains with the existing product owner.
    """
    import cross_version_supervisor_authority as owner
    from cryptad_certification.phase_12_runtime_adapters import _AuthenticatedSupervisor, _ORIGINAL_SUPERVISOR, _supervisor_relationships
    closed(bundle, {'plan', 'events', 'checkpoint', 'privateConfig', 'authorization',
                    'privateAuthorization', 'inputSnapshot', 'activation', 'rawInputs'})
    if len(encode(bundle)) > MAX_BYTES:
        raise AdmissionError('runtime-baseline-input-budget')
    plan, events, checkpoint = (bundle[key] for key in ('plan', 'events', 'checkpoint'))
    now = baseline._time(cutoff)
    chain, seen = [], set()
    for index in range(16):
        identity = (coordinates['runId'], coordinates['runAttempt'], coordinates['artifactId'])
        if identity in seen:
            raise AdmissionError('runtime-baseline-original-cycle')
        seen.add(identity)
        stage = Path(scratch) / str(index)
        stage.mkdir(parents=True)
        report, origin = owner.authenticate_report(coordinates, stage)
        chain.append({'report': report, 'origin': origin})
        if report['operation'] == 'authorize':
            break
        coordinates = report['previousOrigin']
    else:
        raise AdmissionError('runtime-baseline-original-chain-budget')
    authority = _AuthenticatedSupervisor(chain, _ORIGINAL_SUPERVISOR)
    values = {'plan.json': plan, 'events.json': events, 'checkpoint.json': checkpoint}
    final, observation = _supervisor_relationships(authority, values, now,
        private_runtime=bool(bundle['authorization'].get('runtimeReference') or bundle['privateConfig'].get('runtimeBaseline')))
    private, authorization = bundle['privateConfig'], bundle['authorization']
    raw_inputs = bundle['rawInputs']
    closed(raw_inputs, {'plan', 'private-config', 'authorization'})
    originals = {'plan': plan, 'private-config': private, 'authorization': authorization}
    if any(not isinstance(raw_inputs[key], str) or decode(raw_inputs[key].encode()) != val
           for key, val in originals.items()):
        raise AdmissionError('runtime-baseline-original-input-bytes-mismatch')
    bindings = {'serviceDigest': chain[-1]['report']['serviceDigest'],
                **{field: byte_digest(raw_inputs[key].encode()) for key, field in
                   (('plan', 'planDigest'), ('private-config', 'privateConfigDigest'), ('authorization', 'authorizationDigest'))}}
    prepared = bundle['privateAuthorization']
    if prepared is None:
        selected_digest = digest(bindings)
    else:
        closed(prepared, {'schemaVersion', 'kind', 'publicContext', 'privateBindings'})
        if (prepared['kind'] != 'private-runtime-authorization' or prepared['schemaVersion'] != 1
                or prepared['privateBindings'] != bindings):
            raise AdmissionError('runtime-baseline-original-selection-mismatch')
        selected_digest = digest(prepared['publicContext'])
    if chain[-1]['report']['selectionDigest'] != selected_digest:
        raise AdmissionError('runtime-baseline-original-selection-mismatch')
    activation = bundle['activation']
    if (activation.get('planDigest') != digest(plan) or activation.get('producer') != plan['producer']
            or activation.get('approvalOrigin') != chain[-1]['origin']
            or activation.get('approvalReportDigest') != digest(chain[-1]['report'])):
        raise AdmissionError('runtime-baseline-activation-mismatch')
    # Reopen original product contexts and run the existing native app/API checks. The branch
    # remains explicit: original synthetic runs never inherit published predecessor provenance.
    if plan['provenanceClass'] == 'production-artifact-comparison':
        import cross_version_product_admission as products
        with products.authenticate_products(plan, private.get('productAdmission'), Path(scratch) / 'products') as admitted:
            admitted.bind(plan, private)
            admitted.bind_apps(plan)
            if admitted.public_identities() != activation.get('products'):
                raise AdmissionError('runtime-baseline-original-products-mismatch')
    runtime_events = [event for event in events if 'runtimeEvidence' in event]
    outcome = terminal_outcome(events, checkpoint)
    if len(runtime_events) > 1 or observation['cleanup'] != 'observed':
        raise AdmissionError('runtime-baseline-original-terminal-invalid')
    attachment = runtime_events[0] if runtime_events else None
    series = attachment['runtimeEvidence']['series'] if attachment else None
    if attachment:
        from importlib import import_module
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
        collector = import_module('scheduler_pressure_runtime')
        snapshot = bundle['inputSnapshot']
        fingerprints = collector.derive_snapshot_fingerprints(snapshot)
        if (snapshot['fingerprint'] != series['fingerprint']
                or any(series['fingerprint'][key] != val for key, val in fingerprints.items())):
            raise AdmissionError('runtime-baseline-original-snapshot-mismatch')
        node = next(node for node in plan['nodes'] if node['role'] == attachment['role'])
        if (series['fingerprint']['productDigest'] != node['artifactDigest']
                or series['fingerprint']['sourceCommit'] != node['sourceCommit']
                or series['fingerprint']['appCohortDigest'] != digest(node['appDigests'])):
            raise AdmissionError('runtime-baseline-original-product-mismatch')
        derive(attachment['runtimeEvidence'], workload_digest=plan['workloadInputs']['scheduler'],
               observation_time=attachment['wallTime'])
    return OriginalRuntimeObservation(_SEAL, {
        'experimentId': plan['experimentId'], 'planDigest': digest(plan),
        'origin': chain[0]['origin'], 'producer': plan['producer'],
        'campaign': authorization.get('runtimeReference'), 'selection': private.get('runtimeBaseline'),
        'activationDigest': digest(activation), 'checkpointDigest': digest(checkpoint),
        'startedAt': events[0]['wallTime'], 'finishedAt': events[-1]['wallTime'],
        'outcome': outcome, 'series': series,
        'policy': attachment['runtimeEvidence']['policy'] if attachment else None,
        'role': attachment['role'] if attachment else None,
        'epoch': attachment['nodeEpoch'] if attachment else None,
        'findings': observation['findings']})


def prepare_proposal(campaign, observations, policy):
    """Derive every attempt and permitted replacement from the fixed original roster."""
    validate_campaign(campaign, policy)
    if not isinstance(observations, list) or not observations:
        raise AdmissionError('runtime-baseline-original-references-missing')
    if any(not isinstance(item, OriginalRuntimeObservation) for item in observations):
        raise AdmissionError('runtime-baseline-original-observation-required')
    rows = [item.values() for item in observations]
    if [row['experimentId'] for row in rows] != campaign['attempts'][:len(rows)]:
        raise AdmissionError('runtime-baseline-attempt-roster-mismatch')
    references, ledger, identities, epochs, node_epochs = [], [], set(), set(), set()
    previous_finish = baseline._time(campaign['plannedAt'])
    replacements = 0
    for row in rows:
        if len(references) == campaign['requiredRepetitions']:
            raise AdmissionError('runtime-baseline-extra-attempts')
        if row['campaign'] != campaign:
            raise AdmissionError('runtime-baseline-campaign-not-originally-selected')
        from maintenance_runtime_projection import COVERAGE_FINDINGS
        allowed_failure = {'observed-failure', 'run-incomplete', 'fault-recovery-incomplete'} if row['outcome'] in {'fail', 'failed', 'cancelled'} else set()
        if set(row['findings']) - COVERAGE_FINDINGS - allowed_failure:
            raise AdmissionError('runtime-baseline-original-journal-invalid')
        origin = row['origin']
        identity = tuple(origin[k] for k in ('runId', 'runAttempt', 'jobId'))
        start, finish = map(baseline._time, (row['startedAt'], row['finishedAt']))
        if (identity in identities or start < previous_finish or finish <= start
                or (finish - start).total_seconds() > campaign['timeoutSeconds']):
            raise AdmissionError('runtime-baseline-repetition-not-independent')
        identities.add(identity)
        previous_finish = finish
        series = row['series']
        valid = False
        if series is not None:
            if row['epoch'] is None or row['epoch'] in node_epochs:
                raise AdmissionError('runtime-baseline-repetition-epoch-reused')
            node_epochs.add(row['epoch'])
            baseline.validate_series(series)
            segment = tuple(sample['epoch'] for sample in series['samples'])
            unique_epochs = set(segment)
            if epochs & unique_epochs or len(unique_epochs) != 1:
                raise AdmissionError('runtime-baseline-repetition-epoch-reused')
            epochs |= unique_epochs
            if (series['fingerprint'] != campaign['referenceFingerprint']
                    or series['evidenceClass'] != campaign['evidenceClass'] or row['policy'] != policy
                    or baseline._time(series['startedAt']) < start or baseline._time(series['finishedAt']) > finish):
                raise AdmissionError('runtime-baseline-reference-applicability-mismatch')
            assessment = baseline.assess(series, policy)
            valid = (assessment['status'] == 'valid' and row['outcome'] in {'pass', 'partial'}
                     and 'observed-failure' not in row['findings'])
        disposition = ('accepted' if valid else 'cancelled' if row['outcome'] == 'cancelled'
                       else 'failed' if row['outcome'] in {'fail', 'failed'} or series is None else 'invalid')
        if valid:
            references.append(series)
        else:
            replacements += 1
            if disposition not in campaign['replacementOutcomes'] or replacements > campaign['maximumReplacements']:
                raise AdmissionError('runtime-baseline-replacement-not-planned')
        ledger.append({'experimentId': row['experimentId'], 'origin': origin, 'planDigest': row['planDigest'],
                       'checkpointDigest': row['checkpointDigest'], 'startedAt': row['startedAt'],
                       'finishedAt': row['finishedAt'], 'disposition': disposition,
                       'seriesDigest': digest(series) if series else None})
    if len(references) != campaign['requiredRepetitions']:
        raise AdmissionError('runtime-baseline-reference-insufficient-data')
    candidate = baseline.collect(references, policy)
    # Reference dispersion uses the existing comparison definitions, without issuing approval.
    import statistics
    for phase in policy['phases']:
        for metric in policy['bounds']:
            medians = [item['phases'][phase]['metrics'][metric]['median'] for item in candidate['assessments']]
            if max(medians) - min(medians) > statistics.median(medians) * policy['maximumDispersionRatio']:
                raise AdmissionError('runtime-baseline-reference-dispersion')
    return {'schemaVersion': 1, 'kind': 'runtime-baseline-proposal', 'campaign': campaign,
            'attemptLedger': ledger, 'unneededAttempts': campaign['attempts'][len(rows):],
            'baseline': candidate, 'baselineByteDigest': byte_digest(encode(candidate)),
            'baselineSemanticDigest': digest(candidate), 'finishedAt': rows[-1]['finishedAt']}


class AuthenticatedRuntimeBaseline:
    """One approved baseline bound to one original candidate and assessment cutoff."""
    __slots__ = ('_raw',)

    def __init__(self, seal, proposal, decision, selection, observation, cutoff):
        if seal is not _SEAL or not isinstance(observation, OriginalRuntimeObservation):
            raise AdmissionError('runtime-baseline-original-authority-required')
        object.__setattr__(self, '_raw', encode({'proposal': proposal, 'decision': decision, 'selection': selection,
                            'observation': observation.values(), 'cutoff': cutoff}))

    def __setattr__(self, *_):
        raise AdmissionError('runtime-baseline-immutable')

    def compare_candidate(self, series, *, binding, cutoff, candidate_policy):
        value = decode(self._raw)
        proposal, decision, selection, observed = (value[key] for key in ('proposal', 'decision', 'selection', 'observation'))
        expected = {key: observed[key] for key in ('planDigest', 'activationDigest', 'role', 'epoch', 'checkpointDigest')}
        expected.update(sourceCommit=series['fingerprint']['sourceCommit'], productDigest=series['fingerprint']['productDigest'])
        if (binding != expected or series != observed['series'] or cutoff != value['cutoff']
                or candidate_policy != proposal['baseline']['policy'] or candidate_policy != observed['policy']):
            raise AdmissionError('runtime-baseline-candidate-unverified')
        reviewed = reviewed_view(proposal, decision)
        comparison_series = decode(encode(series))
        # v1 compatibility view is in-memory only; exact original selection binds its immutable
        # candidate bytes and detached approval. It never rewrites original collected bytes.
        comparison_series['selection']['baselineDigest'] = digest(reviewed)
        numeric = baseline.compare(comparison_series, reviewed)
        applicability = 'applicable'
        if decision['status'] != 'active':
            applicability = 'revoked'
        elif not baseline._time(decision['effectiveAt']) <= baseline._time(cutoff) < baseline._time(decision['expiresAt']):
            applicability = 'expired'
        status = numeric['status']
        accepted = status == 'within-reviewed-local-bounds' and applicability == 'applicable'
        reason = ('approval-' + applicability if applicability in {'expired', 'revoked'} else
                  {'fail': 'regression', 'incomparable': 'incomparable', 'insufficient-data': 'insufficient-data',
                   'measured-but-uncompared': 'approval-missing'}.get(status))
        return {'schemaVersion': 1, 'kind': 'authenticated-runtime-baseline-comparison',
                'numericComparison': status, 'referenceProvenance': 'authenticated',
                'approvalAuthentication': 'authenticated', 'preselectionBinding': 'authenticated',
                'originalCandidateObservation': 'authenticated', 'applicability': applicability,
                'scopedPerformanceVerdict': 'accepted' if accepted else 'regression' if status == 'fail' else 'blocked',
                'claim': 'runtime-within-reviewed-bounds', 'status': 'observed' if accepted else 'not-observed',
                'scope': proposal['campaign']['scope'],
                # The fixed scheduler workload produces synthetic content even when the
                # historical series format labels its protected execution "operational".
                'evidenceClass': 'synthetic',
                'reasons': ['runtime-baseline-' + reason] if reason else [],
                'fullAppBudgets': 'not-observed', 'releaseEligible': False}


def reviewed_view(proposal, decision):
    result = decode(encode(proposal['baseline']))
    result['review'] = {'status': 'reviewed', 'reviewedAt': decision['approvalCompletedBy'],
                        'originDigest': digest(proposal['attemptLedger']), 'approvalDigest': digest(decision),
                        'candidateDigest': digest(result),
                        'evidenceClass': proposal['campaign']['evidenceClass']}
    return result


def admit_candidate(proposal, approved, selection, observation, *, cutoff, original_references):
    from runtime_baseline_approval import AuthenticatedApproval
    if not isinstance(approved, AuthenticatedApproval) or not isinstance(observation, OriginalRuntimeObservation):
        raise AdmissionError('runtime-baseline-original-authority-required')
    if prepare_proposal(proposal['campaign'], original_references, proposal['baseline']['policy']) != proposal:
        raise AdmissionError('runtime-baseline-proposal-recomputation-mismatch')
    decision = approved.decision()
    closed(selection, {'schemaVersion', 'proposalDigest', 'baselineDigest', 'approvalContext',
                       'policyDigest', 'selectedAt', 'role', 'scope', 'approvalOrigin'})
    observed = observation.values()
    from maintenance_runtime_projection import COVERAGE_FINDINGS
    if set(observed['findings']) - COVERAGE_FINDINGS or observed['outcome'] not in {'pass', 'partial'}:
        raise AdmissionError('runtime-baseline-original-candidate-invalid')
    for original in original_references:
        reference_observation = original.values()
        if (reference_observation['planDigest'] == observed['planDigest']
                or reference_observation['epoch'] is not None and reference_observation['epoch'] == observed['epoch']
                or reference_observation['series'] is not None and
                {sample['epoch'] for sample in reference_observation['series']['samples']} &
                {sample['epoch'] for sample in observed['series']['samples']}):
            raise AdmissionError('runtime-baseline-candidate-reuses-reference')
    if (selection['schemaVersion'] != 1 or selection['proposalDigest'] != digest(proposal)
            or selection['baselineDigest'] != proposal['baselineSemanticDigest']
            or selection['policyDigest'] != digest(proposal['baseline']['policy'])
            or selection['scope'] != proposal['campaign']['scope'] or selection['role'] != observed['role']
            or selection != observed['selection'] or decision['proposalDigest'] != digest(proposal)
            or decision['proposalByteDigest'] != byte_digest(encode(proposal))
            or selection['approvalContext'] != decision['approvalContext']
            or selection['approvalOrigin'] != decision['originalCoordinates']
            or decision['policyDigest'] != digest(proposal['baseline']['policy'])
            or decision['scopeDigest'] != digest(proposal['campaign']['scope'])):
        raise AdmissionError('runtime-baseline-selection-mismatch')
    start, selected, approved_by, end, assessed = map(baseline._time, (
        observed['series']['startedAt'], selection['selectedAt'], decision['approvalCompletedBy'],
        observed['finishedAt'], cutoff))
    if (not baseline._time(proposal['finishedAt']) <= approved_by <= selected <= baseline._time(observed['startedAt']) <= start < end <= assessed
            or not baseline._time(decision['effectiveAt']) <= selected < baseline._time(decision['expiresAt'])
            or observed['series']['selection'] != {'baselineDigest': selection['baselineDigest'],
                'policyDigest': selection['policyDigest'], 'selectedAt': selection['selectedAt']}):
        raise AdmissionError('runtime-baseline-preselection-order-invalid')
    reference = proposal['campaign']['referenceFingerprint']
    current = observed['series']['fingerprint']
    matching = [current[key] == reference[key] for key in ('productDigest', 'sourceCommit')]
    if (selection['scope'] == 'same-product-repeatability' and not all(matching)
            or selection['scope'] != 'same-product-repeatability' and any(matching)):
        raise AdmissionError('runtime-baseline-comparison-scope-invalid')
    return AuthenticatedRuntimeBaseline(_SEAL, proposal, decision, selection, observation, cutoff)


def authenticate_selected(selection, scratch, *, cutoff):
    """Recompute frozen proposal from all original references before admitting its approval."""
    import runtime_baseline_approval as approvals
    import cross_version_supervisor_authority as owner
    raw = approvals.read_private_proposal(selection['approvalContext'])
    proposal = decode(raw)
    from runtime_reference_ledger import verify_complete
    verify_complete(proposal['campaign'], [row['experimentId'] for row in proposal['attemptLedger']])
    observations = []
    for index, attempt in enumerate(proposal['attemptLedger']):
        path = approvals.PRIVATE_STORE / 'observations' / (attempt['experimentId'] + '.json')
        bundle = decode(owner.secured(path, private=True).read_bytes())
        observations.append(authenticate_observation(attempt['origin'], bundle, Path(scratch) / f'reference-{index}', cutoff=cutoff))
    rebuilt = prepare_proposal(proposal['campaign'], observations, proposal['baseline']['policy'])
    if encode(rebuilt) != raw or digest(rebuilt) != selection['proposalDigest']:
        raise AdmissionError('runtime-baseline-proposal-recomputation-mismatch')
    approval_scratch = Path(scratch) / 'approval'
    approval_scratch.mkdir(mode=0o700)
    approved = approvals.authenticate_approval(selection['approvalOrigin'], approval_scratch,
        proposal_digest=digest(rebuilt), proposal_byte_digest=byte_digest(raw),
        proposal_finished_at=rebuilt['finishedAt'], cutoff=cutoff,
        reviewed_source_commit=selection['approvalOrigin']['sourceCommit'])
    decision = approved.decision()
    if (decision['policyDigest'] != digest(rebuilt['baseline']['policy'])
            or decision['scopeDigest'] != digest(rebuilt['campaign']['scope'])
            or decision['approvalContext'] != selection['approvalContext']
            or selection['baselineDigest'] != rebuilt['baselineSemanticDigest']
            or selection['policyDigest'] != digest(rebuilt['baseline']['policy'])):
        raise AdmissionError('runtime-baseline-approval-scope-mismatch')
    return rebuilt, approved, observations


def _owned_read(path, uid, maximum):
    import os
    import stat
    # Every parent below the owned experiment is confined by the caller. Open each component
    # without following links, so a workload cannot swap a snapshot into an unrelated file.
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = Path(path).absolute().parts[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(file, 'rb') as stream:
            observed = os.fstat(stream.fileno())
            if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != uid or observed.st_mode & 0o077
                    or observed.st_nlink != 1 or observed.st_size > maximum):
                raise AdmissionError('runtime-baseline-private-observation-unavailable')
            result = stream.read(maximum + 1)
            if len(result) > maximum:
                raise AdmissionError('runtime-baseline-input-budget')
            return result
    finally:
        os.close(descriptor)


def owned_bundle(plan, events, checkpoint, activation):
    """Capture original owned inputs only inside the fixed stopped root supervisor."""
    import os
    import cross_version_supervisor_authority as owner
    if os.geteuid() != 0 or owner.read_json(owner.secured(owner.AUTHORITY / 'activation.json')) != activation:
        raise AdmissionError('runtime-baseline-owned-activation-required')
    if owner._service_state() != 'stopped':
        raise AdmissionError('runtime-baseline-owned-terminal-required')
    terminal_outcome(events, checkpoint)
    selected, hashes = owner.read_selected(owner.STATE, activation['ownerUid'])
    if selected['plan'] != plan:
        raise AdmissionError('runtime-baseline-owned-plan-substituted')
    raw = {key: _owned_read(owner.STATE / 'selected' / (key + '.json'), activation['ownerUid'], 4 * 1024 * 1024).decode()
           for key in ('plan', 'private-config', 'authorization')}
    if any(byte_digest(text.encode()) != hashes[key] for key, text in raw.items()):
        raise AdmissionError('runtime-baseline-selected-input-changed')
    snapshot_path = Path(selected['private-config']['root']) / 'scheduler-observation/runtime-input-snapshot.json'
    snapshot = decode(_owned_read(snapshot_path, activation['ownerUid'], 65536)) if any('runtimeEvidence' in event for event in events) else None
    prepared = owner.read_json(owner.secured(owner.AUTHORITY / 'runtime-authorization.json', private=True)) if activation['schemaVersion'] == 2 else None
    return {'plan': plan, 'events': events, 'checkpoint': checkpoint,
            'privateConfig': selected['private-config'], 'authorization': selected['authorization'],
            'privateAuthorization': prepared, 'inputSnapshot': snapshot, 'activation': activation,
            'rawInputs': raw}


def retain_owned_observation(plan, events, checkpoint, activation):
    """Keep a private immutable original companion; never add it to a public artifact roster."""
    import os
    import cross_version_supervisor_authority as owner
    import runtime_baseline_approval as approvals
    selected, _ = owner.read_selected(owner.STATE, activation['ownerUid'])
    if not selected['authorization'].get('runtimeReference') and not selected['private-config'].get('runtimeBaseline'):
        return
    bundle = owned_bundle(plan, events, checkpoint, activation)
    root = approvals._private_directory(approvals.PRIVATE_STORE)
    directory = root / 'observations'
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / (plan['experimentId'] + '.json')
    raw = encode(bundle)
    if len(raw) > MAX_BYTES:
        raise AdmissionError('runtime-baseline-input-budget')
    if path.exists():
        if owner.secured(path, private=True).read_bytes() != raw:
            raise AdmissionError('runtime-baseline-retained-observation-substituted')
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def project_owned_baseline(plan, events, checkpoint, activation, *, authenticated_selection=None):
    """Construct the producer capability from root's stopped original execution context."""
    bundle = owned_bundle(plan, events, checkpoint, activation)
    selection = bundle['privateConfig']['runtimeBaseline']
    cutoff = dt.datetime.now(dt.timezone.utc).isoformat()
    if authenticated_selection is None:
        with tempfile.TemporaryDirectory(prefix='runtime-baseline-evaluate-') as scratch:
            authenticated_selection = authenticate_selected(selection, Path(scratch), cutoff=cutoff)
    proposal, approval, references = authenticated_selection
    attached = [event for event in events if 'runtimeEvidence' in event]
    if len(attached) != 1:
        raise AdmissionError('runtime-baseline-candidate-unverified')
    event = attached[0]
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
    from scheduler_pressure_runtime import derive_snapshot_fingerprints
    series = event['runtimeEvidence']['series']
    inputs = bundle['inputSnapshot']
    if inputs['fingerprint'] != series['fingerprint'] or any(series['fingerprint'][k] != v for k, v in derive_snapshot_fingerprints(inputs).items()):
        raise AdmissionError('runtime-baseline-original-snapshot-mismatch')
    observed = OriginalRuntimeObservation(_SEAL, {
        'planDigest': digest(plan), 'activationDigest': digest(activation), 'checkpointDigest': digest(checkpoint),
        'role': event['role'], 'epoch': event['nodeEpoch'], 'selection': selection,
        'startedAt': events[0]['wallTime'], 'finishedAt': events[-1]['wallTime'],
        'series': series, 'policy': event['runtimeEvidence']['policy'],
        'findings': verify(plan, events, checkpoint, now=baseline._time(cutoff))['findings'],
        'outcome': events[-1]['outcome']})
    capability = admit_candidate(proposal, approval, selection, observed, cutoff=cutoff, original_references=references)
    binding = {key: observed.values()[key] for key in ('planDigest', 'activationDigest', 'checkpointDigest', 'role', 'epoch')}
    binding.update(sourceCommit=series['fingerprint']['sourceCommit'], productDigest=series['fingerprint']['productDigest'])
    return {'authenticated_baseline': capability, 'baseline_binding': binding, 'now': baseline._time(cutoff)}
