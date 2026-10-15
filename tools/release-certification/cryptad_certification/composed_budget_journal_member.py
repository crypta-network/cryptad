"""Prospective private journal commitments; only original owners authenticate retained bytes.

Historical attachments, their eight-member limit, event budgets and public projections remain
unchanged. References are private checkpoint commitments, never authority or cohort verdicts.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re

from . import composed_budget_evidence as legacy
from . import composed_budget_route_evidence as routes
from . import composed_budget_storage_evidence as storage
from . import composed_budget_privacy_evidence as privacy
from .composed_budget_cohort_contract import STORAGE_VARIANTS, RESTART_VARIANTS

CAMPAIGN_ID = 'pr320-budget-full-cohort-v1'
MAX_RAW_BYTES = 8 * 1024 * 1024
MAX_INLINE_BYTES = 512 * 1024
INPUT_FIELDS = {'schemaVersion', 'kind', 'campaignId', 'members'}
DESCRIPTOR_FIELDS = {'member', 'kind', 'plannedVariants', 'collectorDigest', 'configurationDigest', 'producerDigest'}
REFERENCE_FIELDS = {'schemaVersion', 'kind', 'campaignId', 'member', 'digest', 'size', 'collectorEpoch', 'rawBase64'}
PRODUCER_KEYS = {'route-component': 'installedDriver', 'storage-component': 'installedDriver',
    'legacy-attachment': 'installedDriver', 'installed-privacy': 'installedDriver',
    'installed-browser-privacy': 'browserCollector', 'artifact-privacy': 'publicDescriptorReaders'}


def _need(condition, code):
    if not condition:
        raise ValueError('pr320-budget-journal-' + code)


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _profile(experiment):
    for index, name in enumerate(routes.PROFILE_NAMES):
        if experiment == 'pr320-routes-' + name:
            return [(index, 'route-component', [[row['caseId'], row['variant']] for row in routes.required_variants(name)])]
    if experiment == 'pr320-installed-owner-cancellation':
        return [(7, 'legacy-attachment', [['cancellation', 'deferred-normal-owner']])]
    for index, pair in enumerate(STORAGE_VARIANTS, 8):
        if experiment == 'pr320-storage-' + pair[0] + '-' + pair[1]:
            return [(index, 'storage-component', [list(pair)])]
    if experiment == 'pr320-installed-budget-privacy':
        return [(15, 'installed-privacy', [['privacy', 'native']]),
                (16, 'installed-browser-privacy', [['privacy', 'browser']]),
                (17, 'artifact-privacy', [['privacy', 'public-artifacts']])]
    if experiment == 'pr320-installed-restart-diagnostics':
        return [(18, 'legacy-attachment', [list(pair) for pair in RESTART_VARIANTS])]
    raise ValueError('pr320-budget-journal-experiment-unselected')


def campaign_inputs(plan, tool_identities):
    """Build the code-owned roster before original authorization freezes plan bytes."""
    inputs = plan['composedBudgetInputs']
    result = []
    for index, kind, variants in _profile(plan['experimentId']):
        result.append({'member': 'member-%02d.json' % index, 'kind': kind,
            'plannedVariants': variants, **inputs, 'producerDigest': tool_identities[PRODUCER_KEYS[kind]]})
        if kind == 'installed-browser-privacy':
            result[-1]['servedScriptDigest'] = tool_identities['webShellScript']
    return {'schemaVersion': 1, 'kind': 'pr320-private-budget-campaign-inputs',
            'campaignId': CAMPAIGN_ID, 'members': result}


def validate_inputs(plan):
    value = plan.get('budgetCampaignInputs')
    _need(isinstance(value, dict) and set(value) == INPUT_FIELDS
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'pr320-private-budget-campaign-inputs' and value['campaignId'] == CAMPAIGN_ID,
          'inputs-invalid')
    selected = _profile(plan.get('experimentId'))
    members = value['members']
    _need(isinstance(members, list) and len(members) == len(selected), 'roster-invalid')
    inputs = plan.get('composedBudgetInputs')
    _need(isinstance(inputs, dict) and set(inputs) == {'collectorDigest', 'configurationDigest'}, 'inputs-missing')
    for descriptor, (index, kind, variants) in zip(members, selected):
        fields = DESCRIPTOR_FIELDS | ({'servedScriptDigest'} if kind == 'installed-browser-privacy' else set())
        digests = ('collectorDigest', 'configurationDigest', 'producerDigest') + (
            ('servedScriptDigest',) if kind == 'installed-browser-privacy' else ())
        _need(isinstance(descriptor, dict) and set(descriptor) == fields
              and descriptor['member'] == 'member-%02d.json' % index and descriptor['kind'] == kind
              and descriptor['plannedVariants'] == variants
              and all(isinstance(descriptor[key], str) and re.fullmatch('sha256:[a-f0-9]{64}', descriptor[key])
                      for key in digests)
              and all(descriptor[key] == inputs[key] for key in inputs), 'descriptor-substituted')
    return members


def validate_selected_sources(plan, tool_identities):
    """Call with independently verified original selection, never member-supplied tool labels."""
    _need(plan.get('budgetCampaignInputs') == campaign_inputs(plan, tool_identities), 'selected-source-substituted')
    return validate_inputs(plan)


def _decode(raw):
    _need(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_RAW_BYTES, 'member-size-invalid')
    def unique(pairs):
        value = {}
        for key, child in pairs:
            _need(key not in value, 'duplicate-key')
            value[key] = child
        return value
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('pr320-budget-journal-number-invalid')))
    pending, count = [(value, 0)], 0
    while pending:
        child, depth = pending.pop(); count += 1
        _need(depth <= 32 and count <= 200000, 'member-tree-limit')
        if isinstance(child, dict): pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list): pending.extend((item, depth + 1) for item in child)
    _need(isinstance(value, dict), 'member-shape-invalid')
    return value


def validate_reference(plan, event):
    """Validate a private commitment without mistaking missing source bytes for evidence."""
    descriptors = validate_inputs(plan)
    reference = event.get('composedBudgetCampaignMember')
    _need(isinstance(reference, dict) and set(reference) == REFERENCE_FIELDS
          and type(reference['schemaVersion']) is int and reference['schemaVersion'] == 1
          and reference['kind'] == 'pr320-private-budget-campaign-member'
          and reference['campaignId'] == CAMPAIGN_ID
          and event.get('kind') == 'operation' and event.get('operation') == 'composed-budget-campaign-member'
          and event.get('role') == 'candidate-sender' and event.get('scenario') == 'app-budgets'
          and event.get('outcome') == 'partial' and isinstance(event.get('nodeEpoch'), str)
          and re.fullmatch('[a-f0-9]{32}', event['nodeEpoch'])
          and isinstance(reference['collectorEpoch'], str) and re.fullmatch('[a-f0-9-]{36}', reference['collectorEpoch'])
          and isinstance(reference['digest'], str) and re.fullmatch('sha256:[a-f0-9]{64}', reference['digest'])
          and type(reference['size']) is int and 1 <= reference['size'] <= MAX_RAW_BYTES,
          'reference-invalid')
    matches = [row for row in descriptors if row['member'] == reference['member']]
    _need(len(matches) == 1, 'member-unselected')
    legacy.pressure.baseline._time(event['wallTime'])
    inline = reference['rawBase64']
    if inline is not None:
        _need(isinstance(inline, str) and len(inline) <= 4 * ((MAX_INLINE_BYTES + 2) // 3), 'inline-size-invalid')
        try: raw = base64.b64decode(inline, validate=True)
        except (ValueError, UnicodeError): raise ValueError('pr320-budget-journal-base64-invalid') from None
        _need(base64.b64encode(raw).decode() == inline and len(raw) == reference['size']
              and len(raw) <= MAX_INLINE_BYTES and _digest(raw) == reference['digest'], 'inline-substituted')
        _decode(raw)
    return matches[0]


def _component(value, kind):
    # Privacy's existing exact file includes its selected private wrapper. Preserve
    # those wire bytes because the browser's nativeMemberDigest refers to that file.
    if kind == 'installed-privacy' and value.get('kind') == 'pr320-private-native-privacy':
        _need(set(value) == {'schemaVersion', 'kind', 'selectionDigest', 'component'}, 'privacy-wrapper-invalid')
        return value['component']
    return value


def _epoch(value, kind):
    component = _component(value, kind)
    if kind == 'route-component': return component['bindings']['collectorEpoch']
    if kind == 'storage-component':
        rows = component['storageCases']
        _need(len({row['collectorEpoch'] for row in rows}) <= 1, 'collector-substituted')
        return rows[0]['collectorEpoch'] if rows else None
    if kind in {'installed-privacy', 'installed-browser-privacy', 'artifact-privacy'}:
        if kind == 'installed-privacy': return component['surfaces']['workSnapshot']['collectorEpoch']
        return component.get('collectorEpoch')
    return component['collectorEpoch']


def append_member(journal, kind, raw, *, collector_epoch=None):
    """Emit an actual member after native collection using only the selected fixed slot."""
    matches = [row for row in validate_inputs(journal.plan) if row['kind'] == kind]
    _need(len(matches) == 1, 'producer-kind-unselected')
    value = _decode(raw)
    epoch = _epoch(value, kind) if collector_epoch is None else collector_epoch
    reference = {'schemaVersion': 1, 'kind': 'pr320-private-budget-campaign-member',
        'campaignId': CAMPAIGN_ID, 'member': matches[0]['member'], 'digest': _digest(raw),
        'size': len(raw), 'collectorEpoch': epoch,
        'rawBase64': base64.b64encode(raw).decode() if len(raw) <= MAX_INLINE_BYTES else None}
    from .cross_version_evidence import event_byte_limit
    # Existing scheduler line caps remain unchanged; leave bounded headroom for
    # the original checkpoint envelope rather than enlarge the historical limit.
    if len(json.dumps(reference, separators=(',', ':')).encode()) + 4096 > event_byte_limit(journal.plan):
        reference['rawBase64'] = None
    return journal.append('operation', role='candidate-sender', scenario='app-budgets', outcome='partial',
        operation='composed-budget-campaign-member', composed_budget_campaign_member=reference)


def resolve_journal_members(plan, events, *, members=None):
    """Recompute every supplied original; absent references remain locally unobserved."""
    descriptors = validate_inputs(plan)
    supplied = {} if members is None else members
    _need(isinstance(supplied, dict) and set(supplied) <= {row['member'] for row in descriptors}, 'source-roster-invalid')
    references = {}
    raws = {}
    for event in events:
        if 'composedBudgetCampaignMember' not in event: continue
        descriptor = validate_reference(plan, event); name = descriptor['member']
        _need(name not in references, 'member-replayed')
        reference = event['composedBudgetCampaignMember']; references[name] = event
        raw = supplied.get(name)
        inline = reference['rawBase64']
        if inline is not None:
            decoded = base64.b64decode(inline, validate=True)
            _need(raw is None or raw == decoded, 'source-inline-substituted')
            raw = decoded
        if raw is not None:
            _need(isinstance(raw, bytes) and len(raw) == reference['size'] and _digest(raw) == reference['digest'], 'source-substituted')
            raws[name] = raw
    _need(set(supplied) <= set(references), 'uncommitted-source')
    assessments = []
    for descriptor in descriptors:
        name, kind = descriptor['member'], descriptor['kind']
        event = references.get(name)
        if name not in raws:
            assessments.append({'member': name, 'kind': kind, 'status': 'not-observed',
                'reason': 'member-event-unobserved' if event is None else 'original-bytes-unavailable',
                'verifiedVariants': []})
            continue
        value = _component(_decode(raws[name]), kind)
        reference = event['composedBudgetCampaignMember']
        selected = next(row for row in plan['nodes'] if row['role'] == 'candidate-sender')
        _need(_epoch(value, kind) in {None, reference['collectorEpoch']}, 'collector-substituted')
        observed_at = event['wallTime']
        if kind == 'route-component':
            binding = value['bindings']
            expected = dict(binding, workloadDigest=plan['workloadInputs']['scheduler'],
                productDigest=selected['artifactDigest'], sourceCommit=selected['sourceCommit'],
                appCohortDigest=legacy.pressure.baseline.digest(selected['appDigests']),
                collectorDigest=descriptor['collectorDigest'], configurationDigest=descriptor['configurationDigest'],
                nodeEpoch=event['nodeEpoch'], collectorEpoch=reference['collectorEpoch'])
            result = routes.derive_complete_routes(value, expected, observation_time=observed_at)
            verified = [[row['caseId'], row['variant']] for row in result['verifiedVariants']]
        elif kind == 'storage-component':
            _need(all(row['nodeEpoch'] == event['nodeEpoch'] and row['collectorEpoch'] == reference['collectorEpoch']
                      for row in value['storageCases']), 'storage-epoch-substituted')
            result = storage.derive_complete_storage(value, observation_time=observed_at)
            verified = [[row['caseId'], row['variant']] for row in result['verifiedVariants']]
        elif kind == 'legacy-attachment':
            result = legacy.derive(value, workload_digest=plan['workloadInputs']['scheduler'],
                product_digest=selected['artifactDigest'], source_commit=selected['sourceCommit'],
                app_cohort_digest=legacy.pressure.baseline.digest(selected['appDigests']),
                node_epoch=event['nodeEpoch'], collector_digest=descriptor['collectorDigest'],
                configuration_digest=descriptor['configurationDigest'], observation_time=observed_at)
            if value['schemaVersion'] == 5:
                from . import composed_budget_restart_evidence as restart
                _need(all(restart.derive_controlled(row, observation_time=observed_at)['observed']
                          for row in value['restartCases'] + value['diagnosticsCases']), 'restart-original-invalid')
                verified = [[row['caseId'], row['variant']] for row in value['restartCases'] + value['diagnosticsCases']]
            else:
                _need(value['schemaVersion'] == 4 and value['segments'] == [] and value['storageCases'] == []
                      and len(value['causalCases']) <= 1 and all(row['caseId'] == 'cancellation' for row in value['causalCases']),
                      'owner-original-substituted')
                _need(all(row['caseId'] in result['observedCases'] for row in value['causalCases']), 'owner-original-invalid')
                verified = [['cancellation', 'deferred-normal-owner']] if 'cancellation' in result['observedCases'] else []
        else:
            if kind == 'installed-privacy':
                privacy.verify_installed(value)
                routes._native_history(value['surfaces']['workSnapshot'], observed_at)
            else:
                native_refs = [row for row in descriptors if row['kind'] == 'installed-privacy']
                _need(len(native_refs) == 1, 'privacy-native-missing')
                if native_refs[0]['member'] not in raws:
                    assessments.append({'member': name, 'kind': kind, 'status': 'not-observed',
                        'reason': 'original-dependency-unavailable', 'verifiedVariants': []})
                    continue
                native_raw = raws[native_refs[0]['member']]
                native = _component(_decode(native_raw), 'installed-privacy')
                _need(_epoch(native, 'installed-privacy') == reference['collectorEpoch'], 'privacy-collector-substituted')
                if kind == 'installed-browser-privacy':
                    privacy.verify_installed_browser(value, native, native_digest=_digest(native_raw), script_digest=descriptor['servedScriptDigest'])
                else:
                    privacy.verify_artifacts(value, native, native_digest=_digest(native_raw), source_commit=selected['sourceCommit'])
            verified = descriptor['plannedVariants']
        _need(all(row in descriptor['plannedVariants'] for row in verified), 'unselected-variant')
        assessments.append({'member': name, 'kind': kind, 'status': 'locally-verified' if verified else 'not-observed',
                            'reason': None if verified else 'planned-variants-unobserved',
                            'verifiedVariants': verified})
    return {'schemaVersion': 1, 'kind': 'pr320-private-journal-member-assessment',
        'campaignId': CAMPAIGN_ID, 'members': assessments, 'originalAuthentication': 'not-established',
        'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}
