"""Finite exact-member budget composition; public summaries are never evidence inputs.

The local entry point recomputes native owner records and preserves attempted failures. Original
protected admission belongs to a separate authenticated owner; serialized local coverage cannot
promote itself. Historical attachment schemas and journal limits remain unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re

from . import composed_budget_evidence as legacy
from . import composed_budget_storage_evidence as storage
from . import composed_budget_restart_evidence as restart
from . import composed_budget_privacy_evidence as privacy
from . import composed_budget_route_evidence as routes
from .composed_budget_cohort_contract import REQUIRED_VARIANTS

MAX_MEMBERS = 64
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_CAMPAIGN_BYTES = 32 * 1024 * 1024
SUBJECT_FIELDS = {'productDigest', 'sourceCommit', 'appCohortDigest', 'workloadDigest', 'contractVersion'}
BINDING_FIELDS = {'collectorDigest', 'configurationDigest', 'nodeEpoch', 'collectorEpoch',
                  'role', 'producerDigest', 'observedAt', 'workloadDigest'}
BROWSER_KINDS = {'browser-privacy', 'installed-browser-privacy'}
KINDS = {'legacy-attachment', 'storage-component', 'route-component', 'native-privacy',
         'installed-privacy', 'browser-privacy', 'installed-browser-privacy', 'artifact-privacy'}


def binding_fields(kind):
    return BINDING_FIELDS | ({'servedScriptDigest'} if kind in BROWSER_KINDS else set())


def _need(condition, reason):
    if not condition:
        raise legacy.ComposedEvidenceError('composed-budget-campaign-' + reason)


def _closed(value, fields):
    _need(isinstance(value, dict) and set(value) == fields, 'fields-invalid')


def _decode(raw):
    def unique(pairs):
        value = {}
        for key, child in pairs:
            _need(key not in value, 'duplicate-field')
            value[key] = child
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: _need(False, 'number-invalid'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _need(False, 'member-json-invalid')
    pending, count = [(value, 0)], 0
    while pending:
        child, depth = pending.pop()
        count += 1
        _need(depth <= 32 and count <= 200000, 'member-tree-limit')
        if isinstance(child, dict): pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list): pending.extend((item, depth + 1) for item in child)
    return value


def _streams(value, kind, node_epoch):
    """Return complete immutable streams for replay checks, scoped to the actual daemon epoch."""
    result = []
    if kind == 'route-component':
        return _streams(value['attachment'], 'legacy-attachment', node_epoch)
    if kind == 'storage-component':
        for row in value['storageCases']:
            result.append((row['nodeEpoch'], row['collectorEpoch'], row['events']))
    elif kind == 'legacy-attachment':
        for row in value.get('segments', []) + value.get('causalCases', []) + value.get('storageCases', []):
            result.append((value.get('nodeEpoch'), row['collectorEpoch'], row['events']))
        for row in value.get('restartCases', []) + value.get('diagnosticsCases', []):
            for phase in ('before', 'during', 'after', 'recovery'):
                if phase in row:
                    sample = row[phase]
                    result.append((node_epoch, sample['collectorEpoch'], sample['nativeSnapshot']['events']))
    # Privacy work snapshots intentionally reference already collected causal work. They are
    # checked by their owner and cannot provide additional route/cancellation/storage credit.
    return result


def _variants(value, result, kind):
    if kind in {'native-privacy', 'installed-privacy', 'browser-privacy', 'installed-browser-privacy', 'artifact-privacy'}:
        return {('privacy', {'native-privacy': 'native', 'installed-privacy': 'native',
            'browser-privacy': 'browser', 'installed-browser-privacy': 'browser',
            'artifact-privacy': 'public-artifacts'}[kind])}
    if kind in {'storage-component', 'route-component'}:
        return {(row['caseId'], row['variant']) for row in result['verifiedVariants']}
    observed, variants = set(result['observedCases']), set()
    variants.update((row['caseId'], 'native-route') for row in value.get('segments', [])
                    if row['caseId'] in observed and row['caseId'] != 'authorization-denied')
    for row in value.get('causalCases', []):
        case = row['caseId']
        if case not in observed: continue
        if case in {'import-concurrency', 'fetch-concurrency'}:
            limits = [event for event in row['events'] if event['kind'] == 'CONCURRENCY_LIMIT_REACHED']
            _need(len(limits) == 1, 'limiting-family-invalid')
            variant = 'global' if limits[0]['scope'] == 1 else 'app'
        else:
            variant = 'independently-charged' if case == 'retry' else 'deferred-normal-owner'
        variants.add((case, variant))
    if value.get('schemaVersion') == 5:
        for row in value['restartCases'] + value['diagnosticsCases']:
            if restart.derive_controlled(row)['observed']:
                variants.add((row['caseId'], row['variant']))
    # Historical v4's three representative storage cases cannot supply complete variant credit.
    return variants


def derive_campaign(selection, members, *, expected_subject, expected_bindings):
    """Recompute an exact finite local campaign against independently selected identities.

    ``members`` contains original private bytes, not uploaded coverage projections. The expected
    subject and per-member bindings come from the owning selection. Direct calls remain local
    consistency calculations, including synthetic test vectors; they confer no authentication.
    """
    _closed(selection, {'schemaVersion', 'kind', 'evidenceClass', 'subject', 'members', 'attempts'})
    _need(type(selection['schemaVersion']) is int and selection['schemaVersion'] == 1
          and selection['kind'] == 'composed-budget-campaign'
          and selection['evidenceClass'] in {'synthetic-local-cohort', 'installed-cohort-local-consistency'},
          'selection-invalid')
    subject = selection['subject']
    _closed(subject, SUBJECT_FIELDS)
    _need(subject == expected_subject and type(subject['contractVersion']) is int
          and subject['contractVersion'] >= 25 and re.fullmatch('[0-9a-f]{40}', str(subject['sourceCommit']))
          and all(re.fullmatch('sha256:[0-9a-f]{64}', str(subject[key])) for key in
                  SUBJECT_FIELDS - {'sourceCommit', 'contractVersion'}), 'subject-substituted')
    descriptors = selection['members']
    _need(isinstance(descriptors, list) and 0 < len(descriptors) <= MAX_MEMBERS
          and isinstance(members, dict) and isinstance(expected_bindings, dict), 'member-roster-invalid')
    names = [row.get('member') for row in descriptors if isinstance(row, dict)]
    _need(len(names) == len(descriptors) == len(set(names))
          and all(isinstance(name, str) and re.fullmatch(r'member-[0-9]{2}\.json', name) for name in names)
          and set(names) == set(members) == set(expected_bindings), 'member-roster-invalid')
    _need(subject['workloadDigest'] == legacy.pressure.baseline.digest(
        {name: expected_bindings[name].get('workloadDigest') for name in sorted(names)}),
        'workload-roster-substituted')
    total, observed_variants, planned, seen_events, seen_operations = 0, set(), set(), {}, {}
    results = {}
    for descriptor in descriptors:
        _closed(descriptor, {'member', 'kind', 'digest', 'size', 'binding', 'plannedVariants'})
        name, kind, binding = descriptor['member'], descriptor['kind'], descriptor['binding']
        _closed(binding, binding_fields(kind))
        _need(kind in KINDS and binding == expected_bindings[name]
              and binding['role'] == 'candidate-sender'
              and re.fullmatch('[0-9a-f]{32}', str(binding['nodeEpoch']))
              and re.fullmatch('[0-9a-f-]{36}', str(binding['collectorEpoch']))
              and all(re.fullmatch('sha256:[0-9a-f]{64}', str(binding[key])) for key in
                      ('collectorDigest', 'configurationDigest', 'producerDigest', 'workloadDigest')), 'binding-substituted')
        observed_at = legacy.pressure.baseline._time(binding['observedAt'])
        if kind in BROWSER_KINDS:
            _need(re.fullmatch('sha256:[0-9a-f]{64}', str(binding['servedScriptDigest'])),
                  'served-script-binding-invalid')
        selected_variants = descriptor['plannedVariants']
        _need(isinstance(selected_variants, list) and selected_variants
              and all(isinstance(row, list) and len(row) == 2 and tuple(row) in REQUIRED_VARIANTS
                      for row in selected_variants)
              and len(selected_variants) == len({tuple(row) for row in selected_variants}), 'variant-selection-invalid')
        planned.update(tuple(row) for row in selected_variants)
        raw = members[name]
        _need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MEMBER_BYTES
              and type(descriptor['size']) is int and descriptor['size'] == len(raw)
              and descriptor['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest(), 'member-substituted')
        total += len(raw)
        _need(total <= MAX_CAMPAIGN_BYTES, 'byte-limit')
        value = _decode(raw)
        if kind == 'installed-privacy' and value.get('kind') == 'pr320-private-native-privacy':
            # The original browser binds the retained native wrapper's exact file bytes.
            # Verify its closed owner wrapper before using the embedded native controls.
            value = privacy._installed_privacy_owner().decode_private(raw)['component']
        if kind == 'legacy-attachment':
            result = legacy.derive(value, workload_digest=binding['workloadDigest'],
                product_digest=subject['productDigest'], source_commit=subject['sourceCommit'],
                app_cohort_digest=subject['appCohortDigest'],
                node_epoch=binding['nodeEpoch'] if value.get('schemaVersion') != 1 else None,
                collector_digest=binding['collectorDigest'], configuration_digest=binding['configurationDigest'],
                observation_time=binding['observedAt'])
            if value['schemaVersion'] >= 2:
                _need(value.get('collectorEpoch') == binding['collectorEpoch'], 'collector-substituted')
            _need(all(row['caseId'] in result['observedCases'] for family in
                      ('segments', 'causalCases', 'storageCases')
                      for row in value.get(family, [])), 'supplied-native-invalid')
            _need(all(restart.derive_controlled(row)['observed'] for family in
                      ('restartCases', 'diagnosticsCases') for row in value.get(family, [])),
                  'supplied-restart-invalid')
            _need(selection['evidenceClass'] == 'synthetic-local-cohort' or value['schemaVersion'] != 1,
                  'historical-process-binding-required')
        elif kind == 'route-component':
            selected = value.get('bindings', {})
            _need(all(selected.get(key) == subject[key] for key in SUBJECT_FIELDS - {'contractVersion', 'workloadDigest'})
                  and all(selected.get(key) == binding[key] for key in
                          ('collectorDigest', 'configurationDigest', 'nodeEpoch', 'collectorEpoch', 'workloadDigest')),
                  'route-binding-substituted')
            result = routes.derive_complete_routes(value, observation_time=binding['observedAt'])
        elif kind == 'storage-component':
            result = storage.derive_complete_storage(value, observation_time=binding['observedAt'])
            _need(all(row['nodeEpoch'] == binding['nodeEpoch'] and row['collectorEpoch'] == binding['collectorEpoch']
                      for row in value['storageCases']), 'storage-epoch-substituted')
        elif kind == 'native-privacy':
            result = privacy.verify_native(value)
            _need(value['surfaces']['workSnapshot']['collectorEpoch'] == binding['collectorEpoch'],
                  'privacy-epoch-substituted')
            _need(selection['evidenceClass'] == 'synthetic-local-cohort', 'native-is-not-installed')
        elif kind == 'installed-privacy':
            result = privacy.verify_installed(value)
            _need(value['surfaces']['workSnapshot']['collectorEpoch'] == binding['collectorEpoch'],
                  'installed-privacy-epoch-substituted')
        else:
            references = [row for row in descriptors if row['kind'] in {'native-privacy', 'installed-privacy'}
                          and row['digest'] == value.get('nativeMemberDigest')]
            _need(len(references) == 1, 'privacy-native-reference-invalid')
            native = _decode(members[references[0]['member']])
            native_binding = references[0]['binding']
            _need(all(binding[key] == native_binding[key] for key in
                      ('nodeEpoch', 'collectorEpoch', 'collectorDigest', 'configurationDigest', 'workloadDigest')),
                  'privacy-reference-scope-substituted')
            if references[0]['kind'] == 'installed-privacy' and native.get('kind') == 'pr320-private-native-privacy':
                native = privacy._installed_privacy_owner().decode_private(members[references[0]['member']])['component']
            if kind == 'installed-browser-privacy':
                _need(references[0]['kind'] == 'installed-privacy', 'browser-evidence-class-substituted')
                result = privacy.verify_installed_browser(value, native,
                    native_digest=value['nativeMemberDigest'], script_digest=binding['servedScriptDigest'])
            elif kind == 'browser-privacy':
                _need(references[0]['kind'] == 'native-privacy', 'browser-evidence-class-substituted')
                result = privacy.verify_browser(value, native, native_digest=value['nativeMemberDigest'],
                                                script_digest=binding['servedScriptDigest'])
            else:
                result = privacy.verify_artifacts(value, native, native_digest=value['nativeMemberDigest'],
                                                  source_commit=subject['sourceCommit'])
            if kind == 'browser-privacy':
                _need(selection['evidenceClass'] == 'synthetic-local-cohort', 'local-export-is-not-installed')
        variants = _variants(value, result, kind)
        _need(variants <= {tuple(row) for row in selected_variants}, 'unselected-variant')
        observed_variants.update(variants)
        results[name] = variants
        own_events, own_operations = set(), set()
        for node, epoch, events in _streams(value, kind, binding['nodeEpoch']):
            for event in events:
                _need(legacy.pressure.baseline._time(event['observedAt']) <= observed_at, 'event-time-invalid')
                identity = (binding['role'], node, epoch, event['sequence'])
                _need(identity not in seen_events or seen_events[identity] == name, 'event-replayed')
                own_events.add(identity)
                if event['operationId']:
                    own_operations.add((binding['role'], node, epoch, event['operationId']))
        _need(not any(identity in seen_operations for identity in own_operations), 'operation-replayed')
        seen_events.update((identity, name) for identity in own_events)
        seen_operations.update((identity, name) for identity in own_operations)
        if kind in {'native-privacy', 'installed-privacy'}:
            for event in value['surfaces']['workSnapshot']['events']:
                _need(legacy.pressure.baseline._time(event['observedAt']) <= observed_at, 'privacy-time-invalid')
    attempts = selection['attempts']
    _need(isinstance(attempts, list) and len(attempts) == len(names), 'attempt-roster-invalid')
    failed, seen_attempts = False, set()
    for attempt in attempts:
        _closed(attempt, {'member', 'attempt', 'outcome'})
        _need(attempt['member'] in results and attempt['member'] not in seen_attempts
              and type(attempt['attempt']) is int and attempt['attempt'] > 0
              and attempt['outcome'] in {'observed', 'censored', 'failed', 'setup-failed', 'interrupted'},
              'attempt-invalid')
        seen_attempts.add(attempt['member'])
        if attempt['outcome'] not in {'observed', 'censored'}:
            failed = True
        if attempt['outcome'] == 'censored':
            _need(results[attempt['member']] == {('abrupt-restart', 'inflight-abrupt')}, 'censoring-substituted')
    # Omitted planned variants fail selection, rather than improving completeness by N/A.
    _need(planned == set(REQUIRED_VARIANTS), 'planned-cohort-incomplete')
    observed = {case for case in legacy.REQUIRED_CASES if
                {pair for pair in REQUIRED_VARIANTS if pair[0] == case} <= observed_variants}
    missing_variants = set(REQUIRED_VARIANTS) - observed_variants
    return {'schemaVersion': 1, 'kind': 'composed-budget-campaign-coverage',
            'evidenceClass': selection['evidenceClass'], 'requiredCases': list(legacy.REQUIRED_CASES),
            'observedCases': sorted(observed), 'missingCases': sorted(set(legacy.REQUIRED_CASES) - observed),
            'verifiedVariants': [list(pair) for pair in sorted(observed_variants)],
            'missingVariants': [list(pair) for pair in sorted(missing_variants)],
            'budgetCohortStatus': 'complete-local' if not missing_variants and not failed else 'incomplete',
            'failedAttemptsRetained': failed, 'originalAuthentication': 'not-established',
            'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}


def validate_coverage(value):
    """Validate public facts only; a serialized original verdict grants no capability."""
    _closed(value, {'schemaVersion', 'kind', 'evidenceClass', 'requiredCases', 'observedCases',
        'missingCases', 'verifiedVariants', 'missingVariants', 'budgetCohortStatus',
        'failedAttemptsRetained', 'originalAuthentication', 'fullAppBudgets', 'releaseEligible', 'phaseComplete'})
    _need(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'composed-budget-campaign-coverage'
          and value['requiredCases'] == list(legacy.REQUIRED_CASES)
          and type(value['failedAttemptsRetained']) is bool
          and value['releaseEligible'] is False and value['phaseComplete'] is False, 'coverage-invalid')
    pairs = value['verifiedVariants']
    _need(isinstance(pairs, list) and all(isinstance(pair, list) and len(pair) == 2
          and tuple(pair) in REQUIRED_VARIANTS for pair in pairs)
          and pairs == sorted(map(list, {tuple(pair) for pair in pairs})), 'coverage-variants-invalid')
    supplied = {tuple(pair) for pair in pairs}
    missing = set(REQUIRED_VARIANTS) - supplied
    cases = {case for case in legacy.REQUIRED_CASES if
             {pair for pair in REQUIRED_VARIANTS if pair[0] == case} <= supplied}
    _need(value['observedCases'] == sorted(cases)
          and value['missingCases'] == sorted(set(legacy.REQUIRED_CASES) - cases)
          and value['missingVariants'] == sorted(map(list, missing)), 'coverage-roster-invalid')
    original = value['evidenceClass'] in {'original-protected-budget-cohort',
                                        'original-protected-source-built-budget-cohort'}
    _need(original or value['evidenceClass'] in {'synthetic-local-cohort', 'installed-cohort-local-consistency'},
          'coverage-class-invalid')
    complete = not missing and not value['failedAttemptsRetained']
    _need(value['budgetCohortStatus'] == ('complete-original' if original and complete else
                                         'complete-local' if complete else 'incomplete')
          and value['originalAuthentication'] == ('authenticated' if original else 'not-established')
          and value['fullAppBudgets'] == ('observed' if original and complete else 'not-observed'),
          'coverage-authority-invalid')
    return value
