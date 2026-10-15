"""Closed route-variant admission delegates each original historical v4 native record."""
from __future__ import annotations
import copy
import re
from . import composed_budget_evidence as owner
from . import runtime_pressure_evidence as pressure

MAIN_CASES = tuple(('direct-valid direct-malformed pasted-preview-valid uri-preview-valid '
    'uri-preview-malformed uri-valid uri-malformed uri-fingerprint-mismatch uri-duplicate '
    'authorization-denied invalid-uri invalid-utf8 oversized').split())
INTERFERENCE_CASES = ('app-import-rate', 'global-import-rate', 'app-fetch-rate', 'global-fetch-rate',
                      'shared-foreground', 'shared-subscription')
PROFILE_NAMES = ('main', 'interference', 'import-app', 'import-global', 'fetch-app', 'fetch-global', 'lifecycle')
APP_IDS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')
BINDING_FIELDS = {'workloadDigest', 'productDigest', 'sourceCommit', 'appCohortDigest',
    'collectorDigest', 'configurationDigest', 'nodeEpoch', 'collectorEpoch', 'selectionDigest', 'appBundleDigests'}
FIELDS = {'schemaVersion', 'kind', 'profile', 'evidenceClass', 'bindings', 'attachment',
          'observations', 'attempts', 'transportControls', 'scopeBindings', 'finalSnapshot'}
ROW_FIELDS = {'caseId', 'variant', 'appId', 'scope', 'recordKind', 'recordIndex', 'responseStatus', 'responseCode'}


def required_variants(profile):
    if profile not in PROFILE_NAMES:
        raise ValueError('pr320-route-profile-invalid')
    cases = (MAIN_CASES if profile == 'main' else INTERFERENCE_CASES if profile == 'interference'
             else ('timeout', 'retry') if profile == 'lifecycle' else
             ('import-concurrency' if profile.startswith('import') else 'fetch-concurrency',))
    result = []
    for case in cases:
        variants = (('no-trust', 'no-fetch') if case == 'authorization-denied' else
            (profile.rsplit('-', 1)[1],) if case.endswith('concurrency') else
            ('deferred-normal-owner',) if case == 'timeout' else
            ('independently-charged',) if case == 'retry' else ('native-route',))
        result.extend({'caseId': case, 'variant': variant} for variant in variants)
    return result


def _need(condition, code):
    if not condition:
        raise ValueError('pr320-route-' + code)


def _derive(attachment, bindings, observation_time=None):
    return owner.derive(attachment, workload_digest=bindings['workloadDigest'],
        product_digest=bindings['productDigest'], source_commit=bindings['sourceCommit'],
        app_cohort_digest=bindings['appCohortDigest'], collector_digest=bindings['collectorDigest'],
        configuration_digest=bindings['configurationDigest'], node_epoch=bindings['nodeEpoch'])


def derive_complete_routes(component, expected_bindings=None, *, observation_time=None):
    """Revalidate every supplied row and required variant; local consistency grants no authority."""
    _need(isinstance(component, dict) and set(component) == FIELDS
          and type(component['schemaVersion']) is int and component['schemaVersion'] == 1 and component['kind'] == 'pr320-complete-route-component'
          and component['evidenceClass'] in {'controlled-native-file-backed', 'installed-controller-bound'}, 'shape-invalid')
    required = required_variants(component['profile'])
    expected_pairs = {(row['caseId'], row['variant']) for row in required}
    binding = component['bindings']
    _need(isinstance(binding, dict) and set(binding) == BINDING_FIELDS, 'bindings-invalid')
    _need(all(pressure.baseline.DIGEST.fullmatch(str(binding[key])) for key in
        BINDING_FIELDS - {'sourceCommit', 'nodeEpoch', 'collectorEpoch', 'appBundleDigests'})
        and re.fullmatch('[a-f0-9]{40}', str(binding['sourceCommit']))
        and re.fullmatch('[a-f0-9]{32}', str(binding['nodeEpoch']))
        and re.fullmatch('[a-f0-9-]{36}', str(binding['collectorEpoch']))
        and isinstance(binding['appBundleDigests'], dict) and set(binding['appBundleDigests']) == set(APP_IDS)
        and all(pressure.baseline.DIGEST.fullmatch(str(value)) for value in binding['appBundleDigests'].values())
        and binding['appCohortDigest'] == pressure.baseline.digest(
            [binding['appBundleDigests'][app] for app in APP_IDS]), 'bindings-invalid')
    if expected_bindings is not None:
        _need(binding == expected_bindings, 'selected-bindings-substituted')
    attachment = component['attachment']
    _need(isinstance(attachment, dict) and type(attachment.get('schemaVersion')) is int and attachment.get('schemaVersion') == 4
          and attachment.get('storageCases') == [] and attachment.get('collectorEpoch') == binding['collectorEpoch'],
          'historical-version-substituted')
    _derive(attachment, binding, observation_time)
    _need(len(attachment['segments']) <= 20 and len(attachment['causalCases']) <= 2, 'record-limit')
    for family in ('segments', 'causalCases'):
        for original in attachment[family]:
            one = copy.deepcopy(attachment)
            one['segments'], one['causalCases'] = [], []
            one[family] = [original]
            _need(_derive(one, binding, observation_time)['observedCases'] == [original['caseId']], 'orphan-native-invalid')
    scopes = component['scopeBindings']
    _need(isinstance(scopes, dict) and len(scopes) <= 4
          and all(isinstance(key, str) and key.isdecimal() and int(key) >= 3 and app in APP_IDS
                  for key, app in scopes.items()) and len(set(scopes.values())) == len(scopes), 'scope-invalid')
    observations, attempts = component['observations'], component['attempts']
    _need(isinstance(observations, list) and len(observations) <= len(required)
          and isinstance(attempts, list) and len(attempts) == len(required), 'attempts-invalid')
    attempted = {}
    for attempt in attempts:
        _need(isinstance(attempt, dict) and set(attempt) in (
            {'caseId', 'variant', 'status'}, {'caseId', 'variant', 'status', 'reason', 'responseStatus'})
            and attempt['status'] in {'executed', 'not-observed'}, 'attempt-invalid')
        pair = attempt['caseId'], attempt['variant']
        _need(pair in expected_pairs and pair not in attempted, 'attempt-replayed')
        if 'reason' in attempt:
            _need(attempt['reason'] is None if attempt['status'] == 'executed' else isinstance(attempt['reason'], str),
                  'attempt-reason-invalid')
            _need(attempt['responseStatus'] is None or type(attempt['responseStatus']) is int
                  and 100 <= attempt['responseStatus'] <= 599, 'attempt-response-invalid')
        if attempt['status'] == 'not-observed':
            _need(attempt['caseId'] == 'timeout' and attempt.get('reason') in {
                'request-did-not-time-out', 'delayed-owner-tail-not-observed', 'retained-slot-not-denied',
                'normal-owner-ack-unobserved', 'timeout-recovery-failed', 'timeout-operation-identities-missing'},
                'attempt-reason-invalid')
        attempted[pair] = attempt
    seen, references, verified = set(), set(), []
    for row in observations:
        _need(isinstance(row, dict) and set(row) == ROW_FIELDS, 'observation-invalid')
        pair = row['caseId'], row['variant']
        _need(pair in expected_pairs and pair not in seen and attempted[pair]['status'] == 'executed', 'variant-replayed')
        seen.add(pair)
        _need(type(row['scope']) is int and type(row['responseStatus']) is int
              and row['responseCode'] in {None, 'forbidden'}
              and row['appId'] in APP_IDS and scopes.get(str(row['scope'])) == row['appId']
              and row['recordKind'] in {'segment', 'causal'} and type(row['recordIndex']) is int, 'scope-substituted')
        family = 'segments' if row['recordKind'] == 'segment' else 'causalCases'
        index = row['recordIndex']
        reference = family, index
        _need(reference not in references and 0 <= index < len(attachment[family]), 'record-replayed')
        references.add(reference)
        original = attachment[family][index]
        _need(original['caseId'] == row['caseId'] and original['scope'] == row['scope'], 'record-substituted')
        one = copy.deepcopy(attachment)
        one['segments'], one['causalCases'] = [], []
        one[family] = [original]
        _need(_derive(one, binding, observation_time)['observedCases'] == [row['caseId']], 'native-record-invalid')
        if row['caseId'] == 'authorization-denied':
            app = APP_IDS[2] if row['variant'] == 'no-trust' else APP_IDS[3]
            _need(row['appId'] == app and row['responseStatus'] == 403 and row['responseCode'] == 'forbidden',
                  'capability-direction-substituted')
        elif row['caseId'].endswith('concurrency'):
            denied = [event for event in original['events'] if event['kind'] == 'CONCURRENCY_LIMIT_REACHED']
            _need(len(denied) == 1 and (denied[0]['scope'] == 1) == (row['variant'] == 'global')
                  and row['appId'] == (APP_IDS[0] if row['variant'] == 'app' else APP_IDS[1])
                  and row['responseStatus'] == 429, 'concurrency-direction-substituted')
        elif row['caseId'] == 'timeout':
            _need(row['responseStatus'] in {502, 504} and original['ownerOutcome'] == 'normal-ack', 'timeout-outcome-invalid')
        elif row['caseId'] == 'retry':
            _need(row['responseStatus'] == 200 and original['requestOutcome'] == 'response-lost-retry-succeeded',
                  'retry-outcome-invalid')
        else:
            expected_status = (429 if row['caseId'].endswith('rate') else 400 if row['caseId'] in {
                'direct-malformed', 'uri-preview-malformed', 'uri-malformed', 'invalid-uri'} else
                409 if row['caseId'] == 'uri-fingerprint-mismatch' else 415 if row['caseId'] == 'invalid-utf8'
                else 502 if row['caseId'] == 'oversized' else 200)
            _need(row['responseStatus'] == expected_status, 'response-substituted')
        verified.append({'caseId': pair[0], 'variant': pair[1]})
    _need(all(attempt['status'] == 'not-observed' or pair in seen for pair, attempt in attempted.items()),
          'executed-original-missing')
    supports = {'direct-valid', 'direct-malformed', 'uri-valid'} if component['profile'] == 'interference' else set()
    for family in ('segments', 'causalCases'):
        for index, original in enumerate(attachment[family]):
            if (family, index) not in references:
                _need(family == 'segments' and original['caseId'] in supports, 'orphan-record-unselected')
    final = component['finalSnapshot']
    _need(isinstance(final, dict) and final.get('work', {}).get('known') is True
          and final['work'].get('collectorEpoch') == binding['collectorEpoch'] and type(final['work'].get('dropped')) is int
          and final['work'].get('dropped') == 0 and final.get('budget', {}).get('valid') is True
          and all(type(final['budget'].get(key)) is int and final['budget'][key] >= 0
                  for key in ('activeFamilyLeases', 'reservedFamilyRates'))
          and (seen != expected_pairs or final['budget']['activeFamilyLeases'] == 0
               and final['budget']['reservedFamilyRates'] == 0)
          and pressure.baseline.digest(final.get('budgetConfiguration')) ==
              pressure.baseline.digest(native_configuration(component['profile']))
          and final.get('schedulerConfiguration', {}).get('enabled') is False, 'final-native-unavailable')
    original_events = _native_history(final['work'], observation_time)
    _need(all(original_events.get(event['sequence']) == event for record in
        attachment['segments'] + attachment['causalCases'] for event in record['events']), 'final-native-substituted')
    controls = component['transportControls']
    _need(isinstance(controls, list) and len(controls) == (2 if component['profile'] == 'main' else 0), 'transport-controls-missing')
    for control in controls:
        _need(isinstance(control, dict) and set(control) == {'kind', 'status', 'before', 'after'}
              and control['kind'] in {'other-app-origin', 'invalid-session'}
              and type(control['status']) is int and control['status'] == (403 if control['kind'] == 'other-app-origin' else 401)
              and isinstance(control['before'], dict) and set(control['before']) == {
                  'sequence', 'budgetValid', 'droppedEvents', 'rates', 'holds', 'retainedStatements'}
              and type(control['before']['sequence']) is int and control['before']['sequence'] >= 0
              and control['before']['sequence'] <= final['work']['lastSequence']
              and control['before']['budgetValid'] is True and type(control['before']['droppedEvents']) is int
              and control['before']['droppedEvents'] == 0 and control['before']['holds'] == []
              and isinstance(control['before']['rates'], list)
              and control['before'] == control['after'], 'transport-control-invalid')
    if controls: _need(len({row['kind'] for row in controls}) == 2, 'transport-control-replayed')
    return {'schemaVersion': 1, 'kind': 'pr320-route-profile-coverage',
        'status': 'complete' if seen == expected_pairs else 'incomplete', 'requiredVariants': required,
        'verifiedVariants': sorted(verified, key=lambda row: (row['caseId'], row['variant'])),
        'missingVariants': [row for row in required if (row['caseId'], row['variant']) not in seen],
        'evidenceClass': component['evidenceClass'], 'originalAuthentication': 'not-established',
        'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}


def native_configuration(profile):
    """Closed configuration is independent of caller labels and campaign summaries."""
    required_variants(profile)
    result = {'foregroundContentFetchPerAppPerMinute': 32, 'foregroundContentFetchGlobalPerMinute': 64,
        'foregroundContentFetchConcurrentPerApp': 2, 'foregroundContentFetchConcurrentGlobal': 1,
        'subscriptionPollPerAppPerHour': 48, 'subscriptionPollGlobalPerHour': 1024,
        'subscriptionPollConcurrentPerApp': 1, 'subscriptionPollConcurrentGlobal': 8,
        'trustGraphImportPerAppPerHour': 32, 'trustGraphImportGlobalPerHour': 64,
        'trustGraphImportConcurrentPerApp': 1, 'trustGraphImportConcurrentGlobal': 4}
    if profile in {'main', 'interference'}:
        result.update(foregroundContentFetchConcurrentGlobal=8, trustGraphImportConcurrentPerApp=2,
                      trustGraphImportConcurrentGlobal=8)
    if profile == 'interference':
        result.update(foregroundContentFetchPerAppPerMinute=3, foregroundContentFetchGlobalPerMinute=5,
                      trustGraphImportPerAppPerHour=4, trustGraphImportGlobalPerHour=6)
    elif profile == 'import-app': result['foregroundContentFetchConcurrentGlobal'] = 8
    elif profile == 'import-global':
        result.update(foregroundContentFetchConcurrentGlobal=8, trustGraphImportConcurrentPerApp=2,
                      trustGraphImportConcurrentGlobal=1)
    elif profile == 'fetch-app':
        result.update(foregroundContentFetchConcurrentPerApp=1, foregroundContentFetchConcurrentGlobal=8,
                      trustGraphImportConcurrentPerApp=2)
    return result


def _native_history(work, observation_time=None):
    events = work.get('events')
    _need(isinstance(events, list) and len(events) <= 2048 and type(work.get('lastSequence')) is int
          and len(events) == work['lastSequence'], 'final-native-prefix-invalid')
    previous = None
    for index, event in enumerate(events):
        owner._closed(event, pressure.EVENT_FIELDS)
        _need(event['kind'] in pressure.KINDS | owner.COMPOSED_KINDS | owner.CAUSAL_KINDS | owner.STORAGE_KINDS
              and event['operation'] in pressure.OPERATIONS
              and all(pressure._number(event[key]) for key in pressure.EVENT_FIELDS -
                      {'observedAt', 'kind', 'operation', 'sourceEpoch'})
              and event['sequence'] == index + 1
              and (event['sourceEpoch'] is None or isinstance(event['sourceEpoch'], str)
                   and re.fullmatch('[a-zA-Z0-9._-]{1,96}', event['sourceEpoch'])), 'final-native-event-invalid')
        stamp = pressure.baseline._time(event['observedAt'])
        _need(observation_time is None or stamp <= pressure.baseline._time(observation_time),
              'final-native-future-event')
        _need(previous is None or stamp >= pressure.baseline._time(previous['observedAt'])
              and event['elapsedNanos'] >= previous['elapsedNanos'], 'final-native-order-invalid')
        previous = event
    return {event['sequence']: event for event in events}
