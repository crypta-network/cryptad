"""Accepting synthetic native vectors; none represents an installed or protected execution."""
import copy
import unittest
from cryptad_certification import composed_budget_route_evidence as routes
from cryptad_certification import composed_budget_evidence as owner
from cryptad_certification.tests import test_composed_budget_evidence as _templates_module


def Templates():
    return _templates_module.ComposedBudgetEvidenceTest()
from cryptad_certification.tests.test_composed_budget_causal_evidence import (
    import_concurrency_fixture, fetch_concurrency_fixture, deferred_owner_fixture, retry_fixture, EPOCH, NODE_EPOCH)


def route_segment(case, scope=3):
    template = Templates()
    source = (template.valid_uri(preview=case in {'uri-preview-valid', 'uri-preview-malformed'})
              if case.startswith('uri-') or case in {'invalid-uri', 'invalid-utf8', 'oversized'}
              else template.valid_direct())
    if source['schemaVersion'] == 1: template.promote_v2(source)
    row = source['segments'][0]
    row['caseId'] = case
    def change_scope(child):
        if isinstance(child, dict):
            if child.get('scope') == 3: child['scope'] = scope
            for value in child.values(): change_scope(value)
        elif isinstance(child, list):
            for value in child: change_scope(value)
    change_scope(row)
    events = row['events']
    def remove(predicate): events[:] = [event for event in events if not predicate(event)]
    def replace(kind, replacement):
        next(event for event in events if event['kind'] == kind)['kind'] = replacement
    if case == 'authorization-denied':
        row['events'] = [dict(events[0], kind=kind) for kind in
            ('COMPOSED_URI_IMPORT_START', 'CAPABILITY_DENIED', 'REQUEST_FAILED')]
    elif case in {'direct-malformed', 'uri-malformed', 'uri-preview-malformed'}:
        replace('PARSE_SUCCEEDED', 'PARSE_FAILED')
        replace('REQUEST_SUCCEEDED', 'REQUEST_FAILED')
        remove(lambda e: e['kind'].startswith(('GRAPH_STORE_', 'FINGERPRINT_')) or e['kind'] == 'PREVIEW_BUILT')
    elif case == 'pasted-preview-valid':
        replace('COMPOSED_DIRECT_IMPORT_START', 'COMPOSED_PASTED_PREVIEW_START')
        replace('GRAPH_STORE_ATTEMPT', 'PREVIEW_BUILT')
        remove(lambda e: e['kind'].startswith('GRAPH_STORE_') or e['kind'] == 'PARSE_SUCCEEDED')
    elif case == 'uri-fingerprint-mismatch':
        replace('FINGERPRINT_ACCEPTED', 'FINGERPRINT_REJECTED')
        replace('REQUEST_SUCCEEDED', 'REQUEST_FAILED')
        remove(lambda e: e['kind'].startswith('GRAPH_STORE_'))
    elif case == 'uri-duplicate': replace('GRAPH_STORE_IMPORTED', 'GRAPH_STORE_DUPLICATE')
    elif case in {'invalid-uri', 'invalid-utf8', 'oversized'}:
        remove(lambda e: e['operationId'] == 1 and e['kind'].startswith(('PARSE_', 'FINGERPRINT_', 'GRAPH_STORE_')))
        reject = {'invalid-uri': 'CONTENT_URI_REJECTED', 'invalid-utf8': 'CONTENT_UTF8_REJECTED',
                  'oversized': 'CONTENT_BYTES_REJECTED'}[case]
        position = next(i for i, e in enumerate(events) if e['kind'] == 'RATE_RESERVATION_RELEASED')
        events.insert(position, dict(events[0], kind=reject))
        replace('REQUEST_SUCCEEDED', 'REQUEST_FAILED')
        if case == 'invalid-uri': remove(lambda e: e['operationId'] == 3)
        if case == 'oversized': replace('FETCH_SUCCEEDED', 'FETCH_FAILED')
    if case in {'uri-preview-malformed', 'invalid-uri', 'invalid-utf8', 'oversized'}:
        remove(lambda e: e['operationId'] == 2 and e['kind'] in {'RATE_CHARGED', 'RATE_OBSERVED', 'BUDGET_COMMITTED'})
    row['graphBefore'] = {'retainedStatements': 0}
    row['graphAfter'] = {'retainedStatements': 1 if case in {'direct-valid', 'uri-valid'} else 0}
    return row


def native_component(profile):
    """Build coherent, sequential native rows from existing owner's accepting synthetic vectors."""
    required = routes.required_variants(profile)
    segments, causal, observations, scopes, attempts = [], [], [], {}, []
    if profile in {'main', 'interference'}:
        for wanted in required:
            case, variant = wanted['caseId'], wanted['variant']
            scope = 5 if variant == 'no-trust' else 6 if variant == 'no-fetch' else 4 if case in {
                'global-import-rate', 'global-fetch-rate', 'shared-subscription'} else 3
            if case.startswith('shared-'):
                row = Templates().interference(case == 'shared-subscription')['segments'][0]
                # Historical fixture uses host numeric2. Rebind only fixture app scope.
                def relabel(child):
                    if isinstance(child, dict):
                        if child.get('scope') == 2: child['scope'] = scope
                        for value in child.values(): relabel(value)
                    elif isinstance(child, list):
                        for value in child: relabel(value)
                relabel(row)
            elif case.endswith('rate'):
                row = rate_segment(case, scope)
            else: row = route_segment(case, scope)
            segments.append(row)
            app = routes.APP_IDS[scope - 3]
            observations.append(dict(caseId=case, variant=variant, appId=app, scope=scope,
                recordKind='segment', recordIndex=len(segments)-1, responseStatus=status(case),
                responseCode='forbidden' if case == 'authorization-denied' else None))
            scopes[str(scope)] = app
    else:
        cases = [retry_fixture(), deferred_owner_fixture()] if profile == 'lifecycle' else [
            fetch_concurrency_fixture() if profile.startswith('fetch') else import_concurrency_fixture()]
        for source in cases:
            row = source['causalCases'][0]
            variant = next(item['variant'] for item in required if item['caseId'] == row['caseId'])
            # Existing causal vectors use a single app; global alternatives use a
            # separate contender and exact global held/denied family.
            if variant == 'global':
                denied = next(e for e in row['events'] if e['kind'] == 'CONCURRENCY_LIMIT_REACHED')
                family = 'content_fetch_global' if profile.startswith('fetch') else 'trust_graph_import'
                holder = next(op['operationId'] for op in row['operations'] if op['role'] in {'holder-fetch', 'holder-import'})
                for event in row['events']:
                    op = next(item for item in row['operations'] if item['operationId'] == event['operationId'])
                    if op['role'].startswith(('contender-', 'recovery-')) and event['scope'] == 3: event['scope'] = 4
                for op in row['operations']:
                    if op['role'].startswith(('contender-', 'recovery-')): op['scope'] = 4
                denied.update(scope=1, operation=family)
                held = next(e for e in row['events'] if e['kind'] == 'CONCURRENCY_HELD' and e['operationId'] == holder)
                index = row['events'].index(held)
                row['events'].insert(index+1, dict(held, scope=1, operation=family))
                released = next(e for e in row['events'] if e['kind'] == 'CONCURRENCY_RELEASED' and e['operationId'] == holder)
                row['events'].insert(row['events'].index(released)+1, dict(released, scope=1, operation=family))
                row['snapshots']['during']['holds'].append(dict(operationId=holder, operation=family,
                    scope=1, kind='concurrency', count=1))
                row['scope'] = 4
            elif row['caseId'] == 'retry':
                # Retry is generated by actual helper's budget-importer handle.
                for event in row['events']:
                    if event['scope'] == 3: event['scope'] = 4
                for operation in row['operations']: operation['scope'] = 4
                row['scope'] = 4
            causal.append(row)
            scope = row['scope']
            app = routes.APP_IDS[scope-3]
            observations.append(dict(caseId=row['caseId'], variant=variant, appId=app, scope=scope,
                recordKind='causal', recordIndex=len(causal)-1, responseStatus=502 if row['caseId']=='timeout'
                else 200 if row['caseId']=='retry' else 429, responseCode=None))
            scopes[str(scope)] = app
            if variant == 'global': scopes['3'] = routes.APP_IDS[0]
    # Recompute the complete sequential prefix, per-operation write evidence, rates,
    # parent IDs and independent snapshots; no serialized coverage claim is an input.
    events, rates, retained = [], {}, 0
    for record_index, row in enumerate(segments + causal):
        for reached in (e for e in row['events'] if e['kind'] == 'RATE_LIMIT_REACHED'):
            rates.setdefault((reached['operation'], reached['scope'], reached['windowStartEpochSecond']), 0)
        before_rates = rate_rows(rates)
        before_sequence, retained_before = len(events), retained
        original_sequence_map = {}
        offset = record_index * 100
        own = []
        for original in row['events']:
            event = copy.deepcopy(original)
            old_sequence = event['sequence']
            event['operationId'] += offset
            if event['kind'] == 'COMPOSED_CHILD': event['value'] += offset
            key = event['operation'], event['scope'], event['windowStartEpochSecond']
            if event['kind'] in {'RATE_OBSERVED', 'RATE_LIMIT_REACHED'}: event['value'] = rates.get(key, 0)
            if event['kind'] == 'RATE_CHARGED':
                event['value'] = rates.get(key, 0) + 1
                attempt = dict(event, kind='RATE_WRITE_ATTEMPT')
                own.append(attempt); events.append(attempt)
                rates[key] = event['value']
            own.append(event); events.append(event)
            original_sequence_map[old_sequence] = len(events)
            if event['kind'] == 'GRAPH_STORE_IMPORTED': retained += 1
        for index, event in enumerate(events): event.update(sequence=index+1, elapsedNanos=index)
        row['events'] = own
        row['operationId'] += offset
        if row in segments:
            row.update(beforeRates=before_rates, afterRates=rate_rows(rates),
                graphBefore={'retainedStatements': retained_before}, graphAfter={'retainedStatements': retained})
        else:
            row['retryOfOperationId'] = row['retryOfOperationId'] + offset if row['retryOfOperationId'] else None
            for op in row['operations']: op['operationId'] += offset; op['parentOperationId'] = op['parentOperationId']+offset if op['parentOperationId'] else None
            for phase in ('before', 'during', 'after'):
                snap = row['snapshots'][phase]
                snap['sequence'] = before_sequence if phase == 'before' else len(events) if phase == 'after' else original_sequence_map[snap['sequence']]
                if phase == 'during':
                    intermediate={(r['operation'],r['scope'],r['windowStartEpochSecond']):r['count'] for r in before_rates}
                    for event in own:
                        if event['sequence'] <= snap['sequence'] and event['kind'] == 'RATE_CHARGED':
                            intermediate[(event['operation'],event['scope'],event['windowStartEpochSecond'])]=event['value']
                    snap['rates']=rate_rows(intermediate)
                else: snap['rates'] = before_rates if phase == 'before' else rate_rows(rates)
                snap['retainedStatements'] = retained_before if phase in {'before','during'} else retained
                for hold in snap['holds']:
                    hold['operationId'] += offset
                    if row['scope'] == 4 and hold['scope'] == 3 and profile != 'import-global' and profile != 'fetch-global': hold['scope'] = 4
            row.update(sequenceStart=before_sequence+1, sequenceEnd=len(events), rateAttribution=attribution(own))
    for index, event in enumerate(events): event.update(sequence=index+1, elapsedNanos=index)
    bundles = {app: 'sha256:' + str(index+1)*64 for index,app in enumerate(routes.APP_IDS)}
    binding = dict(workloadDigest='sha256:'+'1'*64, productDigest='sha256:'+'2'*64, sourceCommit='3'*40,
        appCohortDigest=routes.pressure.baseline.digest([bundles[app] for app in routes.APP_IDS]),
        collectorDigest='sha256:'+'5'*64, configurationDigest='sha256:'+'6'*64,
        collectorEpoch=EPOCH,nodeEpoch=NODE_EPOCH,selectionDigest='sha256:'+'7'*64,appBundleDigests=bundles)
    attachment = {key:value for key,value in binding.items() if key not in {'selectionDigest','appBundleDigests'}}
    attachment.update(schemaVersion=4,segments=segments,causalCases=causal,storageCases=[])
    final = dict(work=dict(known=True,collectorEpoch=EPOCH,dropped=0,lastSequence=len(events),events=events),
        budget=dict(valid=True,activeFamilyLeases=0,reservedFamilyRates=0,rates=rate_rows(rates)),
        budgetConfiguration=routes.native_configuration(profile),schedulerConfiguration={'enabled':False},retainedStatements=retained)
    controls = [dict(kind=kind,status=code,before={'sequence':len(events),'budgetValid':True,'droppedEvents':0,'rates':rate_rows(rates),'holds':[],'retainedStatements':None},
                         after={'sequence':len(events),'budgetValid':True,'droppedEvents':0,'rates':rate_rows(rates),'holds':[],'retainedStatements':None})
                for kind,code in [('other-app-origin',403),('invalid-session',401)]] if profile=='main' else []
    attempts=[dict(caseId=row['caseId'],variant=row['variant'],status='executed') for row in observations]
    return dict(schemaVersion=1,kind='pr320-complete-route-component',profile=profile,
        evidenceClass='controlled-native-file-backed',bindings=binding,attachment=attachment,observations=observations,
        attempts=attempts,scopeBindings=scopes,finalSnapshot=final,transportControls=controls)


def rate_rows(rates):
    return [dict(operation=op,scope=scope,windowStartEpochSecond=window,count=count)
            for (op,scope,window),count in rates.items()]


def attribution(events):
    totals={}
    for event in events:
        if event['kind']=='RATE_CHARGED':
            key=event['operationId'],event['operation'],event['scope'],event['windowStartEpochSecond']
            totals[key]=totals.get(key,0)+1
    return [dict(operationId=op,operation=family,scope=scope,windowStartEpochSecond=window,delta=count)
            for (op,family,scope,window),count in totals.items()]


def status(case):
    return 403 if case=='authorization-denied' else 429 if case.endswith('rate') else 400 if case in {
        'direct-malformed','uri-preview-malformed','uri-malformed','invalid-uri'} else 409 if case=='uri-fingerprint-mismatch' else 415 if case=='invalid-utf8' else 502 if case=='oversized' else 200


def rate_segment(case, scope):
    row=route_segment('authorization-denied',scope)
    template=row['events'][0]
    fetch='fetch' in case; global_case=case.startswith('global')
    family='content_fetch_global' if fetch and global_case else 'foreground_content_fetch' if fetch else 'trust_graph_import'
    specifications=[('COMPOSED_URI_IMPORT_START',1,None,scope,0,0),('COMPOSED_CHILD',2,None,scope,1,0),('BUDGET_RESERVE',2,'trust_graph_import',scope,0,0)]
    if fetch:
        for selected in (scope,1):
            specifications.extend([('RATE_RESERVED',2,'trust_graph_import',selected,0,1789387200),('CONCURRENCY_HELD',2,'trust_graph_import',selected,0,0)])
        specifications += [('BUDGET_RESERVED',2,'trust_graph_import',scope,0,0),('COMPOSED_CHILD',3,None,scope,1,0),('BUDGET_ACQUIRE',3,'trust_graph_import_uri',scope,0,0)]
    denied=3 if fetch else 2
    specifications += [('RATE_LIMIT_REACHED',denied,family,1 if global_case else scope,1,1789387200),('BUDGET_RATE_DENIED',denied,'trust_graph_import_uri' if fetch else 'trust_graph_import',scope,0,0)]
    if fetch:
        for selected in (scope,1): specifications += [('RATE_RESERVATION_RELEASED',2,'trust_graph_import',selected,0,1789387200),('CONCURRENCY_RELEASED',2,'trust_graph_import',selected,0,0)]
        specifications += [('BUDGET_RELEASED',2,'trust_graph_import',scope,0,0)]
    specifications += [('REQUEST_FAILED',1,None,scope,0,0)]
    row.update(caseId=case,events=[dict(template,kind=kind,operationId=op,operation=family,scope=selected,value=value,windowStartEpochSecond=window)
        for kind,op,family,selected,value,window in specifications])
    return row


class CompleteRoutesTest(unittest.TestCase):
    def test_all_seven_profile_vectors_have_accepting_native_validators(self):
        for profile in routes.PROFILE_NAMES:
            with self.subTest(profile=profile):
                component=native_component(profile)
                derived=routes.derive_complete_routes(component,copy.deepcopy(component['bindings']))
                self.assertEqual('complete',derived['status'])
                self.assertEqual('not-observed',derived['fullAppBudgets'])
                self.assertFalse(derived['releaseEligible'])

    def test_observation_cutoff_rejects_post_observation_native_stages(self):
        with self.assertRaises(ValueError):
            routes.derive_complete_routes(native_component('main'), observation_time='2026-09-14T11:59:00Z')

    def test_capability_direction_cannot_relabel_existing_denied_app(self):
        value=native_component('main')
        next(row for row in value['observations'] if row['variant']=='no-trust')['appId']=routes.APP_IDS[3]
        with self.assertRaises(ValueError): routes.derive_complete_routes(value)

    def test_schema_bool_scope_bool_response_bool_reject(self):
        for field in ('schemaVersion','scope','responseStatus','recordIndex'):
            value=native_component('import-app')
            target=value if field=='schemaVersion' else value['observations'][0]
            target[field]=True
            with self.assertRaises(ValueError): routes.derive_complete_routes(value)

    def test_original_missing_write_owner_ack_held_interval_or_orphan_rejects(self):
        for mutation in ('write','hold','orphan','binding','final-prefix'):
            value=native_component('import-app')
            if mutation=='binding': value['bindings']['appBundleDigests'][routes.APP_IDS[0]]='sha256:'+'f'*64
            elif mutation=='orphan': value['attachment']['causalCases'].append(copy.deepcopy(value['attachment']['causalCases'][0]))
            elif mutation=='final-prefix': value['finalSnapshot']['work']['events'].append(copy.deepcopy(value['finalSnapshot']['work']['events'][-1]))
            else:
                event=next(e for e in value['attachment']['causalCases'][0]['events'] if e['kind']==('RATE_WRITE_ATTEMPT' if mutation=='write' else 'CONCURRENCY_HELD'))
                event['kind']='RATE_OBSERVED' if mutation=='write' else 'BUDGET_CHECK'
            with self.assertRaises(ValueError): routes.derive_complete_routes(value)

    def test_deferred_timeout_unobserved_tail_is_incomplete_not_synthesized(self):
        value=native_component('lifecycle')
        value['attachment']['causalCases']=value['attachment']['causalCases'][:1]
        value['observations']=value['observations'][:1]
        attempt=next(row for row in value['attempts'] if row['caseId']=='timeout')
        attempt.update(status='not-observed',reason='normal-owner-ack-unobserved',responseStatus=None)
        value['finalSnapshot']['budget']['activeFamilyLeases']=4
        derived=routes.derive_complete_routes(value)
        self.assertEqual('incomplete',derived['status'])
        self.assertEqual([{'caseId':'timeout','variant':'deferred-normal-owner'}],derived['missingVariants'])


if __name__=='__main__': unittest.main()
