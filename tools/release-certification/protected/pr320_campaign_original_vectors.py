"""Synthetic original-owner vectors. External attestation/OS boundaries stay test-only.

No native owner or coverage verifier is replaced here. These values prove accepting/rejection
paths in the original consumer; they do not claim that a protected or installed run happened.
"""
from __future__ import annotations
import base64
import copy
import datetime as dt
import hashlib
import json

from cryptad_certification import composed_budget_route_evidence as routes
from cryptad_certification import composed_budget_storage_evidence as storage
from cryptad_certification import composed_budget_evidence as native
from cryptad_certification import composed_budget_journal_member as journal
from cryptad_certification.tests.test_composed_budget_routes import native_component
from cryptad_certification.tests.test_composed_budget_complete_storage import complete_rows
from test_pr320_route_installed import selected as route_selected, originals as route_originals
from test_pr320_storage_installed import selected as storage_selected
from test_pr318_storage_installed import resign, clock_sample


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def b64(value):
    return base64.b64encode(value if isinstance(value,bytes) else encoded(value)).decode()


def terminal(record):
    records,stops={},{}
    for role in ('candidate-sender','candidate-recipient','previous','relay-no-apps'):
        value=dict(record,role=role,state='quiescent',cgroupIdentity=[1,2])
        records[role]={'status':'captured','record':value}
        stops[role]={'current':{'status':'captured','record':dict(value,membership='only-stop-helper',descendantCgroups=0)}}
    return dict(schemaVersion=1,kind='pr315-private-volatile-diagnostics',cleanupReportedByCaller=True,
        sentinel=dict(status='matched',expectedDigest='sha256:'+'a'*64,observedDigest='sha256:'+'a'*64,sizeBytes=32),
        controllerRecords=records,stopReceipts=stops)


def complete_selection(selected, *, provenance='production-artifact-comparison'):
    """Freeze prospective private metadata using the selected helper/source roster."""
    plan,auth=selected['plan'],selected['authorization']
    plan['provenanceClass']=provenance
    plan['budgetCampaignInputs']=journal.campaign_inputs(plan,auth['budgetSelection']['toolIdentities'])
    # The privacy profile separately binds its provider in the original authorization.
    if auth['executionClass']=='pr320-installed-budget-privacy-v1':
        import pr320_privacy_contract as contract
        auth['planDigest']=contract.canonical_digest(plan);auth['selectionDigest']=contract.selection_digest(auth)
    else:resign(plan,auth)
    return selected


def original_envelope(owner,private,selected,diagnostics,stopped,checkpoints,*,root_native=None,report=None,privacy_originals=None,browser=None,artifact=None):
    return dict(owner=owner,private=b64(private),selected=selected,diagnostics=diagnostics,terminal=stopped,
        report={} if report is None else report,checkpoints=b64(b'\n'.join(encoded(row) for row in checkpoints)+b'\n'),
        native=None if root_native is None else b64(root_native),privacyOriginals=None if privacy_originals is None else b64(privacy_originals),
        browser=None if browser is None else b64(browser), artifact=None if artifact is None else b64(artifact))


def route_vector(name):
    import pr320_route_contract as contract
    base=route_originals()
    private,_,diagnostics,old_terminal,_,old_native=copy.deepcopy(base)
    selected,_=route_selected(name);complete_selection(selected)
    authorization=selected['authorization'];plan=selected['plan'];node=plan['nodes'][0]
    component=native_component(name);component['evidenceClass']='installed-controller-bound'
    binding=component['bindings']
    binding.update(workloadDigest=plan['workloadInputs']['scheduler'],productDigest=node['artifactDigest'],sourceCommit=node['sourceCommit'],
        appCohortDigest=contract.canonical_digest(node['appDigests']),**plan['composedBudgetInputs'],selectionDigest=authorization['selectionDigest'],
        appBundleDigests=authorization['budgetSelection']['appBundleDigests'])
    for key in component['attachment']:
        if key in binding:component['attachment'][key]=binding[key]
    prefix=copy.deepcopy(json.loads(old_native)['work']['events'][:10]);shift=len(prefix)
    for row in component['attachment']['causalCases']:
        row['sequenceStart']+=shift;row['sequenceEnd']+=shift
        for snapshot in row['snapshots'].values():snapshot['sequence']+=shift
    for event in component['finalSnapshot']['work']['events']:event['sequence']+=shift;event['elapsedNanos']+=shift
    component['finalSnapshot']['work']['events']=prefix+component['finalSnapshot']['work']['events'];component['finalSnapshot']['work']['lastSequence']+=shift
    # Transport denials are offered after native work in the actual driver.
    for control in component['transportControls']:
        control['before']['sequence']+=shift;control['after']['sequence']+=shift
    role_digest='sha256:'+binding['nodeEpoch']+'a'*32
    record=old_terminal['controllerRecords']['candidate-sender']['record'];record['roleEpochDigest']=role_digest
    contexts=private['contexts']
    private.update(executionClass=authorization['executionClass'],selectionDigest=authorization['selectionDigest'],component=component,
        coverage=routes.derive_complete_routes(component))
    root_native=copy.deepcopy(component['finalSnapshot']);root_native.pop('retainedStatements');raw=encoded(root_native)
    usage=[]
    for rate in root_native['budget']['rates']:
        usage.append(dict(appId='_cryptad_global' if rate['scope']==1 else contract.APP_IDS[rate['scope']-3],operation=rate['operation'],
            windowStart=dt.datetime.fromtimestamp(rate['windowStartEpochSecond'],dt.timezone.utc).isoformat(),
            windowSeconds=3600 if rate['operation'] in {'trust_graph_import','subscription_poll'} else 60,
            count=rate['count'],lastDecisionAt=None,lastDecision=None,nextAvailableAt=None))
    diagnostics['routeBudgetSelectionDigest']=authorization['selectionDigest']
    diagnostics['routeBudgetOriginalRecord'].update(durableUsage=usage,nativeDigest='sha256:'+hashlib.sha256(raw).hexdigest(),
        graphFacts=[dict(documentFingerprint=authorization['budgetSelection']['statementFingerprint'],signatureVerified=True)
                    for _ in range(component['finalSnapshot']['retainedStatements'])])
    checkpoints=[dict(phase='native-collected',component=copy.deepcopy(component))]
    originals=original_envelope('pr320_route_runtime_evidence',private,selected,diagnostics,terminal(record),checkpoints,root_native=raw)
    return encoded(component),originals


def storage_vector(case,variant):
    import pr320_storage_contract as contract
    row=copy.deepcopy(next(row for row in complete_rows() if (row['caseId'],row['variant'])==(case,variant)))
    selected,_=storage_selected(case,variant)
    auth=selected['authorization'];plan=selected['plan']
    auth['budgetSelection']['statementFingerprint']=row['selectedFingerprint']
    if case=='window-crossing':
        auth['budgetSelection']['timePlan']={key:row['timePlan'][key] for key in
            ('boundaryEpochSecond','selectedAtEpochSecond','startMarginSeconds','requestDeadlineMillis')}
    complete_selection(selected)
    role_digest='sha256:'+row['nodeEpoch']+'a'*32
    contexts={app:dict(appId=app,role='candidate-sender',roleEpochDigest=role_digest,**{key:'sha256:'+'a'*64 for key in
        ('daemonEpochDigest','workerEpochDigest','originDigest','sessionDigest','sessionExpiryDigest')}) for app in contract.APP_IDS}
    component=dict(schemaVersion=1,kind='composed-budget-storage-component',storageCases=[row])
    private=dict(schemaVersion=1,kind='pr320-private-storage-budget',selectionDigest=auth['selectionDigest'],executionClass=auth['executionClass'],
        contexts=contexts,attempts=[{'caseId':case,'status':'executed'}],storageComponent=component,storageCoverage=storage.derive_complete_storage(component))
    record=dict(roleEpochDigest=role_digest,generation=row['roleGeneration'],managerInvocation='b'*32,bootId='c'*36,handle='d'*64)
    receipt=row.get('adminReceipt')
    diagnostics=dict(storageAccessCleanup='completed',storageSelectionDigest=auth['selectionDigest'],
        storageBootstrapContext=dict(apps=contexts,**{key:record[key] for key in ('generation','managerInvocation','bootId','handle')}),
        storageFaultReceipts=[receipt['restriction'],receipt['restoration']] if receipt else [])
    boundary=auth['budgetSelection']['timePlan']['boundaryEpochSecond']
    report={'storageClock':{'before':clock_sample((boundary-30)*10**9,10**12),'after':clock_sample((boundary+30)*10**9,2*10**12)}}
    checkpoints=[{'phase':'attempt-completed','attempt':private['attempts'][0],'row':row}]
    return encoded(component),original_envelope('pr320_storage_runtime_evidence',private,selected,diagnostics,terminal(record),checkpoints,report=report)


def cancellation_vector():
    from test_pr320_owner_installed import originals_fixture
    private,selected,diagnostics,stopped,checkpoints,root_native=copy.deepcopy(originals_fixture())
    old=selected['authorization']['selectionDigest'];complete_selection(selected);new=selected['authorization']['selectionDigest']
    def rebind(value):
        if isinstance(value,dict):return {key:rebind(child) for key,child in value.items()}
        if isinstance(value,list):return [rebind(child) for child in value]
        return new if value==old else value
    private,diagnostics,checkpoints,root_native=map(rebind,(private,diagnostics,checkpoints,root_native))
    return encoded(private['composedBudgetEvidence']),original_envelope('pr320_owner_runtime_evidence',private,selected,diagnostics,
        terminal(stopped['controllerRecords']['candidate-sender']['record']),checkpoints,root_native=root_native)


def privacy_vectors():
    from test_pr320_privacy_installed import vector
    from cryptad_certification import certification_public_export as exports
    args=copy.deepcopy(vector());selected=args['selected'];old=selected['authorization']['selectionDigest']
    complete_selection(selected);new=selected['authorization']['selectionDigest']
    def rebind(value):
        if isinstance(value,dict):return {key:rebind(child) for key,child in value.items()}
        if isinstance(value,list):return [rebind(child) for child in value]
        return new if value==old else value
    for key in ('private','originals','browser'):args[key]=rebind(args[key])
    private=args['private'];native_raw=encoded(private);native_digest='sha256:'+hashlib.sha256(native_raw).hexdigest()
    browser=args['browser'];browser.update(nativeMemberDigest=native_digest)
    receipt=args['originals']['receipts'][2]
    receipt.update(component=copy.deepcopy(browser),packagedScriptDigest=browser['scriptDigest'],collectorOutput=[{'stdout':encoded(browser).decode(),'stderr':''}])
    checkpoints=[dict(phase='native-collected',component=private['component']),dict(phase='browser-collected',component=browser)]
    orig=original_envelope('pr320_privacy_runtime_evidence',private,selected,args['diagnostics'],args['terminal'],checkpoints,
        report=args['report'],privacy_originals=args['originals'],browser=browser)
    # Exact local transfer fixtures exercise the real allowlist/public byte exporter.
    source_commit=selected['plan']['nodes'][0]['sourceCommit']
    import tempfile
    from pathlib import Path
    from cryptad_certification.tests.test_certification_public_export import envelope
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);workspace=root/'workspace';workspace.mkdir()
        source=workspace/'build/release-certification/ci-42-1/release-certification/summary.json'
        source.parent.mkdir(parents=True);source.write_bytes(exports._json(envelope(workspace)))
        manifest=root/'manifest.json';manifest.write_text(json.dumps({'release':{'id':'ci-42-1','version':'1','profile':'pr'},'output':{'root':'build/release-certification'}}))
        destination=root/'public';exports.create_export(manifest,workspace,destination,source_commit)
        raw_files={name:(destination/name).read_bytes() for name in exports.ROSTER}
    artifact=dict(schemaVersion=1,kind='composed-budget-artifact-component',nativeMemberDigest=native_digest,sourceCommit=source_commit,
        files={name:base64.b64encode(raw).decode() for name,raw in raw_files.items()},
        transferFiles={name:base64.b64encode(raw).decode() for name,raw in raw_files.items()},jobSummary=raw_files['report.md'].decode())
    orig['artifact']=b64(artifact)
    return [(native_raw,copy.deepcopy(orig)),(encoded(browser),copy.deepcopy(orig)),(encoded(artifact),copy.deepcopy(orig))]


def restart_vector():
    from test_pr320_restart_installed import selected as restart_selected
    from test_pr319_restart_runtime_evidence import bound_vector, diagnostic_vector
    import pr320_restart_contract as contract
    from cryptad_certification import composed_budget_restart_evidence as restart
    selected=restart_selected();auth=selected['authorization'];plan=selected['plan']
    parts=[copy.deepcopy(bound_vector(variant)) for variant in ('settled-graceful','settled-abrupt','inflight-abrupt')]
    parts += [copy.deepcopy(diagnostic_vector(variant)) for variant in ('enumeration-only','required-key-unreadable')]
    private=copy.deepcopy(parts[-1][0]);diagnostics=copy.deepcopy(parts[-1][1]);record=copy.deepcopy(parts[-1][2]['controllerRecords']['candidate-sender']['record'])
    attachment=dict(schemaVersion=5,restartCases=[],diagnosticsCases=[])
    phases,receipts,epoch_contexts,actual,bootstraps,stops,checkpoints=[],[],[],[],{}, {},[]
    for index,(part,diag,_terminal,_digest) in enumerate(parts):
        row=(part['composedBudgetEvidence']['restartCases']+part['composedBudgetEvidence']['diagnosticsCases'])[0]
        row['selectedFingerprint']='a'*64
        if row['caseId']=='diagnostics-unavailable':
            graph=copy.deepcopy(parts[0][0]['composedBudgetEvidence']['restartCases'][0]['before']['graph'])
            for phase in ('before','during','after','recovery'):
                row[phase]['graph']=copy.deepcopy(graph)
            for checkpoint in part['phaseReceipts']:
                checkpoint['receipt']['graphFacts']=copy.deepcopy(graph)
            for receipt in part['originalReceipts']+diag['restartFaultReceipts']:
                if 'graphFacts' in receipt:receipt['graphFacts']=copy.deepcopy(graph)
        # Distinct native stream epochs are mandatory across each supplied variant.
        def epochs(value):
            if isinstance(value,dict):
                for key,child in value.items():
                    if key=='collectorEpoch':value[key]=('%08x'%(100+index))+child[8:]
                    else:epochs(child)
            elif isinstance(value,list):
                for child in value:epochs(child)
        epochs(row);epochs(part['phaseReceipts'])
        seen=set()
        def monotonic(value):
            if isinstance(value,(dict,list)):
                if id(value) in seen:return
                seen.add(id(value))
            if isinstance(value,dict):
                for key,child in value.items():
                    if key in {'observedMonotonicNs','capturedMonotonicNs','startedMonotonicNs'}:value[key]=child+index*1000
                    else:monotonic(child)
            elif isinstance(value,list):
                for child in value:monotonic(child)
        monotonic(part['phaseReceipts']);monotonic(part['originalReceipts']);monotonic(diag['restartFaultReceipts'])
        family='diagnosticsCases' if row['caseId']=='diagnostics-unavailable' else 'restartCases'
        attachment[family].append(row)
        phases.extend(part['phaseReceipts']);receipts.extend(part['originalReceipts']);epoch_contexts.extend(part['epochContexts'])
        actual.extend(diag['restartFaultReceipts']);bootstraps.update(diag['restartBootstrapContexts']);stops.update(diag['restartOriginalStops'])
        for phase in ('before','during','after','recovery'):
            if phase in row:checkpoints.append(dict(caseId=row['caseId'],variant=row['variant'],phase=phase,sample=row[phase]))
        if family=='restartCases':checkpoints.append(dict(caseId=row['caseId'],variant=row['variant'],phase='terminal',
            receipt=next(r for r in part['originalReceipts'] if r['phase']=='terminal')))
    private.update(composedBudgetEvidence=attachment,phaseReceipts=phases,originalReceipts=receipts,epochContexts=epoch_contexts)
    diagnostics.update(restartFaultReceipts=actual,restartBootstrapContexts=bootstraps,restartOriginalStops=stops)
    epoch=private['contexts']['feed-reader']['roleEpochDigest'];record['roleEpochDigest']=epoch
    stamp=int(restart._time(attachment['restartCases'][0]['before']['diagnostics']['observedAt']))
    boundary=(stamp//3600+1)*3600
    auth['budgetSelection']['timePlan']=dict(boundaryEpochSecond=boundary,selectedAtEpochSecond=boundary-300,startMarginSeconds=10,requestDeadlineMillis=45000)
    auth['budgetSelection']['statementFingerprint']='a'*64
    old=private['selectionDigest'];complete_selection(selected);new=auth['selectionDigest']
    def rebind(value):
        if isinstance(value,dict):return {key:rebind(child) for key,child in value.items()}
        if isinstance(value,list):return [rebind(child) for child in value]
        return new if value==old else value
    private,diagnostics,checkpoints=map(rebind,(private,diagnostics,checkpoints));attachment=private['composedBudgetEvidence']
    node=plan['nodes'][0]
    attachment.update(collectorEpoch=attachment['diagnosticsCases'][-1]['recovery']['collectorEpoch'],nodeEpoch=epoch[7:39],
        workloadDigest=plan['workloadInputs']['scheduler'],productDigest=node['artifactDigest'],sourceCommit=node['sourceCommit'],
        appCohortDigest=journal.legacy.pressure.baseline.digest(node['appDigests']),**plan['composedBudgetInputs'],segments=[],causalCases=[],storageCases=[])
    private['composedBudgetCoverage']=native.derive(attachment,workload_digest=attachment['workloadDigest'],product_digest=attachment['productDigest'],
        source_commit=attachment['sourceCommit'],app_cohort_digest=attachment['appCohortDigest'],node_epoch=attachment['nodeEpoch'],
        collector_digest=attachment['collectorDigest'],configuration_digest=attachment['configurationDigest'])
    report={'storageClock':{'before':clock_sample((stamp-60)*10**9,10**12),'after':clock_sample((stamp+60)*10**9,2*10**12)}}
    return encoded(attachment),original_envelope('pr320_restart_runtime_evidence',private,selected,diagnostics,terminal(record),checkpoints,report=report)


def distinct_stream(raw,originals,index):
    """Give independent synthetic producer attempts distinct daemon ring identities."""
    original=copy.deepcopy(originals)
    def visit(value):
        if isinstance(value,dict):
            for key,child in value.items():
                if key=='collectorEpoch':value[key]=('%08x'%(1000+index))+child[8:]
                else:visit(child)
        elif isinstance(value,list):
            for child in value:visit(child)
    private=json.loads(base64.b64decode(original['private']));visit(private)
    visit(original['diagnostics'])
    for key in ('native','privacyOriginals'):
        if original[key] is not None:
            decoded=json.loads(base64.b64decode(original[key]));visit(decoded);original[key]=b64(decoded)
    checkpoints=[json.loads(line) for line in base64.b64decode(original['checkpoints']).splitlines()]
    visit(checkpoints)
    component=json.loads(raw);visit(component)
    if original['owner']=='pr320_route_runtime_evidence':
        private['coverage']=routes.derive_complete_routes(private['component'])
        original['diagnostics']['routeBudgetOriginalRecord']['nativeDigest']='sha256:'+hashlib.sha256(base64.b64decode(original['native'])).hexdigest()
    if original['owner']=='pr320_owner_runtime_evidence':
        a=private['composedBudgetEvidence']
        private['composedBudgetCoverage']=native.derive(a,workload_digest=a['workloadDigest'],product_digest=a['productDigest'],source_commit=a['sourceCommit'],
            app_cohort_digest=a['appCohortDigest'],node_epoch=a['nodeEpoch'],collector_digest=a['collectorDigest'],configuration_digest=a['configurationDigest'])
    original['private']=b64(private);original['checkpoints']=b64(b'\n'.join(encoded(row) for row in checkpoints)+b'\n')
    return encoded(component),original


def all_original_members():
    values=[]
    for index,name in enumerate(routes.PROFILE_NAMES):
        raw,original=route_vector(name);values.append((index,'route-component',*distinct_stream(raw,original,index)))
    raw,original=cancellation_vector();values.append((7,'legacy-attachment',*distinct_stream(raw,original,7)))
    for index,(case,variant) in enumerate(journal.STORAGE_VARIANTS,8):
        raw,original=storage_vector(case,variant);values.append((index,'storage-component',*distinct_stream(raw,original,index)))
    values.extend((index,kind,raw,original) for index,kind,(raw,original) in zip(range(15,18),
        ('installed-privacy','installed-browser-privacy','artifact-privacy'),privacy_vectors()))
    raw,original=restart_vector();values.append((18,'legacy-attachment',raw,original))
    return values
