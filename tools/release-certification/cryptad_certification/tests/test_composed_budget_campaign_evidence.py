"""All finite native owners participate; local completeness never manufactures authority."""
import base64
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from cryptad_certification import composed_budget_campaign_evidence as campaign
from cryptad_certification import composed_budget_artifact_capture as capture
from cryptad_certification import certification_public_export as export
from cryptad_certification import composed_budget_route_evidence as routes
from cryptad_certification.composed_budget_cohort_contract import REQUIRED_VARIANTS
from cryptad_certification.tests.test_composed_budget_routes import native_component
from cryptad_certification.tests.test_composed_budget_complete_storage import complete_rows, component
from cryptad_certification.tests.test_composed_budget_causal_evidence import deferred_owner_fixture
from cryptad_certification.tests.test_composed_budget_restart_evidence import process, diagnostics
from cryptad_certification.tests.test_certification_public_export import envelope

ROOT = Path(__file__).resolve().parents[4]


def encode(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def rebind_epochs(value, node, collector):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'nodeEpoch': value[key] = node
            elif key == 'collectorEpoch': value[key] = collector
            else: rebind_epochs(child, node, collector)
    elif isinstance(value, list):
        for child in value: rebind_epochs(child, node, collector)


def complete_local(native_raw, browser_raw, artifact_raw):
    main = native_component('main')
    subject = {key: main['bindings'][key] for key in campaign.SUBJECT_FIELDS - {'contractVersion'}}
    subject['contractVersion'] = 25
    selection = dict(schemaVersion=1, kind='composed-budget-campaign', evidenceClass='synthetic-local-cohort',
                     subject=subject, members=[], attempts=[])
    members, bindings = {}, {}
    def add(kind, value, pairs, *, raw=None, censored=False):
        index = len(members)
        name = 'member-%02d.json' % index
        node, collector = '%032x' % (index + 1), '%08x-1234-1234-1234-123456789012' % (index + 1)
        binding = dict(collectorDigest='sha256:' + '5' * 64, configurationDigest='sha256:' + '6' * 64,
            nodeEpoch=node, collectorEpoch=collector, role='candidate-sender', producerDigest='sha256:' + '9' * 64,
            observedAt='2026-10-15T00:00:00Z', workloadDigest='sha256:' + '1' * 64)
        if raw is None:
            rebind_epochs(value, node, collector)
            raw = encode(value)
        elif kind == 'native-privacy':
            binding['collectorEpoch'] = value['surfaces']['workSnapshot']['collectorEpoch']
            # This fixture consumes genuinely fresh native bytes. Its synthetic observation
            # cutoff must include those events rather than backdating them to a fixed midnight.
            times = [dt.datetime.fromisoformat(binding['observedAt'].replace('Z', '+00:00'))]
            times.extend(dt.datetime.fromisoformat(event['observedAt'].replace('Z', '+00:00'))
                         for event in value['surfaces']['workSnapshot']['events'])
            binding['observedAt'] = max(times).isoformat()
        elif kind == 'browser-privacy':
            binding['servedScriptDigest'] = value['scriptDigest']
            binding['producerDigest'] = digest((ROOT / 'tools/web-shell/tests/support-browser.cjs').read_bytes())
        members[name], bindings[name] = raw, binding
        selection['members'].append(dict(member=name, kind=kind, digest=digest(raw), size=len(raw),
            binding=binding, plannedVariants=[list(pair) for pair in pairs]))
        selection['attempts'].append(dict(member=name, attempt=1, outcome='censored' if censored else 'observed'))
    for profile in routes.PROFILE_NAMES:
        value = native_component(profile)
        add('route-component', value, [(row['caseId'], row['variant']) for row in routes.required_variants(profile)])
    for row in complete_rows():
        add('storage-component', component([row]), [(row['caseId'], row['variant'])])
    cancel = deferred_owner_fixture(True)
    cancel.update({key: subject[key] for key in ('workloadDigest', 'productDigest', 'sourceCommit', 'appCohortDigest')})
    add('legacy-attachment', cancel, [('cancellation', 'deferred-normal-owner')])
    for row in [process(), process('settled-abrupt'), process('inflight-abrupt'), diagnostics(), diagnostics('required-key-unreadable')]:
        index = len(members)
        # Restart's old and new collectors remain distinct. The v5 top-level collector is
        # its recovery generation, while empty historical families preserve v5 semantics.
        for phase in ('before', 'during', 'after', 'recovery'):
            if phase in row:
                old = row[phase]['collectorEpoch']
                new = '%08x' % (index + 100) + old[8:]
                row[phase]['collectorEpoch'] = row[phase]['nativeSnapshot']['collectorEpoch'] = new
        value = dict(schemaVersion=5, **{key: subject[key] for key in subject if key != 'contractVersion'},
            collectorDigest='sha256:' + '5' * 64, configurationDigest='sha256:' + '6' * 64,
            collectorEpoch=row['recovery']['collectorEpoch'], nodeEpoch='%032x' % (index + 1),
            segments=[], causalCases=[], storageCases=[],
            restartCases=[] if row['caseId'] == 'diagnostics-unavailable' else [row],
            diagnosticsCases=[row] if row['caseId'] == 'diagnostics-unavailable' else [])
        raw = encode(value)
        add('legacy-attachment', value, [(row['caseId'], row['variant'])], raw=raw,
            censored=row.get('tailStatus') == 'censored')
        bindings[selection['members'][-1]['member']]['collectorEpoch'] = value['collectorEpoch']
    for kind, raw, variant in [('native-privacy', native_raw, 'native'),
                               ('browser-privacy', browser_raw, 'browser'),
                               ('artifact-privacy', artifact_raw, 'public-artifacts')]:
        add(kind, json.loads(raw), [('privacy', variant)], raw=raw)
    native_binding = next(row['binding'] for row in selection['members'] if row['kind'] == 'native-privacy')
    for row in selection['members']:
        if row['kind'] in {'browser-privacy', 'artifact-privacy'}:
            row['binding'].update({key: native_binding[key] for key in ('nodeEpoch', 'collectorEpoch', 'collectorDigest', 'configurationDigest', 'workloadDigest')})
    subject['workloadDigest'] = routes.pressure.baseline.digest(
        {name: bindings[name]['workloadDigest'] for name in sorted(bindings)})
    return selection, members, subject, bindings


class CampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_path = ROOT / 'platform-api/build/test-results/pr320-native/privacy.json'
        if not native_path.exists(): raise unittest.SkipTest('actual native privacy producer must execute first')
        cls.native_raw = native_path.read_bytes()
        wanted = digest(cls.native_raw)
        script = digest((ROOT / 'platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js').read_bytes())
        found = []
        for path in sorted((ROOT / 'build/pr320-browser-private').glob('attempt-*/browser.json')):
            raw = path.read_bytes()
            value = json.loads(raw)
            if (value['nativeMemberDigest'] == wanted and value['scriptDigest'] == script
                    and all(row['method'] == 'GET' for row in value['requests'])):
                found.append(raw)
        if not found: raise unittest.SkipTest('actual browser must execute against the current native artifact')
        cls.browser_raw = found[0]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        workspace = root / 'workspace'; workspace.mkdir()
        private = root / 'private'; private.mkdir(mode=0o700)
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps({'release': {'id': 'ci-42-1', 'version': '1', 'profile': 'pr'},
                                        'output': {'root': 'build/release-certification'}}))
        source = workspace / 'build/release-certification/ci-42-1/release-certification/summary.json'
        source.parent.mkdir(parents=True)
        original = envelope(workspace)
        original['payload']['legacy']['metadata']['gitCommit'] = '3' * 40
        original['payload']['legacy']['privateInputs'] = json.loads(self.native_raw)['stimuli']
        source.write_bytes(export._json(original))
        public, transferred = root / 'public', root / 'transferred'
        export.create_export(manifest, workspace, public, '3' * 40)
        shutil.copytree(public, transferred)
        job = root / 'job.md'; job.write_bytes((transferred / 'report.md').read_bytes())
        native = private / 'native.json'; native.write_bytes(self.native_raw)
        artifact = private / 'artifact.json'
        capture.capture(native, public, transferred, job, artifact, source_commit='3' * 40)
        self.selection, self.members, self.subject, self.bindings = complete_local(
            self.native_raw, self.browser_raw, artifact.read_bytes())

    def derive(self):
        return campaign.derive_campaign(self.selection, self.members,
            expected_subject=self.subject, expected_bindings=self.bindings)

    def replace(self, index, value):
        descriptor = self.selection['members'][index]
        raw = encode(value); self.members[descriptor['member']] = raw
        descriptor.update(digest=digest(raw), size=len(raw))

    def test_all_31_and_every_mandatory_variant_are_recomputed_at_local_class(self):
        result = self.derive()
        self.assertEqual('complete-local', result['budgetCohortStatus'])
        self.assertEqual(31, len(result['observedCases']))
        self.assertEqual(sorted(map(list, REQUIRED_VARIANTS)), result['verifiedVariants'])
        self.assertEqual([], result['missingVariants'])
        self.assertEqual('not-established', result['originalAuthentication'])
        self.assertEqual('not-observed', result['fullAppBudgets'])
        self.assertFalse(result['releaseEligible']); self.assertFalse(result['phaseComplete'])

    def test_each_member_omission_fails_the_frozen_roster(self):
        for name in list(self.members):
            raw = self.members.pop(name)
            with self.subTest(member=name), self.assertRaises(ValueError): self.derive()
            self.members[name] = raw

    def test_invalid_original_cannot_hide_in_green_case_union(self):
        value = json.loads(self.members['member-00.json'])
        value['attachment']['segments'][0]['events'][-1]['kind'] = 'REQUEST_FAILED'
        self.replace(0, value)
        with self.assertRaises(ValueError): self.derive()

    def test_replayed_epoch_operations_and_future_native_events_reject(self):
        for mutation in ('replay', 'future'):
            saved = copy.deepcopy((self.selection, self.members, self.bindings))
            value = json.loads(self.members['member-01.json'])
            if mutation == 'replay':
                node, collector = (self.bindings['member-00.json'][key] for key in ('nodeEpoch', 'collectorEpoch'))
                rebind_epochs(value, node, collector)
                self.bindings['member-01.json'].update(nodeEpoch=node, collectorEpoch=collector)
            else:
                value['attachment']['segments'][0]['events'][0]['observedAt'] = '2027-01-01T00:00:00Z'
            self.replace(1, value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.derive()
            self.selection, self.members, self.bindings = saved

    def test_wrong_source_cohort_collector_configuration_epoch_and_member_bytes_reject(self):
        for key in self.subject:
            changed = dict(self.subject); changed[key] = 26 if key == 'contractVersion' else 'wrong'
            with self.subTest(subject=key), self.assertRaises(ValueError):
                campaign.derive_campaign(self.selection, self.members, expected_subject=changed, expected_bindings=self.bindings)
        for key in campaign.BINDING_FIELDS:
            changed = copy.deepcopy(self.bindings); changed['member-00.json'][key] = 'wrong'
            with self.subTest(binding=key), self.assertRaises(ValueError):
                campaign.derive_campaign(self.selection, self.members, expected_subject=self.subject, expected_bindings=changed)
        self.members['member-00.json'] += b' '
        with self.assertRaises(ValueError): self.derive()

    def test_failed_attempt_is_retained_and_censoring_cannot_be_relabelled(self):
        self.selection['attempts'][0]['outcome'] = 'failed'
        result = self.derive()
        self.assertEqual('incomplete', result['budgetCohortStatus'])
        self.assertTrue(result['failedAttemptsRetained'])
        self.selection['attempts'][0]['outcome'] = 'censored'
        with self.assertRaises(ValueError): self.derive()

    def test_summary_fixture_authority_and_unauthorized_na_reject(self):
        self.selection['evidenceClass'] = 'original-protected-budget'
        with self.assertRaises(ValueError): self.derive()
        self.selection['evidenceClass'] = 'synthetic-local-cohort'
        self.selection['members'][0]['plannedVariants'].pop()
        with self.assertRaises(ValueError): self.derive()


if __name__ == '__main__': unittest.main()
