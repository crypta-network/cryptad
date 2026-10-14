"""Bounded source-to-sink checks for private native privacy observations.

Actual producers retain stimulus readback and export bytes privately. This module recomputes
local consistency; it grants neither installed provenance nor protected authentication. Public
exports use a closed projection rather than treating arbitrary digest metadata as safe.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from urllib.parse import quote, quote_plus

from .composed_budget_evidence import ComposedEvidenceError, REQUIRED_CASES
from .redaction import scan_value

MAX_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 100000
MAX_DEPTH = 32
NATIVE_SURFACES = frozenset({'appErrors', 'appAudit', 'workSnapshot', 'operatorRuntime',
                            'supportBundle', 'supportPreview'})
PURPOSES = frozenset({'statement', 'sourceLabel', 'sourceUri', 'documentIdentity', 'subject',
                      'appDataKey', 'appDataValue', 'credentialShape', 'filesystem', 'selectionMapping',
                      'fieldName', 'nestedCredential', 'backupShape', 'attachmentName'})


def _need(condition, classification):
    if not condition:
        raise ComposedEvidenceError('composed-budget-privacy-' + classification)


def _encoded(value):
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _need(False, 'serialization-invalid')
    _need(0 < len(raw) <= MAX_BYTES, 'byte-limit')
    pending, count = [(value, 0)], 0
    while pending:
        child, depth = pending.pop()
        count += 1
        _need(depth <= MAX_DEPTH and count <= MAX_MEMBERS, 'tree-limit')
        if isinstance(child, dict):
            _need(all(isinstance(key, str) for key in child), 'field-invalid')
            pending.extend((key, depth + 1) for key in child)
            pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list):
            pending.extend((item, depth + 1) for item in child)
        elif isinstance(child, str):
            _need(len(child.encode()) <= MAX_BYTES, 'string-limit')
        else:
            _need(child is None or type(child) in {int, bool, float}, 'scalar-invalid')
    return raw


def representations(value, *, private_digests=False):
    """Only representations emitted by these collectors, never arbitrary decoding."""
    _need(isinstance(value, str) and 8 <= len(value.encode()) <= 8192, 'stimulus-invalid')
    raw = value.encode()
    strings = {value, html.escape(value, quote=True), quote(value, safe=''), quote_plus(value),
               json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value, ensure_ascii=True)[1:-1],
               base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()}
    strings.update(item.rstrip('=') for item in tuple(strings) if item.endswith('='))
    if private_digests:
        strings.add(hashlib.sha256(raw).hexdigest())
    return tuple(item.encode() for item in strings)


def check_omission(value, stimuli, *, public=False):
    """Fixed classification on contamination; matching text and filenames never escape."""
    raw = _encoded(value)
    _need(isinstance(stimuli, list) and 0 < len(stimuli) <= 64, 'stimulus-limit')
    leaves = [raw]
    pending = [value]
    while pending:
        child = pending.pop()
        if isinstance(child, str): leaves.append(child.encode())
        elif isinstance(child, dict):
            pending.extend(child)
            pending.extend(child.values())
        elif isinstance(child, list): pending.extend(child)
    for marker in stimuli:
        _need(not any(candidate in leaf for candidate in representations(marker, private_digests=public) for leaf in leaves),
              'output-contaminated')
    return raw


def verify_support_wire(text):
    """Verify Java's digest without changing number or escaped-string wire representations."""
    _need(isinstance(text, str) and 0 < len(text.encode()) <= MAX_BYTES, 'support-wire-invalid')
    def unique(pairs):
        result = {}
        for key, child in pairs:
            _need(key not in result, 'support-duplicate-field')
            result[key] = child
        return result
    try:
        bundle = json.loads(text, object_pairs_hook=unique,
                            parse_constant=lambda _: _need(False, 'support-number-invalid'))
    except (ValueError, RecursionError):
        _need(False, 'support-wire-invalid')
    _encoded(bundle)
    _need(isinstance(bundle, dict) and 'supportDigest' in bundle, 'support-wire-invalid')
    decoder = json.JSONDecoder()
    wire = text.strip()
    index, members = 1, []
    try:
        while index < len(wire) - 1:
            while wire[index] in ' \t\r\n': index += 1
            start = index
            key, index = decoder.raw_decode(wire, index)
            while wire[index] in ' \t\r\n': index += 1
            _need(wire[index] == ':', 'support-wire-invalid')
            index += 1
            while wire[index] in ' \t\r\n': index += 1
            _, index = decoder.raw_decode(wire, index)
            if key != 'supportDigest': members.append(wire[start:index])
            while wire[index] in ' \t\r\n': index += 1
            if wire[index] == '}': break
            _need(wire[index] == ',', 'support-wire-invalid')
            index += 1
    except (ValueError, IndexError):
        _need(False, 'support-wire-invalid')
    # Remove only insignificant JSON whitespace. Quoted bytes, including escapes,
    # retain the serializer's original spellings and member ordering.
    compact, quoted, escaped = [], False, False
    for char in '{' + ','.join(members) + '}':
        if quoted:
            compact.append(char)
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True; compact.append(char)
        elif char not in ' \t\r\n': compact.append(char)
    _need(bundle['supportDigest'] == {'algorithm': 'SHA-256',
        'digest': hashlib.sha256(''.join(compact).encode()).hexdigest()}, 'support-digest-invalid')
    return bundle


def verify_native(value):
    """Verify actual readback plus nonempty exports, not a caller's privacy verdict."""
    _encoded(value)
    fields = {'schemaVersion', 'caseId', 'evidenceClass', 'producer', 'stimuli',
              'privateSurfaces', 'surfaces', 'denials', 'counters'}
    _need(isinstance(value, dict) and set(value) == fields and type(value['schemaVersion']) is int
          and value['schemaVersion'] == 1 and value['caseId'] == 'privacy'
          and value['evidenceClass'] == 'controlled-native-file-backed'
          and value['producer'] == 'network.crypta.platform.api.TrustGraphPrivacyIntegrationTest', 'binding-invalid')
    controls, surfaces, rows = value['privateSurfaces'], value['surfaces'], value['stimuli']
    _need(isinstance(controls, dict) and 0 < len(controls) <= 32
          and isinstance(surfaces, dict) and NATIVE_SURFACES <= set(surfaces)
          and set(surfaces) <= NATIVE_SURFACES | {'queueSummary', 'subscriptionSummary', 'graphAuditSummary', 'logs', 'redactorProjection'},
          'surfaces-missing')
    _need(isinstance(rows, list) and 0 < len(rows) <= 64, 'stimulus-limit')
    seen, markers, purposes = set(), [], set()
    for row in rows:
        _need(isinstance(row, dict) and set(row) == {'purpose', 'marker', 'privateSurface'}
              and row['purpose'] in PURPOSES and row['privateSurface'] in controls, 'stimulus-binding-invalid')
        representations(row['marker'])
        control = controls[row['privateSurface']]
        _encoded(control)
        pending, observed = [control], False
        while pending:
            child = pending.pop()
            if isinstance(child, str): observed |= row['marker'] in child
            elif isinstance(child, dict):
                pending.extend(child)
                pending.extend(child.values())
            elif isinstance(child, list): pending.extend(child)
        _need(row['marker'] not in seen and observed, 'stimulus-not-observed')
        seen.add(row['marker'])
        markers.append(row['marker'])
        purposes.add(row['purpose'])
    _need(PURPOSES <= purposes, 'stimulus-purpose-missing')
    for surface in surfaces.values():
        check_omission(surface, markers)
    bundle = surfaces['supportBundle']
    if isinstance(bundle, str):
        bundle = verify_support_wire(bundle)
    else:
        bundle = verify_support_wire(_encoded(bundle).decode())
    _need(isinstance(bundle, dict) and bundle.get('kind') == 'cryptad-operator-support-bundle'
          and bundle.get('schemaVersion') == 2 and bundle.get('sections') and bundle.get('dashboard')
          and bundle.get('diagnostics') and bundle.get('redaction', {}).get('status') == 'pass'
          and bundle['redaction'].get('rawSensitiveMaterialExcluded') is True
          and bundle['redaction'].get('redactionFindings') == [], 'support-unavailable')
    work = surfaces['workSnapshot']
    _need(isinstance(work, dict) and work.get('version') == 4 and work.get('dropped') == 0
          and isinstance(work.get('events'), list) and len(work['events']) > 0, 'native-work-missing')
    _need(isinstance(surfaces['appErrors'], list) and surfaces['appErrors']
          and isinstance(surfaces['appAudit'], list) and surfaces['appAudit'], 'app-collector-missing')
    denials = value['denials']
    _need(isinstance(denials, list) and len(denials) == 6, 'denial-roster-invalid')
    required = {'operator/runtime-observation', 'operator/support-bundle', 'operator/app-data/backups',
                'operator/network-budgets', 'operator/beta-dashboard', 'trust-graph/statements'}
    _need({row.get('route') for row in denials if isinstance(row, dict)} == required, 'denial-roster-invalid')
    for row in denials:
        _need(set(row) == {'route', 'status', 'composerCallsBefore', 'composerCallsAfter'}
              and type(row['status']) is int and row['status'] in {401, 403}
              and type(row['composerCallsBefore']) is int and row['composerCallsBefore'] >= 0
              and row['composerCallsAfter'] == row['composerCallsBefore'], 'composition-before-denial')
    counters = value['counters']
    _need(isinstance(counters, dict) and set(counters) == {'graphStatements', 'auditDecisions',
          'fetchCalls', 'workEvents', 'composerCalls'}
          and all(type(count) is int and count > 0 for count in counters.values())
          and counters['workEvents'] == len(work['events']), 'useful-counters-missing')
    return {'caseId': 'privacy', 'component': 'native', 'status': 'verified',
            'evidenceClass': value['evidenceClass'], 'stimulusCount': len(rows),
            'surfaceCount': len(surfaces), 'originalAuthentication': 'not-established',
            'installedObservation': False, 'fullAppBudgets': 'not-observed',
            'releaseEligible': False, 'phaseComplete': False}


def public_projection(coverage):
    """Closed budget facts: no scope, app, graph, source, selection or private artifact hashes."""
    required, observed, missing = (coverage.get(key) for key in ('requiredCases', 'observedCases', 'missingCases'))
    _need(required == list(REQUIRED_CASES) and isinstance(observed, list) and isinstance(missing, list)
          and len(observed) == len(set(observed)) and len(missing) == len(set(missing))
          and set(observed).isdisjoint(missing) and set(observed) | set(missing) == set(required),
          'coverage-invalid')
    classification = coverage.get('evidenceClass')
    _need(classification in {'synthetic-local-cohort', 'native-observation-local-consistency',
                            'installed-cohort-local-consistency', 'original-protected-budget-cohort'},
          'coverage-class-invalid')
    authority = coverage.get('originalAuthentication')
    _need(authority in {'not-established', 'authenticated'}
          and (authority == 'authenticated') == (classification == 'original-protected-budget-cohort'),
          'authority-invalid')
    result = {'schemaVersion': 1, 'kind': 'composed-budget-public-coverage',
              'evidenceClass': classification, 'requiredCases': list(required),
              'observedCases': sorted(observed), 'missingCases': sorted(missing),
              'originalAuthentication': authority,
              'fullAppBudgets': 'observed' if not missing and authority == 'authenticated' else 'not-observed',
              'releaseEligible': False, 'phaseComplete': False}
    _need(not scan_value(result), 'public-scan-failed')
    return result


def verify_browser(value, native, *, native_digest, script_digest):
    """Recompute browser exports and fault observations against the actual native bundle."""
    verify_native(native)
    fields = {'schemaVersion', 'kind', 'transport', 'nativeMemberDigest', 'scriptDigest',
              'clipboardText', 'downloadText', 'downloadName', 'domText', 'persistence',
              'failedExports', 'requests'}
    _encoded(value)
    _need(isinstance(value, dict) and set(value) == fields
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'composed-budget-browser-component'
          and value['transport'] == 'intercepted-local-http'
          and value['nativeMemberDigest'] == native_digest and value['scriptDigest'] == script_digest,
          'browser-binding-invalid')
    markers = [row['marker'] for row in native['stimuli']]
    check_omission(value, markers)
    _need(isinstance(value['clipboardText'], str) and value['clipboardText']
          and value['downloadText'] == value['clipboardText']
          and re.fullmatch('cryptad-support-bundle-[a-zA-Z0-9-]+\\.json', str(value['downloadName'])),
          'browser-export-invalid')
    try:
        bundle = json.loads(native['surfaces']['supportBundle'])
        exported = json.loads(value['clipboardText'])
    except (TypeError, ValueError):
        _need(False, 'browser-json-invalid')
    _need(exported == bundle, 'browser-bundle-substituted')
    _need(value['clipboardText'] == native['surfaces']['supportBundle'].strip() + '\n',
          'browser-wire-substituted')
    _need(value['persistence'] == {'local': [], 'session': [], 'databases': []},
          'browser-persistence-contaminated')
    faults = value['failedExports']
    _need(isinstance(faults, list) and len(faults) == 4
          and {row.get('variant') for row in faults if isinstance(row, dict)} ==
              {'failed', 'malformed', 'digest', 'redaction'}, 'browser-fault-roster-invalid')
    for row in faults:
        _need(set(row) == {'variant', 'copyDisabled', 'downloadDisabled', 'statusText', 'domText'}
              and row['copyDisabled'] is True and row['downloadDisabled'] is True
              and row['statusText'] == 'Support bundle could not be verified; generate it again before export.'
              and isinstance(row['domText'], str) and row['domText'], 'browser-fault-unverified')
    requests = value['requests']
    _need(isinstance(requests, list) and 0 < len(requests) <= 256
          and all(isinstance(row, dict) and set(row) == {'origin', 'path', 'method'}
                  and row['origin'] == 'http://localhost' and row['method'] == 'GET'
                  and isinstance(row['path'], str) and row['path'].startswith(('/api/v1/', '/app/node/'))
                  for row in requests)
          and {'/api/v1/operator/support-bundle', '/api/v1/operator/support-bundle/preview'} <=
              {row['path'] for row in requests}, 'browser-network-invalid')
    return {'caseId': 'privacy', 'variant': 'browser', 'status': 'verified',
            'evidenceClass': 'real-browser-native-response-local-transport',
            'installedObservation': False, 'originalAuthentication': 'not-established'}


def verify_artifacts(value, native, *, native_digest, source_commit):
    """Exact before/after transfer roster and job summary, delegating public field policy."""
    from . import certification_public_export as exports
    if native.get('evidenceClass') == 'installed-four-role-private-observer':
        verify_installed(native)
    else:
        verify_native(native)
    fields = {'schemaVersion', 'kind', 'nativeMemberDigest', 'sourceCommit',
              'files', 'transferFiles', 'jobSummary'}
    _encoded(value)
    _need(isinstance(value, dict) and set(value) == fields
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'composed-budget-artifact-component'
          and value['nativeMemberDigest'] == native_digest and value['sourceCommit'] == source_commit,
          'artifact-binding-invalid')
    candidates = []
    for name in ('files', 'transferFiles'):
        roster = value[name]
        _need(isinstance(roster, dict) and set(roster) == exports.ROSTER, 'artifact-roster-invalid')
        decoded = {}
        for member, text in roster.items():
            _need(isinstance(text, str) and len(text) <= 1024 * 1024, 'artifact-size-invalid')
            try:
                raw = base64.b64decode(text, validate=True)
            except ValueError:
                _need(False, 'artifact-encoding-invalid')
            _need(raw and len(raw) <= 1024 * 1024, 'artifact-size-invalid')
            decoded[member] = raw
        candidates.append(decoded)
    _need(candidates[0] == candidates[1], 'artifact-transfer-substituted')
    raw = candidates[0]
    try:
        summary = exports.verify_export_bytes(raw, source_commit)
    except (ValueError, TypeError, KeyError):
        _need(False, 'artifact-public-fields-invalid')
    _need(summary['exportFailure'] == 'none' and summary['counts']['evidence'] > 0,
          'artifact-source-unverified')
    _need(isinstance(value['jobSummary'], str) and value['jobSummary'].encode() == raw['report.md'],
          'artifact-manifest-invalid')
    markers = [row['marker'] for row in native['stimuli']]
    for name, content in raw.items():
        try:
            candidate = content.decode('utf-8')
        except UnicodeError:
            _need(False, 'artifact-text-invalid')
        check_omission({name: candidate}, markers, public=True)
    check_omission(value['jobSummary'], markers, public=True)
    return {'caseId': 'privacy', 'variant': 'public-artifacts', 'status': 'verified',
            'evidenceClass': 'exact-public-export-local-transfer',
            'originalAuthentication': 'not-established', 'installedObservation': False}


def _installed_privacy_owner():
    """Load only the fixed owning verifier; evidence cannot supply an import or executable."""
    import importlib
    from pathlib import Path
    import sys
    if Path(__file__).absolute().is_relative_to('/opt/cryptad-cross-version'):
        from pr320_original_acquisition import verified_privacy_observer
        return verified_privacy_observer()
    root = Path(__file__).resolve().parents[3]
    prior = list(sys.path)
    try:
        sys.path[:0] = [str(root / 'tools/release-certification/restricted'),
                       str(root / 'tools/release-certification/protected'), str(root / 'tools/interop')]
        owner = importlib.import_module('pr320_privacy_runtime_evidence')
        _need(Path(owner.__file__).resolve() == root / 'tools/release-certification/restricted/pr320_privacy_runtime_evidence.py',
              'installed-owner-invalid')
        return owner
    finally:
        sys.path[:] = prior


def verify_installed(value):
    """Delegate installed native detail verification; original authority remains separate."""
    return _installed_privacy_owner().verify_component(value)


def verify_installed_browser(value, native_component, *, native_digest, script_digest):
    """Verify real installed HTTP browser bytes plus explicitly controlled UI fault fixtures.

    Root provider/namespace/worker matching belongs to the original host consumer. This function
    cannot authenticate a saved root receipt or browser-provider declaration on its own.
    """
    verify_installed(native_component)
    _encoded(value)
    fields = {'schemaVersion', 'kind', 'transport', 'nativeMemberDigest', 'scriptDigest',
              'browserBundleText', 'clipboardText', 'downloadText', 'downloadName', 'domText',
              'persistence', 'appPersistence', 'failedExports', 'browserDenials', 'requests',
              'faultEvidenceClass'}
    _need(isinstance(value, dict) and set(value) == fields
          and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
          and value['kind'] == 'composed-budget-installed-browser-component'
          and value['transport'] == 'selected-role-namespace-http'
          and value['nativeMemberDigest'] == native_digest and value['scriptDigest'] == script_digest
          and value['faultEvidenceClass'] == 'browser-response-negative-fixture', 'installed-browser-binding-invalid')
    markers = [row['marker'] for row in native_component['stimuli']]
    check_omission(value, markers)
    _need(isinstance(value['browserBundleText'], str) and value['browserBundleText']
          and value['clipboardText'] == value['downloadText'] == value['browserBundleText'].strip() + '\n'
          and re.fullmatch('cryptad-support-bundle-[a-zA-Z0-9-]+\\.json', str(value['downloadName'])),
          'installed-browser-export-invalid')
    try:
        bundle = json.loads(value['browserBundleText'])
    except ValueError:
        _need(False, 'installed-browser-json-invalid')
    # The fresh browser response has its own generation time and exact digest. Prior native
    # support bytes prove the same useful sections, not equality across two distinct samples.
    _installed_privacy_owner()._support(bundle, native_component['surfaces']['supportPreview'],
                                      wire=value['browserBundleText'])
    _need(bundle['dashboard'].get('trustGraph', {}).get('statementCount', 0) > 0
          and bundle['diagnostics'].get('sectionCount', 0) > 0, 'installed-browser-empty-export')
    empty = {'local': [], 'session': [], 'databases': []}
    _need(value['persistence'] == value['appPersistence'] == empty, 'installed-browser-persistence')
    faults = value['failedExports']
    _need(isinstance(faults, list) and len(faults) == 4
          and {row.get('variant') for row in faults if isinstance(row, dict)} ==
              {'failed', 'malformed', 'digest', 'redaction'}, 'installed-browser-fault-roster')
    for row in faults:
        _need(set(row) == {'variant', 'copyDisabled', 'downloadDisabled', 'statusText', 'domText'}
              and row['copyDisabled'] is True and row['downloadDisabled'] is True
              and row['statusText'] == 'Support bundle could not be verified; generate it again before export.'
              and isinstance(row['domText'], str) and row['domText'], 'installed-browser-fault-unverified')
    denials = value['browserDenials']
    required = {'operator/runtime-observation', 'operator/network-budgets', 'operator/support-bundle', 'operator/beta-dashboard'}
    _need(isinstance(denials, list) and len(denials) == len(required)
          and {row.get('route') for row in denials if isinstance(row, dict)} == required,
          'installed-browser-denial-roster')
    for row in denials:
        _need(set(row) == {'route', 'status', 'body'} and type(row['status']) is int
              and row['status'] in {401, 403} and isinstance(row['body'], str) and row['body'],
              'installed-browser-denial-unverified')
    requests = value['requests']
    _need(isinstance(requests, list) and 0 < len(requests) <= 256, 'installed-browser-network-missing')
    origins = set()
    for row in requests:
        _need(isinstance(row, dict) and set(row) == {'origin', 'path', 'method'}
              and re.fullmatch('http://127\\.0\\.0\\.1:[1-9][0-9]{0,4}', str(row['origin']))
              and isinstance(row['path'], str) and row['path'].startswith('/')
              and row['method'] in {'GET', 'POST', 'OPTIONS'}, 'installed-browser-network-invalid')
        origins.add(row['origin'])
    _need(all(1 <= int(origin.rsplit(':', 1)[1]) <= 65535 for origin in origins), 'installed-browser-port-invalid')
    app_origins = origins - {'http://127.0.0.1:19402'}
    _need(len(app_origins) == 1 and 'sha256:' + hashlib.sha256(_encoded(next(iter(app_origins)))).hexdigest() ==
          native_component['phaseContexts']['apps']['feed-reader']['originDigest'], 'installed-browser-app-origin-substituted')
    _need('http://127.0.0.1:19402' in origins and len(origins) == 2
          and {'/api/v1/operator/support-bundle', '/api/v1/operator/support-bundle/preview'} <=
              {row['path'] for row in requests}, 'installed-browser-origins-invalid')
    return {'caseId': 'privacy', 'component': 'browser', 'status': 'verified',
            'evidenceClass': 'installed-browser-private-original-matched-local-consistency',
            'installedObservation': False, 'originalAuthentication': 'not-established',
            'fullAppBudgets': 'not-observed', 'releaseEligible': False, 'phaseComplete': False}
