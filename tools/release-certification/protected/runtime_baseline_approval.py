"""Fixed original GitHub review adapter for detached runtime baseline decisions.

Review history has no decision timestamp or attempt identity. This lane permits only attempt one,
uses one fixed job/environment, and records original job completion as an upper bound, never as the
human decision instant. Opaque review contexts bind every privately retained applicability field.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import os
import secrets
import stat
import sys
import json
from pathlib import Path
import re
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / 'interop'))

from original_artifact_authentication import authenticate_original, _gh, _environment, REPOSITORY

WORKFLOW = '.github/workflows/runtime-baseline-approval.yml'
ENVIRONMENT = 'runtime-baseline-approval'
JOB = 'approve-runtime-baseline'
MEMBER = 'runtime-baseline-approval.json'
PROPOSAL_MEMBER = 'runtime-baseline-proposal.json'
PRIVATE_STORE = Path('/var/lib/cryptad-runtime-baselines')
WORKSPACE = Path('/var/lib/cryptad-restricted/resolver')
_AUTHORITY = object()
REQUEST_FIELDS = {'schemaVersion', 'kind', 'proposalDigest', 'proposalByteDigest', 'proposalFinishedAt',
                  'policyDigest', 'scopeDigest', 'status', 'effectiveAt', 'expiresAt', 'producer'}


class ApprovalError(ValueError):
    """Fixed diagnostic without private proposal values."""


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _time(value):
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.utcoffset() != dt.timedelta(0):
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError):
        raise ApprovalError('runtime-approval-time-invalid') from None


def _decode(raw, maximum=65536):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ApprovalError('runtime-approval-duplicate-key')
            result[key] = value
        return result
    try:
        if not isinstance(raw, bytes) or len(raw) > maximum:
            raise ValueError()
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError, UnicodeError):
        raise ApprovalError('runtime-approval-json-invalid') from None


def validate_request(request):
    if (not isinstance(request, dict) or set(request) != REQUEST_FIELDS
            or request['schemaVersion'] != 1 or type(request['schemaVersion']) is not int
            or request['kind'] != 'runtime-baseline-approval-request'
            or request['status'] not in {'active', 'revoked', 'superseded'}):
        raise ApprovalError('runtime-approval-request-invalid')
    for field in ('proposalDigest', 'proposalByteDigest', 'policyDigest', 'scopeDigest'):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', str(request[field])):
            raise ApprovalError('runtime-approval-digest-invalid')
    producer = request['producer']
    if (not isinstance(producer, dict) or set(producer) != {'sourceCommit', 'runId', 'runAttempt', 'jobId'}
            or not re.fullmatch(r'[0-9a-f]{40}', str(producer['sourceCommit']))
            or any(type(producer[k]) is not int or producer[k] < 1 for k in ('runId', 'runAttempt', 'jobId'))
            or producer['runAttempt'] != 1):
        raise ApprovalError('runtime-approval-producer-invalid')
    finished, effective, expires = map(_time, (request['proposalFinishedAt'], request['effectiveAt'], request['expiresAt']))
    if not finished <= effective < expires or expires - effective > dt.timedelta(days=90):
        raise ApprovalError('runtime-approval-window-invalid')
    return request


def decision_comment(context):
    if not isinstance(context, str) or not re.fullmatch(r'[0-9a-f]{64}', context):
        raise ApprovalError('runtime-approval-context-invalid')
    return 'approve-runtime-baseline:' + context


def _review(request, environment, *, completed, context, producer):
    prefix = f'repos/{REPOSITORY}'
    run = _gh(['api', f"{prefix}/actions/runs/{producer['runId']}/attempts/1"], environment)
    if (run.get('id') != producer['runId'] or run.get('run_attempt') != 1
            or run.get('head_sha') != producer['sourceCommit'] or run.get('path') != WORKFLOW
            or run.get('event') != 'workflow_dispatch'
            or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('actor', {}).get('login') != 'leumor'
            or run.get('triggering_actor', {}).get('login') != 'leumor'
            or completed and (run.get('status') != 'completed' or run.get('conclusion') != 'success')):
        raise ApprovalError('runtime-approval-run-mismatch')
    # The run-level endpoint otherwise permits an old attempt's approval to authorize a rerun.
    current = _gh(['api', f"{prefix}/actions/runs/{producer['runId']}"], environment)
    if current.get('run_attempt') != 1:
        raise ApprovalError('runtime-approval-rerun-forbidden')
    pages = _gh(['api', '--paginate', '--slurp', f"{prefix}/actions/runs/{producer['runId']}/attempts/1/jobs?per_page=100"], environment)
    jobs = [j for page in pages for j in page.get('jobs', []) if j.get('name') == JOB]
    if (len(jobs) != 1 or jobs[0].get('id') != producer['jobId']
            or jobs[0].get('head_sha') != producer['sourceCommit']
            or completed and jobs[0].get('conclusion') != 'success'):
        raise ApprovalError('runtime-approval-job-mismatch')
    job = jobs[0]
    if _time(job.get('started_at')) < _time(request['proposalFinishedAt']):
        raise ApprovalError('runtime-approval-before-proposal')
    history = _gh(['api', f"{prefix}/actions/runs/{producer['runId']}/approvals"], environment)
    if not isinstance(history, list):
        raise ApprovalError('runtime-approval-history-invalid')
    rows = [row for row in history if isinstance(row, dict) and any(
        env.get('name') == ENVIRONMENT for env in row.get('environments', []) if isinstance(env, dict))]
    if len(rows) != 1 or rows[0].get('state') != 'approved' or rows[0].get('comment') != decision_comment(context):
        raise ApprovalError('runtime-approval-decision-missing-or-conflicting')
    user = rows[0].get('user', {})
    login, identifier = user.get('login'), user.get('id')
    if (not isinstance(login, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,39}', login)
            or type(identifier) is not int or identifier < 1 or user.get('type') != 'User'
            or login.lower() in {run['actor']['login'].lower(), run['triggering_actor']['login'].lower()}):
        raise ApprovalError('runtime-approval-reviewer-separation-invalid')
    permission = _gh(['api', f'{prefix}/collaborators/{login}/permission'], environment)
    if (permission.get('role_name', permission.get('permission')) not in {'admin', 'maintain'}
            or permission.get('user', {}).get('id') != identifier):
        raise ApprovalError('runtime-approval-reviewer-role-invalid')
    return {'login': login, 'id': identifier, 'role': 'repository-maintainer'}, job


def _private_directory(root):
    root = Path(root)
    for path in (root, *root.parents):
        try:
            observed = path.lstat()
        except OSError:
            raise ApprovalError('runtime-approval-private-store-unavailable') from None
        if stat.S_ISLNK(observed.st_mode) or observed.st_uid != 0 or observed.st_mode & 0o022:
            raise ApprovalError('runtime-approval-private-store-untrusted')
    if root.stat().st_mode & 0o077:
        raise ApprovalError('runtime-approval-private-store-untrusted')
    return root


def prepare_request(proposal_bytes, request, private_store=PRIVATE_STORE):
    """Freeze private request once before public opaque-context review; requires installed root job."""
    validate_request(request)
    if digest(proposal_bytes) != request['proposalByteDigest'] or digest(_bytes(_decode(proposal_bytes, 16 * 1024 * 1024))) != request['proposalDigest']:
        raise ApprovalError('runtime-approval-proposal-substituted')
    if os.geteuid() != 0 or os.environ.get('GITHUB_JOB') != 'prepare-runtime-baseline':
        raise ApprovalError('runtime-approval-fixed-preparation-required')
    root = _private_directory(private_store)
    producer = request['producer']
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_SHA') != producer['sourceCommit']
            or os.environ.get('GITHUB_RUN_ID') != str(producer['runId']) or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'):
        raise ApprovalError('runtime-approval-fixed-preparation-required')
    context = secrets.token_hex(32)
    descriptor = os.open(root / (context + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(_bytes(request))
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o400)
    descriptor = os.open(root / (context + '.proposal.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(proposal_bytes)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o400)
    return {'schemaVersion': 1, 'kind': 'runtime-baseline-proposal-anchor',
            'approvalContext': context, 'producer': producer}


def _private_request(context, private_store):
    decision_comment(context)
    root = _private_directory(private_store)
    try:
        descriptor = os.open(root / (context + '.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ApprovalError('runtime-approval-private-request-unavailable') from None
    with os.fdopen(descriptor, 'rb') as stream:
        observed = os.fstat(stream.fileno())
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o400 or observed.st_size > 65536):
            raise ApprovalError('runtime-approval-private-request-untrusted')
        return validate_request(_decode(stream.read(65537)))


def _require_current_context(context, private_store):
    """Apply operator denial only after the caller has verified original integrity."""
    decision_comment(context)
    root = _private_directory(private_store)
    if os.path.lexists(root / (context + '.revoked')) or os.path.lexists(root / (context + '.superseded')):
        raise ApprovalError('runtime-approval-context-revoked-or-superseded')


def read_private_proposal(context, private_store=PRIVATE_STORE):
    """Read immutable proposal bytes for integrity verification, without granting current use."""
    decision_comment(context)
    root = _private_directory(private_store)
    try:
        descriptor = os.open(root / (context + '.proposal.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ApprovalError('runtime-approval-private-proposal-unavailable') from None
    with os.fdopen(descriptor, 'rb') as stream:
        observed = os.fstat(stream.fileno())
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o400 or observed.st_size > 16 * 1024 * 1024):
            raise ApprovalError('runtime-approval-private-proposal-untrusted')
        raw = stream.read(16 * 1024 * 1024 + 1)
    request = _private_request(context, private_store)
    if (digest(raw) != request['proposalByteDigest']
            or digest(_bytes(_decode(raw, 16 * 1024 * 1024))) != request['proposalDigest']):
        raise ApprovalError('runtime-approval-private-proposal-substituted')
    return raw

def _original_member(coordinates, private_root, member, family, job, reviewed_source_commit):
    if (coordinates.get('sourceFamily') != family or coordinates.get('sourceCommit') != reviewed_source_commit
            or coordinates.get('runAttempt') != 1 or coordinates.get('jobName') != job
            or coordinates.get('artifactName') != f"{family}-{coordinates.get('runId')}-1"):
        raise ApprovalError('runtime-approval-original-selection-invalid')
    original = authenticate_original(coordinates, Path(private_root))
    try:
        with zipfile.ZipFile(io.BytesIO(original.content)) as archive:
            entries = archive.infolist()
            if (len(entries) != 1 or entries[0].filename != member or entries[0].file_size > 65536
                    or (entries[0].external_attr >> 16) & 0o170000 == 0o120000):
                raise ApprovalError('runtime-approval-member-invalid')
            raw = archive.read(entries[0])
    except (zipfile.BadZipFile, OSError):
        raise ApprovalError('runtime-approval-archive-invalid') from None
    env = _environment()
    with tempfile.TemporaryDirectory(dir=private_root) as directory:
        path = Path(directory) / member
        path.write_bytes(raw)
        proof = _gh(['attestation', 'verify', str(path), '--repo', REPOSITORY,
                     '--signer-workflow', REPOSITORY + '/' + WORKFLOW, '--source-digest', reviewed_source_commit,
                     '--signer-digest', reviewed_source_commit, '--format', 'json'], env)
    invocation = f"https://github.com/{REPOSITORY}/actions/runs/{coordinates['runId']}/attempts/1"
    if not isinstance(proof, list) or not any(row.get('verificationResult', {}).get('signature', {}).get('certificate', {}).get('runInvocationURI') == invocation for row in proof if isinstance(row, dict)):
        raise ApprovalError('runtime-approval-attested-attempt-mismatch')
    from restricted_results import verify_original
    verify_original(raw, coordinates, {'baseline-prepare'} if member == PROPOSAL_MEMBER else {'baseline-approve'})
    return _decode(raw), original, digest(raw)


def _prepared(origin, private_root, private_store, reviewed_source_commit):
    anchor, original, _ = _original_member(origin, private_root, PROPOSAL_MEMBER,
        'runtime-baseline-proposal', 'prepare-runtime-baseline', reviewed_source_commit)
    if (not isinstance(anchor, dict) or set(anchor) != {'schemaVersion', 'kind', 'approvalContext', 'producer'}
            or anchor.get('schemaVersion') != 1 or anchor.get('kind') != 'runtime-baseline-proposal-anchor'
            or anchor.get('producer') != {k: origin[k] for k in ('sourceCommit', 'runId', 'runAttempt', 'jobId')}):
        raise ApprovalError('runtime-approval-preparation-anchor-invalid')
    request = _private_request(anchor['approvalContext'], private_store)
    read_private_proposal(anchor['approvalContext'], private_store)
    if request['producer'] != anchor['producer'] or _time(request['proposalFinishedAt']) > _time(original.job_completed_at):
        raise ApprovalError('runtime-approval-private-preparation-mismatch')
    return request, anchor['approvalContext'], original.job_completed_at


def produce_approval(preparation_origin, private_root, *, private_store=PRIVATE_STORE):
    """Authenticate frozen private preparation and emit only an opaque reviewed public anchor."""
    source = os.environ.get('GITHUB_SHA')
    request, context, prepared_by = _prepared(preparation_origin, private_root, private_store, source)
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_JOB') != JOB or os.environ.get('GITHUB_RUN_ATTEMPT') != '1':
        raise ApprovalError('runtime-approval-fixed-producer-required')
    try:
        run_id = int(os.environ['GITHUB_RUN_ID'])
    except (ValueError, KeyError):
        raise ApprovalError('runtime-approval-fixed-producer-required') from None
    env = _environment()
    pages = _gh(['api', '--paginate', '--slurp', f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/1/jobs?per_page=100'], env)
    jobs = [j for page in pages for j in page.get('jobs', []) if j.get('name') == JOB]
    if len(jobs) != 1:
        raise ApprovalError('runtime-approval-job-mismatch')
    producer = {'sourceCommit': source, 'runId': run_id, 'runAttempt': 1, 'jobId': jobs[0]['id']}
    _, job = _review(request, env, completed=False, context=context, producer=producer)
    if _time(prepared_by) > _time(job['started_at']):
        raise ApprovalError('runtime-approval-preparation-after-review-boundary')
    _require_current_context(context, private_store)
    return {'schemaVersion': 1, 'kind': 'runtime-baseline-approval-anchor', 'approvalContext': context,
            'preparationOrigin': preparation_origin, 'producer': producer}


class AuthenticatedApproval:
    """Immutable original verified decision; accessor returns a defensive decoded copy."""
    __slots__ = ('_payload',)

    def __init__(self, authority, decision):
        if authority is not _AUTHORITY:
            raise ApprovalError('runtime-approval-original-authority-required')
        object.__setattr__(self, '_payload', _bytes(decision))

    def __setattr__(self, name, value):
        raise ApprovalError('runtime-approval-immutable')

    def decision(self):
        return json.loads(self._payload)


def authenticate_approval(coordinates, private_root, *, proposal_digest, proposal_byte_digest,
                          proposal_finished_at, cutoff, reviewed_source_commit, private_store=PRIVATE_STORE,
                          expected_policy_digest=None, expected_scope_digest=None, expected_context=None):
    """Reauthenticate private proposal, original opaque anchors, actual review and current use."""
    decision, original, byte_digest = _original_member(coordinates, private_root, MEMBER,
        'runtime-baseline-approval', JOB, reviewed_source_commit)
    if (not isinstance(decision, dict) or set(decision) != {'schemaVersion', 'kind', 'approvalContext', 'preparationOrigin', 'producer'}
            or decision.get('schemaVersion') != 1 or decision.get('kind') != 'runtime-baseline-approval-anchor'
            or decision.get('producer') != {k: coordinates[k] for k in ('sourceCommit', 'runId', 'runAttempt', 'jobId')}):
        raise ApprovalError('runtime-approval-record-invalid')
    request, context, prepared_by = _prepared(decision['preparationOrigin'], private_root, private_store, reviewed_source_commit)
    if (decision['approvalContext'] != context or request['proposalDigest'] != proposal_digest
            or request['proposalByteDigest'] != proposal_byte_digest or request['proposalFinishedAt'] != proposal_finished_at):
        raise ApprovalError('runtime-approval-proposal-binding-mismatch')
    reviewer, job = _review(request, _environment(), completed=True, context=context, producer=decision['producer'])
    completed = _time(job.get('completed_at'))
    if (_time(prepared_by) > _time(job['started_at'])
            or original.job_completed_at != job.get('completed_at')):
        raise ApprovalError('runtime-approval-original-job-integrity-invalid')
    if ((expected_policy_digest is not None and request['policyDigest'] != expected_policy_digest)
            or (expected_scope_digest is not None and request['scopeDigest'] != expected_scope_digest)
            or (expected_context is not None and context != expected_context)):
        raise ApprovalError('runtime-approval-selected-scope-mismatch')
    _require_current_context(context, private_store)
    if request['status'] != 'active' or not _time(request['effectiveAt']) <= completed <= _time(cutoff) < _time(request['expiresAt']):
        raise ApprovalError('runtime-approval-not-currently-applicable')
    return AuthenticatedApproval(_AUTHORITY, {**request, 'kind': 'runtime-baseline-approval',
        'reviewer': reviewer, 'producer': decision['producer'], 'approvalContext': context,
        'approvalCompletedBy': job['completed_at'], 'originalCoordinates': original.coordinates,
        'decisionByteDigest': byte_digest, 'asOf': cutoff,
        'statusPolicy': 'current-review-history-root-deny-markers-and-bounded-expiry-v1'})


def _configuration(path, maximum=65536):
    """Read an administrator-installed bounded private file without links or alternate owners."""
    from cross_version_supervisor_authority import secured
    selected = Path(path)
    for parent in selected.parents:
        observed = parent.lstat()
        if stat.S_ISLNK(observed.st_mode) or observed.st_uid != 0 or observed.st_mode & 0o022:
            raise ApprovalError('runtime-approval-configuration-parent-untrusted')
    secured(selected, private=True)
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        observed = os.fstat(stream.fileno())
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size > maximum:
            raise ApprovalError('runtime-approval-configuration-invalid')
        return _decode(stream.read(maximum + 1), maximum)


def execute_owned(operation):
    """Return the existing owner's closed result inside the installed controller.

    The controller authenticates and supplies the original job context before calling this
    function. This entrypoint retains all original source, job, proposal and reviewer checks;
    its return value is data, never a transferable approval capability.
    """
    from cross_version_supervisor_authority import installed_identity, run_identity
    if os.geteuid() != 0 or operation not in ('prepare', 'approve'):
        raise ApprovalError('runtime-approval-fixed-operation-required')
    identity, producer = installed_identity(), run_identity()
    if identity['sourceCommit'] != producer['sourceCommit'] or producer['runAttempt'] != 1:
        raise ApprovalError('runtime-approval-installed-source-mismatch')
    job_name = 'prepare-runtime-baseline' if operation == 'prepare' else JOB
    if os.environ.get('GITHUB_JOB') != job_name:
        raise ApprovalError('runtime-approval-fixed-job-required')
    pages = _gh(['api', '--paginate', '--slurp',
        f"repos/{REPOSITORY}/actions/runs/{producer['runId']}/attempts/1/jobs?per_page=100"], _environment())
    jobs = [job for page in pages for job in page.get('jobs', []) if job.get('name') == job_name]
    if len(jobs) != 1 or jobs[0].get('head_sha') != producer['sourceCommit']:
        raise ApprovalError('runtime-approval-job-mismatch')
    producer['jobId'] = jobs[0]['id']
    with tempfile.TemporaryDirectory(prefix='runtime-baseline-private-',
                                     dir=_private_directory(WORKSPACE)) as temporary:
        if operation == 'approve':
            origin = _configuration('/etc/cryptad-certification/runtime-baseline-approval-origin.json')
            result = produce_approval(origin, Path(temporary))
        else:
            from runtime_baseline_admission import authenticate_observation, prepare_proposal
            config = _configuration('/etc/cryptad-certification/runtime-baseline-preparation.json')
            if (not isinstance(config, dict) or set(config) != {'campaignPath', 'policyPath', 'observations', 'requestPath'}
                    or not isinstance(config['observations'], list) or not 1 <= len(config['observations']) <= 32):
                raise ApprovalError('runtime-approval-preparation-config-invalid')
            campaign, policy = _configuration(config['campaignPath']), _configuration(config['policyPath'])
            observations = []
            for index, row in enumerate(config['observations']):
                if not isinstance(row, dict) or set(row) != {'coordinates', 'bundlePath'}:
                    raise ApprovalError('runtime-approval-preparation-observation-invalid')
                observations.append(authenticate_observation(row['coordinates'], _configuration(row['bundlePath'], 16 * 1024 * 1024),
                    Path(temporary) / f'reference-{index}', cutoff=dt.datetime.now(dt.timezone.utc).isoformat()))
            proposal = prepare_proposal(campaign, observations, policy)
            from runtime_reference_ledger import verify_complete
            verify_complete(campaign, [row['experimentId'] for row in proposal['attemptLedger']])
            raw = _bytes(proposal)
            request = _configuration(config['requestPath'])
            if not isinstance(request, dict) or set(request) != {'status', 'effectiveAt', 'expiresAt'}:
                raise ApprovalError('runtime-approval-request-config-invalid')
            request = {**request, 'schemaVersion': 1, 'kind': 'runtime-baseline-approval-request',
                'producer': producer, 'scopeDigest': digest(_bytes(campaign['scope'])), 'proposalDigest': digest(raw), 'proposalByteDigest': digest(raw),
                'proposalFinishedAt': proposal['finishedAt'], 'policyDigest': digest(_bytes(policy))}
            result = prepare_request(raw, request)
        return result


def main(argv=None):
    """Legacy fixed installed CLI; the restricted controller calls ``execute_owned`` directly."""
    args = sys.argv[1:] if argv is None else argv
    if args not in (['prepare'], ['approve']):
        raise ApprovalError('runtime-approval-fixed-operation-required')
    # Only these closed opaque anchor records cross the public workflow stdout boundary.
    print(_bytes(execute_owned(args[0])).decode())


if __name__ == '__main__':
    try:
        main()
    except (ApprovalError, ValueError, OSError, KeyError, TypeError):
        print('runtime-baseline-protected-operation-failed', file=sys.stderr)
        raise SystemExit(1) from None
