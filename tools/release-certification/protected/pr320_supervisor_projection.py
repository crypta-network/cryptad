"""Opaque public handoff for prospective budget supervisor originals.

The original attested member carries only job, operation and an unpredictable receipt.
Private plans, scope hashes and journal summaries stay in the owned root store. Reopening
requires the exact attested envelope and the owning supervisor's original authentication.
Historical supervisor reports retain their original bytes and validation.
"""
from pathlib import Path
import os
import re
import uuid

ROOT = Path('/var/lib/cryptad-cross-version-authority/budget-supervisor-originals')


def validate(value):
    from cross_version_supervisor_authority import AuthorityError
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'kind', 'operation',
            'job', 'purpose', 'releaseEligible', 'privateOriginalReceipt'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 9
            or value['kind'] != 'cryptad-cross-version-supervisor'
            or value['operation'] not in {'authorize', 'start', 'checkpoint', 'finish'}
            or value['purpose'] != 'nonrelease-observed-experiment'
            or value['releaseEligible'] is not False):
        raise AuthorityError('protected-budget-public-report-invalid')
    receipt = value['privateOriginalReceipt']
    job = value['job']
    if (not isinstance(job, dict) or set(job) != {'sourceCommit', 'runId', 'runAttempt'}
            or not isinstance(job['sourceCommit'], str)
            or re.fullmatch('[0-9a-f]{40}', job['sourceCommit']) is None
            or any(type(job[key]) is not int or not 1 <= job[key] < 2**53
                   for key in ('runId', 'runAttempt'))):
        raise AuthorityError('protected-budget-public-job-invalid')
    if (not isinstance(receipt, dict) or set(receipt) != {'schemaVersion', 'kind', 'receiptId'}
            or type(receipt['schemaVersion']) is not int or receipt['schemaVersion'] != 1
            or receipt['kind'] != 'pr320-private-supervisor-original'
            or not isinstance(receipt['receiptId'], str)
            or re.fullmatch('[0-9a-f]{32}', receipt['receiptId']) is None):
        raise AuthorityError('protected-budget-public-receipt-invalid')
    return value


def retain(report):
    """Retain the actual owned report; no caller-supplied authority flag is accepted."""
    from cross_version_supervisor_authority import _atomic, AuthorityError, validate_report
    if os.geteuid() != 0 or not Path(__file__).absolute().is_relative_to('/opt/cryptad-cross-version'):
        raise AuthorityError('protected-budget-report-owner-required')
    validate_report(report)
    receipt = {'schemaVersion': 1, 'kind': 'pr320-private-supervisor-original',
               'receiptId': uuid.uuid4().hex}
    envelope = validate({key: report[key] for key in ('kind', 'operation', 'job',
        'purpose', 'releaseEligible')} | {'schemaVersion': 9, 'privateOriginalReceipt': receipt})
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_uid != 0 or ROOT.stat().st_mode & 0o077:
        raise AuthorityError('protected-budget-report-root-not-owned')
    _atomic(ROOT / (receipt['receiptId'] + '.json'),
            {'schemaVersion': 1, 'envelope': envelope, 'report': report}, 0o400)
    return envelope


def reopen(envelope):
    """Resolve only after original artifact/job/attestation verification by the owner."""
    from cross_version_supervisor_authority import AuthorityError, validate_report
    from composed_budget_campaign_admission import _read_root
    validate(envelope)
    if os.geteuid() != 0:
        raise AuthorityError('protected-budget-report-owner-required')
    retained = _read_root(ROOT / (envelope['privateOriginalReceipt']['receiptId'] + '.json'))
    if (not isinstance(retained, dict) or set(retained) != {'schemaVersion', 'envelope', 'report'}
            or type(retained['schemaVersion']) is not int or retained['schemaVersion'] != 1
            or retained['envelope'] != envelope):
        raise AuthorityError('protected-budget-report-substituted')
    report = validate_report(retained['report'])
    if any(report[key] != envelope[key] for key in ('kind', 'operation', 'job', 'purpose', 'releaseEligible')):
        raise AuthorityError('protected-budget-report-substituted')
    return report
