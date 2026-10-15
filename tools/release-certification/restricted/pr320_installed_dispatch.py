"""Finite PR-320 kit integration extracted from the 5,000-line campaign driver."""
from pathlib import Path
import sys

_SOURCE = Path(__file__).resolve().parents[3]
if _SOURCE == Path('/opt/cryptad-restricted-test-kit'):
    _SOURCE = Path('/opt/cryptad-cross-version/current').resolve(strict=True)
sys.path.insert(0, str(_SOURCE / 'tools/release-certification/protected'))
import pr320_budget_contract as common
import pr320_storage_contract as contract

EXECUTION_CLASSES = common.PROSPECTIVE_EXECUTION_CLASSES


def fixture(execution_class, source):
    source = Path(source)
    if execution_class == common.RESTART_EXECUTION_CLASS:
        import pr320_restart_selection
        return pr320_restart_selection, source / 'build/pr320-restart-inputs'
    if execution_class == common.CANCELLATION_EXECUTION_CLASS:
        import pr320_owner_selection
        return pr320_owner_selection, source / 'build/pr320-owner-inputs'
    if execution_class == common.PRIVACY_EXECUTION_CLASS:
        import pr320_privacy_selection
        return pr320_privacy_selection, source / 'build/pr320-privacy-inputs'
    if execution_class in common.ROUTE_EXECUTION_CLASSES:
        import pr320_route_selection
        selected = common.prospective_profile(execution_class)
        return pr320_route_selection, source / 'build/pr320-route-inputs' / selected['experiment']
    selected = contract.selected_profile(execution_class)
    import pr320_storage_selection
    return pr320_storage_selection, source / 'build/pr320-storage-inputs' / selected['experiment']


def capture_members(execution_class):
    return (*_component_capture_members(execution_class),
        ('pr320-campaign-root-originals.private.json',
         '/var/lib/cryptad-restricted-workload/authority/pr320-campaign-original-inputs.private.json',
         16 * 1024 * 1024))


def _component_capture_members(execution_class):
    selected = common.prospective_profile(execution_class)
    root = '/var/lib/cryptad-cross-version/experiments/' + selected['experiment'] + '/'
    selection = ('pr320-selection.private.json', '/root/pr314-workload-selection.json', 262144)
    if execution_class == common.RESTART_EXECUTION_CLASS:
        return (selection,
            ('pr319-restart-budget.private.json', root + 'pr319-restart-budget.private.json', 4 * 1024 * 1024),
            ('pr319-restart-attempts.private.jsonl', root + 'pr319-restart-attempts.private.jsonl', 4 * 1024 * 1024))
    if execution_class == common.CANCELLATION_EXECUTION_CLASS:
        return (selection,
            ('pr320-owner-budget.private.json', root + 'pr320-owner-budget.private.json', 4 * 1024 * 1024),
            ('pr320-owner-checkpoints.private.jsonl', root + 'pr320-owner-checkpoints.private.jsonl', 4 * 1024 * 1024),
            ('pr320-owner-root-native.private.json',
             '/var/lib/cryptad-restricted-workload/authority/pr320-owner-original-native.json', 4 * 1024 * 1024))
    if execution_class == common.PRIVACY_EXECUTION_CLASS:
        return (selection,
            ('pr320-privacy-native.private.json', root + 'pr320-privacy-native.private.json', 4 * 1024 * 1024),
            ('pr320-privacy-browser.private.json', root + 'pr320-privacy-browser.private.json', 4 * 1024 * 1024),
            ('pr320-public-artifact.private.json', root + 'pr320-public-artifact.private.json', 2 * 1024 * 1024),
            ('pr320-privacy-checkpoints.private.jsonl', root + 'pr320-privacy-checkpoints.private.jsonl', 4 * 1024 * 1024),
            ('pr320-privacy-originals.private.json',
             '/var/lib/cryptad-restricted-workload/authority/pr320-privacy-originals.private.json', 8 * 1024 * 1024))
    if execution_class in common.ROUTE_EXECUTION_CLASSES:
        return (selection,
            ('pr320-route-budget.private.json', root + 'pr320-route-budget.private.json', 4 * 1024 * 1024),
            ('pr320-route-attempts.private.jsonl', root + 'pr320-route-attempts.private.jsonl', 4 * 1024 * 1024),
            ('pr320-route-root-native.private.json',
             '/var/lib/cryptad-restricted-workload/authority/pr320-route-original-native.json', 4 * 1024 * 1024))
    contract.selected_profile(execution_class)
    return (selection,
            ('pr320-storage-budget.private.json', root + 'pr320-storage-budget.private.json', 4 * 1024 * 1024),
            ('pr320-storage-attempts.private.jsonl', root + 'pr318-storage-attempts.private.jsonl', 4 * 1024 * 1024))


def _admin(execution_class):
    if execution_class == common.RESTART_EXECUTION_CLASS:
        import pr320_restart_admin
        return pr320_restart_admin
    if execution_class == common.CANCELLATION_EXECUTION_CLASS:
        import pr320_owner_admin
        return pr320_owner_admin
    if execution_class == common.PRIVACY_EXECUTION_CLASS:
        import pr320_privacy_admin
        return pr320_privacy_admin
    if execution_class in common.ROUTE_EXECUTION_CLASSES:
        import pr320_route_admin
        return pr320_route_admin
    if execution_class in contract.EXECUTION_CLASSES:
        import pr320_storage_admin
        return pr320_storage_admin
    return None


def configure_sampler(sampler, execution_class, handoff):
    selected = _admin(execution_class)
    if selected is not None:
        sampler.pr320_execution_class = execution_class
        selected.configure_sampler(sampler, execution_class, handoff)


def cleanup_sampler(sampler, diagnostics):
    if sampler is not None:
        selected = _admin(getattr(sampler, 'pr320_execution_class', None))
        if selected is not None:
            selected.cleanup_sampler(sampler, diagnostics)


def cleanup_final(sampler, diagnostics):
    if sampler is not None and getattr(sampler, 'pr320_execution_class', None) == common.PRIVACY_EXECUTION_CLASS:
        _admin(common.PRIVACY_EXECUTION_CLASS).cleanup_final(sampler, diagnostics)


def capture_root(workload, selected, diagnostics, volatile):
    if selected['authorization']['executionClass'] not in EXECUTION_CLASSES:
        raise ValueError('pr320-original-capture-class-invalid')
    from pr320_campaign_capture import prepare_root
    return prepare_root(workload, selected, diagnostics, volatile)


def _driver(execution_class):
    if execution_class == common.RESTART_EXECUTION_CLASS:
        import cross_version_installed_pr320_restart_budgets as driver
        return driver
    if execution_class == common.CANCELLATION_EXECUTION_CLASS:
        import cross_version_installed_owner_budgets as driver
        return driver
    if execution_class == common.PRIVACY_EXECUTION_CLASS:
        import cross_version_installed_privacy_budgets as driver
        return driver
    if execution_class in common.ROUTE_EXECUTION_CLASSES:
        import cross_version_installed_route_budgets as driver
        return driver
    raise ValueError('pr320-component-class-invalid')


def validate_observation(execution_class, value, selection_digest):
    if execution_class in contract.EXECUTION_CLASSES:
        from cross_version_installed_storage_budgets import validate_complete_guest_observation
        validate_complete_guest_observation(value, selection_digest)
    else:
        _driver(execution_class).validate_guest_observation(value, selection_digest)


def attach_context(value, identity, runtime_policy, campaign_deadline):
    if value['executionClass'] in contract.EXECUTION_CLASSES:
        from cross_version_installed_storage_budgets import attach_complete_guest_context
        return attach_complete_guest_context(value, identity, runtime_policy, campaign_deadline)
    return _driver(value['executionClass']).attach_guest_context(value, identity, runtime_policy, campaign_deadline)


def observe(adapter, execution_class, channel, deadline, diagnostic):
    selected = _admin(execution_class)
    if selected is None:
        raise ValueError('pr320-component-class-invalid')
    return selected.run_observer(adapter, channel, deadline, diagnostic)


def purpose(execution_class):
    if execution_class == common.RESTART_EXECUTION_CLASS:
        return 'budget-restart'
    if execution_class == common.CANCELLATION_EXECUTION_CLASS:
        return 'budget-owner'
    if execution_class == common.PRIVACY_EXECUTION_CLASS:
        return 'budget-privacy'
    if execution_class in common.ROUTE_EXECUTION_CLASSES:
        return 'budget-routes'
    if execution_class in contract.EXECUTION_CLASSES:
        return 'budget-storage'
    raise ValueError('pr320-component-class-invalid')


def require_cleanup(execution_class, diagnostics):
    if execution_class == common.RESTART_EXECUTION_CLASS and diagnostics.get('restartAccessCleanup') != 'completed':
        raise ValueError('pr320-restart-restoration-incomplete')
    if execution_class in contract.EXECUTION_CLASSES and diagnostics.get('storageAccessCleanup') != 'completed':
        raise ValueError('pr320-storage-restoration-incomplete')
    if execution_class == common.CANCELLATION_EXECUTION_CLASS and diagnostics.get('ownerOriginalCollection') != 'complete':
        raise ValueError('pr320-owner-originals-incomplete')
    if execution_class == common.PRIVACY_EXECUTION_CLASS and diagnostics.get('privacyCollectorCleanup') != 'completed':
        raise ValueError('pr320-privacy-originals-incomplete')
    if execution_class in common.ROUTE_EXECUTION_CLASSES and diagnostics.get('routeBudgetCollectorCleanup') != 'completed':
        raise ValueError('pr320-route-originals-incomplete')
