"""Prospective PR-320 signed cohort; historical PR-317 through PR-319 rosters remain unchanged."""
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
APP_IDS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')
APPROVED_PERMISSIONS = {
    'feed-reader': ('content.fetch', 'content.subscribe', 'trust.read', 'trust.write',
                    'app.data.read', 'app.data.write'),
    'budget-importer': ('content.fetch', 'content.subscribe', 'trust.read', 'trust.write',
                        'app.data.read', 'app.data.write'),
    'budget-no-trust': ('content.fetch',),
    'budget-no-fetch': ('trust.read', 'trust.write'),
}
PERMISSIONS = APPROVED_PERMISSIONS
PROCESS_CLIENT_APPS = ('feed-reader', 'budget-importer')
PROCESS_CLIENT_PATH = 'tools/release-certification/restricted/pr320_budget_process_client.py'
PROCESS_START_BYTES = b'#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I -S -B lib/pr320-budget-process-client.py\n'
PROCESS_SOCKET_NAME = 'pr320-budget-owner.sock'
PRIVACY_EXECUTION_CLASS = 'pr320-installed-budget-privacy-v1'
CANCELLATION_EXECUTION_CLASS = 'pr320-installed-owner-cancellation-v1'
RESTART_EXECUTION_CLASS = 'pr320-installed-restart-diagnostics-v1'
STORAGE_VARIANTS = (
    ('window-crossing', 'available-capacity'), ('window-crossing', 'contested-capacity'),
    ('partial-rate-write', 'direct-readable-directory-denial'),
    ('partial-rate-write', 'uri-child-write-denial'), ('partial-rate-write', 'uri-import-commit-denial'),
    ('graph-store-unavailable', 'direct-readable-directory-denial'),
    ('graph-store-unavailable', 'uri-readable-directory-denial'),
)
ROUTE_EXECUTION_CLASSES = tuple('pr320-routes-' + name + '-v1' for name in (
    'main', 'interference', 'import-app', 'import-global', 'fetch-app', 'fetch-global', 'lifecycle'))
PROSPECTIVE_EXECUTION_CLASSES = (PRIVACY_EXECUTION_CLASS, CANCELLATION_EXECUTION_CLASS, RESTART_EXECUTION_CLASS,
    *ROUTE_EXECUTION_CLASSES,
    *('pr320-storage-' + case + '-' + variant + '-v1' for case, variant in STORAGE_VARIANTS))


def prospective_profile(execution_class):
    """Dispatch exact code-owned prospective classes without a prefix or selector language."""
    if execution_class == PRIVACY_EXECUTION_CLASS:
        import pr320_privacy_contract
        return pr320_privacy_contract.profile()
    if execution_class == CANCELLATION_EXECUTION_CLASS:
        import pr320_cancellation_contract
        return pr320_cancellation_contract.profile()
    if execution_class == RESTART_EXECUTION_CLASS:
        import pr320_restart_contract
        return pr320_restart_contract.profile()
    if execution_class in ROUTE_EXECUTION_CLASSES:
        import pr320_route_contract
        return pr320_route_contract.selected_profile(execution_class)
    import pr320_storage_contract
    return pr320_storage_contract.selected_profile(execution_class)
