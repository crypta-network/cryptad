"""Finite owner roster for prospective cohort selection, independent of release authority."""
from .composed_budget_evidence import REQUIRED_CASES

STORAGE_VARIANTS = (
    ('window-crossing', 'available-capacity'),
    ('window-crossing', 'contested-capacity'),
    ('partial-rate-write', 'direct-readable-directory-denial'),
    ('partial-rate-write', 'uri-child-write-denial'),
    ('partial-rate-write', 'uri-import-commit-denial'),
    ('graph-store-unavailable', 'direct-readable-directory-denial'),
    ('graph-store-unavailable', 'uri-readable-directory-denial'),
)
STORAGE_EXPERIMENTS = frozenset('pr320-storage-' + case + '-' + variant
                                for case, variant in STORAGE_VARIANTS)
BUDGET_EXPERIMENTS = frozenset({
    'pr317-namespace-bound-composed-budget',
    'pr318-fixed-window-partial-store',
    'pr319-composed-budget-restart-diagnostics',
    'pr320-installed-budget-privacy',
    'pr320-installed-owner-cancellation',
    'pr320-installed-restart-diagnostics',
}) | STORAGE_EXPERIMENTS | frozenset('pr320-routes-' + profile for profile in
    ('main', 'interference', 'import-app', 'import-global', 'fetch-app', 'fetch-global', 'lifecycle'))
# Route names are fixed. Applicable variant completeness is additional to case presence.
ROUTE_CASES = tuple(case for case in REQUIRED_CASES if case not in {
    'authorization-denied', 'import-concurrency', 'fetch-concurrency', 'timeout', 'cancellation', 'retry',
    'window-crossing', 'partial-rate-write', 'graph-store-unavailable',
    'graceful-restart', 'abrupt-restart', 'diagnostics-unavailable', 'privacy'})
RESTART_VARIANTS = (
    ('graceful-restart', 'settled-graceful'),
    ('abrupt-restart', 'settled-abrupt'),
    ('abrupt-restart', 'inflight-abrupt'),
    ('diagnostics-unavailable', 'enumeration-only'),
    ('diagnostics-unavailable', 'required-key-unreadable'),
)
CAUSAL_VARIANTS = (
    ('import-concurrency', 'app'), ('import-concurrency', 'global'),
    ('fetch-concurrency', 'app'), ('fetch-concurrency', 'global'),
    ('timeout', 'deferred-normal-owner'), ('cancellation', 'deferred-normal-owner'),
    ('retry', 'independently-charged'),
)
PRIVACY_VARIANTS = tuple(('privacy', variant) for variant in ('native', 'browser', 'public-artifacts'))
AUTHORIZATION_VARIANTS = (('authorization-denied', 'no-trust'), ('authorization-denied', 'no-fetch'))
REQUIRED_VARIANTS = tuple((case, 'native-route') for case in ROUTE_CASES) + AUTHORIZATION_VARIANTS + CAUSAL_VARIANTS + STORAGE_VARIANTS + RESTART_VARIANTS + PRIVACY_VARIANTS
