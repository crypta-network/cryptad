"""Closed baseline configuration roster and checks at the owning read boundary."""
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import hashlib

from restricted_protocol import BoundaryError, decode

BASE = '/etc/cryptad-certification/'
PREPARATION = BASE + 'runtime-baseline-preparation.json'
ORIGIN = BASE + 'runtime-baseline-approval-origin.json'
_ACTIVE = ContextVar('restricted_configuration', default=None)


def closure(method, reader):
    if method == 'baseline-approve':
        return {ORIGIN}
    if method != 'baseline-prepare':
        return None  # Other owners use their existing input/activation contracts.
    config = decode(reader(Path(PREPARATION), 65536), 65536)
    if (not isinstance(config, dict)
            or set(config) != {'campaignPath', 'policyPath', 'observations', 'requestPath'}
            or not isinstance(config['observations'], list) or not 1 <= len(config['observations']) <= 32):
        raise BoundaryError('restricted-configuration-roster-invalid')
    names = [PREPARATION, config['campaignPath'], config['policyPath'], config['requestPath']]
    for row in config['observations']:
        if not isinstance(row, dict) or set(row) != {'coordinates', 'bundlePath'}:
            raise BoundaryError('restricted-configuration-roster-invalid')
        names.append(row['bundlePath'])
    for name in names:
        if (not isinstance(name, str) or Path(name).as_posix() != name
                or '..' in Path(name).parts or not name.startswith(BASE)
                or name == BASE + 'restricted-provider.json'):
            raise BoundaryError('restricted-configuration-path-invalid')
    return set(names)


def require_roster(method, names, reader):
    required = closure(method, reader)
    if required is not None and set(names) != required:
        raise BoundaryError('restricted-configuration-roster-mismatch')


def check_read(path, raw):
    bindings = _ACTIVE.get()
    if bindings is not None:
        expected = bindings.get(str(path))
        if expected != {'digest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'size': len(raw)}:
            raise BoundaryError('restricted-configuration-read-substituted')
    return raw


@contextmanager
def owning_configuration(record):
    token = _ACTIVE.set(record['configurationFiles'])
    try:
        yield
    finally:
        _ACTIVE.reset(token)
