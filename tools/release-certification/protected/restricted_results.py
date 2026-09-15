"""Additional retained-owner check after original producer/member authentication.

This does not create admission capabilities. The original consumer must still run every existing
original, private/native, review and lifetime check. Historical Git sources keep historical scope.
"""
from pathlib import Path
import os
import json
import hashlib
import re

from restricted_protocol import BoundaryError, MAX_RESULT, decode, encode

PREFIX = Path('/opt/cryptad-cross-version')


def verify_original(raw, coordinates, methods):
    """Require a retained exact result for a source installed under the restricted contract."""
    if not Path(__file__).absolute().is_relative_to(PREFIX):
        return  # Ordinary historical/offline consumer path makes no restricted-worker claim.
    from restricted_worker import (OPERATIONS, MAX_RECORD, read, secure, validate_record, digest,
                                   require_not_revoked)
    source = coordinates['sourceCommit']
    versions = secure(PREFIX / 'versions', private=False)
    entries = sorted(versions.iterdir())
    if len(entries) > 128:
        raise BoundaryError('restricted-version-history-limit')
    governed = False
    for entry in entries:
        manifest_path = entry / '.restricted-manifest.json'
        secure(manifest_path, private=False)
        if manifest_path.stat().st_size > 32 * 1024 * 1024:
            raise BoundaryError('restricted-version-history-limit')
        manifest_bytes = manifest_path.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != entry.name:
            raise BoundaryError('restricted-version-history-substituted')
        manifest = json.loads(manifest_bytes)
        if manifest.get('sourceCommit') == source:
            governed = True
    if os.geteuid() != 0:
        raise BoundaryError('restricted-retained-owner-required')
    expected = {key: coordinates[key] for key in ('sourceCommit', 'runId', 'runAttempt', 'jobId')}
    roots = sorted(root for root in secure(OPERATIONS).iterdir()
                   if re.fullmatch('[0-9a-f]{64}', root.name))
    if len(roots) > 1024:
        raise BoundaryError('restricted-operation-history-limit')
    matches = []
    for root in roots:
        secure(root)
        registration_raw = read(root / 'registration.json')
        registration = validate_record(decode(registration_raw, MAX_RECORD))
        if registration['context'] != expected or registration['method'] not in methods:
            continue
        governed = True
        require_not_revoked(root, registration)
        retained = decode(read(root / 'result.json', MAX_RESULT), MAX_RESULT)
        if retained.get('registrationDigest') != digest(registration_raw):
            raise BoundaryError('restricted-retained-result-substituted')
        public = encode(retained['result'])
        if retained['receipt'] != {'schemaVersion': 1, 'kind': 'restricted-owner-result',
                'operationId': registration['handle'], 'method': registration['method'],
                'bundleIdentity': registration['bundleIdentity'], 'resultDigest': digest(public)}:
            raise BoundaryError('restricted-retained-result-substituted')
        matches.append(public + b'\n')
    if not governed:
        return  # Historical original, with no new isolation claim or capability.
    if len(matches) != 1 or matches[0] != raw:
        raise BoundaryError('restricted-original-owner-result-unavailable')
