"""Fixed root-owned private freeze operation; only sealed output returns to the runner.

The parent retains no private selection coordinates. The owning subprocess authenticates original
inputs with provisioned keys, while the native verifier retains its separate confined namespace.
"""
from pathlib import Path
import argparse
import os
import subprocess
import sys
import tempfile

import maintenance_runtime_metadata as metadata


def seal_with_authority(freeze, package, runtime_root, inputs):
    """Invoke only the source-owned producer with the original-provider environment."""
    command = ['sudo', '--non-interactive', '--preserve-env=GITHUB_ACTIONS,GH_TOKEN',
               '/usr/bin/python3', str(Path(__file__).resolve()),
               '--package', str(package), '--runtime-root', str(runtime_root), '--inputs', str(inputs)]
    try:
        result = subprocess.run(command, input=metadata.canonical_bytes(freeze), capture_output=True,
                                timeout=1800, check=True)
        if len(result.stdout) > 2 * 1024 * 1024:
            raise ValueError()
        sealed = metadata.read_json(result.stdout)
        from maintenance_runtime_companion import inspect
        inspect(sealed, runtime_root)
        return sealed
    except (ValueError, OSError, subprocess.SubprocessError):
        raise metadata.RuntimeMetadataError('runtime-metadata-freeze-sealing-failed') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--runtime-root', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ValueError()
        # sudo supplies these identities; dispatch cannot choose an output owner or key path.
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        if uid <= 0 or gid < 0:
            raise ValueError()
        raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError()
        freeze = metadata.read_json(raw)
        from maintenance_runtime_inputs import detect_private_inputs, projection_origin
        if not detect_private_inputs(args.inputs):
            raise ValueError()
        origin = projection_origin(args.inputs)
        with tempfile.TemporaryDirectory(prefix='maintenance-freeze-original-', dir='/tmp') as directory:
            sealed = metadata.seal_private_freeze(freeze, args.package, args.runtime_root,
                projection_origin=origin, private_root=Path(directory))
        from maintenance_runtime_companion import inspect, DESCRIPTOR, CIPHERTEXT
        inspect(sealed, args.runtime_root)
        # Transfer only the fixed inspected encrypted roster, retaining owner-only access.
        for path in (args.runtime_root / DESCRIPTOR, args.runtime_root / CIPHERTEXT, args.runtime_root):
            os.chown(path, uid, gid, follow_symlinks=False)
        sys.stdout.buffer.write(metadata.canonical_bytes(sealed))
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print('runtime-metadata-freeze-sealing-failed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
