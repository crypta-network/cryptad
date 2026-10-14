"""Fixed bounded private daemon stdio for prospective PR-320 role observations."""
import json
import os
from pathlib import Path
import re
import select
import stat
import time

MAX_STREAM_BYTES = 2 * 1024 * 1024
TAIL_SECONDS = 15
NAMES = ('stdout.private.log', 'stderr.private.log')


class Capture:
    """Drain pipes without accepting truncation, symlinks, reused logs or an unbounded file."""
    def __init__(self, role_root, *, generation=None):
        self.files, self.pipes, self.counts, self.ended = {}, {}, {}, set()
        self.root = Path(role_root) / 'logs'
        self.status = 'in-progress'
        self.generation = generation
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError('pr320-stdio-owner-invalid')
            if generation is not None:
                if not isinstance(generation, str) or re.fullmatch('[0-9a-f]{32}', generation) is None:
                    raise ValueError('pr320-stdio-generation-invalid')
                name = 'stdio-' + generation
                os.mkdir(name, mode=0o700, dir_fd=descriptor)
                parent = descriptor
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
                self.root /= name
            for name in NAMES:
                self.files[name] = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                    os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor)
                self.counts[name] = 0
        except BaseException:
            self.close()
            raise
        finally:
            os.close(descriptor)

    def bind(self, process):
        self.pipes = dict(zip(NAMES, (process.stdout, process.stderr)))
        for pipe in self.pipes.values():
            os.set_blocking(pipe.fileno(), False)

    def pump(self):
        pending = [pipe for name, pipe in self.pipes.items() if name not in self.ended]
        ready, _, _ = select.select(pending, [], [], 0)
        for pipe in ready:
            name = next(name for name, candidate in self.pipes.items() if candidate is pipe)
            # Bound work per loop as well as retained output; pipe backpressure remains explicit.
            for _ in range(32):
                try:
                    raw = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    break
                if not raw:
                    self.ended.add(name)
                    break
                if self.counts[name] + len(raw) > MAX_STREAM_BYTES:
                    self.status = 'output-budget-exhausted'
                    raise ValueError('pr320-stdio-output-budget-exhausted')
                offset = 0
                while offset < len(raw):
                    offset += os.write(self.files[name], raw[offset:])
                self.counts[name] += len(raw)

    def finish(self):
        # The existing role unit allows twenty seconds for its real group stop.
        # Drain within that lifecycle, leaving time to fsync the fixed receipt.
        deadline = time.monotonic() + TAIL_SECONDS
        while len(self.ended) < 2:
            self.pump()
            if time.monotonic() >= deadline:
                self.status = 'tail-unobserved'
                raise ValueError('pr320-stdio-tail-unobserved')
            if len(self.ended) < 2:
                time.sleep(.01)
        self.status = 'complete'

    def close(self):
        for descriptor in self.files.values():
            os.fsync(descriptor)
            os.close(descriptor)
        self.files.clear()
        for pipe in self.pipes.values():
            pipe.close()

    def receipt(self):
        value = {'schemaVersion': 1, 'kind': 'pr320-private-daemon-stdio',
                 'status': self.status, 'bytes': self.counts,
                 'completeStreams': sorted(self.ended), 'perStreamLimit': MAX_STREAM_BYTES}
        if self.generation is not None:
            value.update(schemaVersion=2, generation=self.generation)
        descriptor = os.open(self.root / 'stdio.private.json',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
