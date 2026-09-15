"""Bounded execution of one selected local helper in its own process group."""
from __future__ import annotations
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Callable


def run(arguments: list[str], *, environment: dict[str, str], payload: bytes | None = None,
        timeout: float = 180, output_limit: int = 32768,
        diagnostic_sink: Callable[[bytes, bytes], None] | None = None) -> bytes:
    """Drain both pipes under one deadline and terminate only this newly owned process group.

    A trusted optional sink receives at most ``output_limit`` bytes from each stream after
    cleanup, including failed executions. It must use bounded private storage and must not
    publish the bytes. The sink never grants authority to output or establishes quiescence
    beyond this helper's process group; the installed owner still checks its complete cgroup.
    """
    if payload is not None and len(payload) > 16384:
        raise ValueError("bounded_process_input_exceeded")
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, start_new_session=True)
    except OSError:
        if diagnostic_sink is not None:
            try:
                diagnostic_sink(b"", b"")
            except Exception:
                raise ValueError("bounded_process_diagnostics_failed") from None
        raise
    completed = False
    diagnostics = {"stdout": bytearray(), "stderr": bytearray()} if diagnostic_sink is not None else None
    try:
        output = bytearray()
        counts = {"stdout": 0, "stderr": 0}
        with selectors.DefaultSelector() as selector:
            pending = memoryview(payload or b"")
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("bounded_process_deadline_exceeded")
                for selected, _mask in selector.select(min(remaining, 1)):
                    if selected.data == "stdin":
                        try:
                            count = os.write(selected.fileobj.fileno(), pending)
                            pending = pending[count:]
                        except BlockingIOError:
                            continue
                        if not pending:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    chunk = os.read(selected.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(selected.fileobj)
                        continue
                    if diagnostics is not None:
                        captured = diagnostics[selected.data]
                        captured.extend(chunk[:max(0, output_limit - len(captured))])
                    counts[selected.data] += len(chunk)
                    if counts[selected.data] > output_limit:
                        raise ValueError("bounded_process_output_exceeded")
                    if selected.data == "stdout": output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise ValueError("bounded_process_failed")
        completed = True
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("bounded_process_failed") from None
    finally:
        try:
            if not completed:
                try:
                    # The group identifier comes only from this start_new_session child, never
                    # a caller manifest. Descendants can retain pipes after their leader exits.
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
        finally:
            if not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()
            process.stderr.close()
            if diagnostics is not None:
                try:
                    diagnostic_sink(bytes(diagnostics["stdout"]), bytes(diagnostics["stderr"]))
                except Exception:
                    raise ValueError("bounded_process_diagnostics_failed") from None
