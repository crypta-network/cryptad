"""Disposable test-kit owner: synthetic Java attacks through the installed fixed adapter.

This administrator-owned driver is never imported by the production controller. Its JAR is
synthetic candidate input, not a product or provider authority. Failures retain private material.
"""
from pathlib import Path
from contextlib import nullcontext
from unittest.mock import patch
import hashlib
import json
import os
import secrets
import shutil
import struct
import stat
import subprocess
import time


SOURCE = r'''
package network.crypta.platform.api;
import java.nio.file.*;
import java.nio.channels.*;
import java.net.*;
import java.util.*;
public final class PackagedApiExport {
  static void require(boolean ok) { if (!ok) throw new IllegalStateException("fixture-check-failed"); }
  static void deniedRead(String path) throws Exception {
    try { Files.readAllBytes(Path.of(path)); throw new IllegalStateException("unexpected-read"); }
    catch (java.io.IOException expected) { }
  }
  static void deniedWrite(String path) throws Exception {
    try { Files.writeString(Path.of(path), "attack"); throw new IllegalStateException("unexpected-write"); }
    catch (java.io.IOException expected) { }
  }
  public static void main(String[] args) throws Exception {
    String mode = Files.readString(Path.of("/work/mode")).trim();
    System.err.println("fixture-mode-started:" + mode); System.err.flush();
    if (mode.equals("timeout") || mode.equals("synthetic-revocation") || mode.equals("lost-start-response")) { Thread.sleep(300000); return; }
    if (mode.equals("overflow")) {
      byte[] block = new byte[4096];
      Thread stderr = new Thread(() -> { for (;;) System.err.write(block, 0, block.length); });
      stderr.start(); for (;;) System.out.write(block, 0, block.length);
    }
    if (mode.equals("descendant")) {
      new ProcessBuilder("/usr/bin/setsid", "/usr/bin/sleep", "300").inheritIO().start();
      System.err.println("fixture-descendant-started"); System.err.flush();
      System.out.println("fixture-pass"); return;
    }
    if (mode.equals("unexpected-output")) {
      Files.writeString(Path.of("/output/forged.json"), "{\"accepted\":true}");
      System.out.println("fixture-pass"); return;
    }
    if (mode.equals("cross-operation")) {
      for (String name : List.of("prior-result", "observer-state")) {
        String path = Files.readString(Path.of("/work/" + name)).trim();
        deniedRead(path); deniedWrite(path);
      }
      System.out.println("fixture-pass"); return;
    }
    require(mode.equals("positive"));
    Map<String,String> status = new HashMap<>();
    for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
      int colon = line.indexOf(':'); if (colon > 0) status.put(line.substring(0, colon), line.substring(colon + 1).trim());
    }
    for (String key : List.of("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"))
      require(Long.parseUnsignedLong(status.get(key), 16) == 0);
    require(status.get("NoNewPrivs").equals("1"));
    Process nestedUserns = new ProcessBuilder("/usr/bin/unshare", "--user", "--map-root-user",
        "--mount", "/usr/bin/true").redirectError(ProcessBuilder.Redirect.DISCARD).start();
    require(nestedUserns.waitFor() != 0);

    String uid = Files.readString(Path.of("/work/uid")).trim();
    for (String value : status.get("Uid").split("\\s+")) require(value.equals(uid));
    require((((Integer) Files.getAttribute(Path.of("/work/root-setid-probe"), "unix:mode")) & 06000) == 0);
    Process setid = new ProcessBuilder("/work/root-setid-probe", "-u").start();
    require(new String(setid.getInputStream().readAllBytes()).trim().equals(uid));
    require(setid.waitFor() == 0);
    Path localSetid = Path.of("/scratch/native-setid-probe");
    Files.copy(Path.of("/work/root-setid-probe"), localSetid);
    Files.setAttribute(localSetid, "unix:mode", 04755);
    Process nativeSetid = new ProcessBuilder(localSetid.toString(), "-u").start();
    require(new String(nativeSetid.getInputStream().readAllBytes()).trim().equals(uid));
    require(nativeSetid.waitFor() == 0);
    Process filecap = new ProcessBuilder("/work/root-filecap-probe", "5").start();
    try {
      for (String line : Files.readAllLines(Path.of("/proc/" + filecap.pid() + "/status"))) {
        if (line.matches("Cap(Eff|Prm|Inh|Amb|Bnd):.*"))
          require(Long.parseUnsignedLong(line.substring(line.indexOf(':') + 1).trim(), 16) == 0);
      }
    } finally { filecap.destroyForcibly(); filecap.waitFor(); }
    Process openat2 = new ProcessBuilder("/usr/bin/python3", "-I", "-S", "/work/openat2.py").start();
    require(new String(openat2.getInputStream().readAllBytes()).trim().equals("openat2-pass"));
    require(openat2.waitFor() == 0);
    String hostPid = Files.readString(Path.of("/work/host-pid")).trim();
    require(!Files.exists(Path.of("/proc/" + hostPid)));
    try (var paths = Files.list(Path.of("/proc"))) {
      require(paths.filter(p -> p.getFileName().toString().matches("[0-9]+")).count() < 16);
    }
    for (String path : List.of("/etc/cryptad-certification/pr312-private-canary",
        "/root/pr312-native-faults/sibling", "/var/lib/cryptad-restricted-native/active.json",
        "/var/lib/cryptad-restricted/runtime/control/processes/daemon.json")) deniedRead(path);
    for (String path : List.of("/pr312-root-write", "/dev/pr312-write",
        "/dev/shm/pr312-write", "/dev/pts/pr312-write", "/work/mode", "/jdk/release", "/usr/pr312-write",
        "/opt/cryptad-restricted/pr312-write", "/sys/fs/cgroup/cgroup.procs")) deniedWrite(path);
    for (String name : System.getenv().keySet())
      require(Set.of("PATH", "LANG", "HOME", "TMPDIR").contains(name));
    try (var paths = Files.list(Path.of("/proc/self/fd"))) {
      for (Path fd : paths.toList()) {
        try {
          String target = Files.readSymbolicLink(fd).toString();
          require(!target.contains("cryptad") || target.equals("/work/cryptad.jar"));
          require(!target.contains("/etc/") && !target.contains("/run/") && !target.contains("/root/"));
        } catch (NoSuchFileException expected) { }
      }
    }
    for (String path : List.of("/run/cryptad-restricted/control.sock", "/run/dbus/system_bus_socket")) {
      try (var socket = SocketChannel.open(StandardProtocolFamily.UNIX)) {
        try { socket.connect(UnixDomainSocketAddress.of(path)); throw new IllegalStateException("socket-visible"); }
        catch (java.io.IOException expected) { }
      }
    }
    for (String host : List.of("127.0.0.1", "192.0.2.1")) {
      try (Socket socket = new Socket()) {
        try { socket.connect(new InetSocketAddress(host, 22), 200); throw new IllegalStateException("network-reachable"); }
        catch (java.io.IOException expected) { }
      }
    }
    require(Files.readAllLines(Path.of("/proc/net/route")).size() == 1);
    System.out.println("fixture-pass");
  }
}
'''
OPENAT2_SOURCE = r"""
# Synthetic candidate probe of the existing Linux syscall, never a privileged broker.
import ctypes
import errno
import os
from pathlib import Path

class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_ulonglong), ('mode', ctypes.c_ulonglong),
                ('resolve', ctypes.c_ulonglong)]

root = Path('/scratch/openat2')
root.mkdir(mode=0o700)
(root / 'inside').write_bytes(b'public-fixture')
(root / 'link').symlink_to('inside')
(root / 'absolute-link').symlink_to('/work/mode')
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
# Reference Debian amd64 Linux uses syscall 437. Both protections are kernel enforced:
# RESOLVE_BENEATH (0x08) rejects escapes; RESOLVE_NO_SYMLINKS (0x04) rejects links.
how = OpenHow(os.O_RDONLY | os.O_CLOEXEC, 0, 0x08 | 0x04)
try:
    for name, expected_errno in ((b'inside', None), (b'link', errno.ELOOP),
                                 (b'absolute-link', errno.ELOOP),
                                 (b'../outside', errno.EXDEV)):
        ctypes.set_errno(0)
        fd = libc.syscall(ctypes.c_long(437), ctypes.c_int(directory), ctypes.c_char_p(name),
                          ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
        if expected_errno is None:
            if fd < 0:
                raise ValueError('openat2-safe-open-failed')
            try:
                if os.read(fd, 32) != b'public-fixture':
                    raise ValueError('openat2-safe-content-failed')
            finally:
                os.close(fd)
        elif fd >= 0:
            os.close(fd)
            raise ValueError('openat2-hostile-open-accepted')
        elif ctypes.get_errno() != expected_errno:
            raise ValueError('openat2-hostile-open-wrong-error')
finally:
    os.close(directory)
print('openat2-pass')
"""
MODES = ('positive', 'cross-operation', 'synthetic-revocation', 'lost-start-response', 'overflow', 'timeout', 'descendant', 'unexpected-output')


def _command(jdk, work):
    return ['/usr/bin/prlimit', '--cpu=60', '--fsize=8388608', '--nofile=128', '--',
        '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--size', '16777216', '--tmpfs', '/tmp',
        '--ro-bind', str(jdk), '/jdk', '--ro-bind', str(work), '/work', '--chdir', '/work', '--',
        '/jdk/bin/java', '-Xmx128m', '-cp', '/work/cryptad.jar',
        'network.crypta.platform.api.PackagedApiExport']


def _quiescent(native):
    state = native._manager('show')
    if state['ActiveState'] not in ('inactive', 'failed') or (native.ROOT / 'active.json').exists():
        raise ValueError('native-fixture-not-quiescent')
    group = Path('/sys/fs/cgroup' + native.CGROUP)
    if group.exists() and 'populated 0' not in (group / 'cgroup.events').read_text().splitlines():
        raise ValueError('native-fixture-not-quiescent')



def _owned_java_running(native):
    # Inspect only PIDs listed by this fixed owned cgroup, never a supplied PID/host-wide search.
    processes = Path('/sys/fs/cgroup' + native.CGROUP) / 'cgroup.procs'
    for value in processes.read_text().split():
        if not value.isdecimal():
            raise ValueError('native-fixture-invalid-owned-process')
        try:
            if (Path('/proc') / value / 'comm').read_text().strip() == 'java':
                return True
        except FileNotFoundError:
            continue
    return False



class _LostStartResponse:
    """Drop only the response to the real fixed unit start in this disposable test owner."""
    def __init__(self, native):
        self.real_manager, self.group = native._manager, native.CGROUP
        self.fired = False
        self.invocation_id = None

    def __call__(self, action, **kwargs):
        result = self.real_manager(action, **kwargs)
        if action != 'start':
            return result
        state = self.real_manager('show')
        identity = state['InvocationID']
        if (self.fired or len(identity) != 32 or any(value not in '0123456789abcdef' for value in identity)
                or state['ControlGroup'] != self.group or state['ActiveState'] != 'active'):
            raise ValueError('native-fixture-start-not-observed')
        self.fired, self.invocation_id = True, identity
        raise ValueError('synthetic-native-start-response-lost')


class _SyntheticRevocation:
    """Synthetic test-owner callback; no production registration/revocation is manufactured."""
    def __init__(self, native, before):
        self.native, self.before = native, before
        self.fired = False
        self.invocation_id = None

    def __call__(self):
        if self.fired:
            raise ValueError('native-fixture-revocation-called-after-rejection')
        stages = [path for path in set(self.native.ROOT.iterdir()) - self.before
                  if path.is_dir() and (path / 'manager.json').exists()]
        if not stages:
            return
        if len(stages) != 1:
            raise ValueError('native-fixture-ambiguous-owned-invocation')
        retained = json.loads((stages[0] / 'manager.json').read_bytes())
        state = self.native._manager('show')
        if (state['InvocationID'] != retained['invocationId']
                or state['ControlGroup'] != self.native.CGROUP
                or state['ActiveState'] != 'active' or state['SubState'] != 'running'):
            return
        if not _owned_java_running(self.native):
            return
        self.fired = True
        self.invocation_id = retained['invocationId']
        raise ValueError('synthetic-native-revocation')



def _fixture_jdk(source, root):
    """Derive a test-only materialized identity, then use the unchanged production stager.

    The source is the guest's pinned synthetic reference JDK, not a production approval.
    Internal vendor legal links are normalized; escapes, special files and oversized trees fail.
    """
    import app_subject_projection as projection
    import maintenance_runtime_metadata as metadata
    source = Path(source).resolve(strict=True)
    deadline = time.monotonic() + 120
    budget = [0, 0]
    def inspect(directory, names):
        if time.monotonic() >= deadline:
            raise ValueError('native-fixture-jdk-normalization-deadline')
        if len(Path(directory).relative_to(source).parts) > 32:
            raise ValueError('native-fixture-jdk-normalization-depth')
        for name in names:
            selected = (Path(directory) / name).resolve(strict=True)
            if not selected.is_relative_to(source):
                raise ValueError('native-fixture-jdk-link-escape')
            info = selected.stat()
            budget[0] += 1
            if stat.S_ISREG(info.st_mode):
                budget[1] += info.st_size
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError('native-fixture-jdk-special-file')
            if budget[0] > 32768 or budget[1] > 4 * 1024**3:
                raise ValueError('native-fixture-jdk-budget')
        return []
    normalized = root / 'jdk-normalized-reference'
    shutil.copytree(source, normalized, symlinks=False, ignore=inspect)
    expected = projection.tree_digest(normalized)
    staged = metadata.stage_jdk(source, root / 'jdk', expected)
    if projection.tree_digest(staged) != expected:
        raise ValueError('native-fixture-jdk-identity-mismatch')
    (root / 'jdk-identity.json').write_text(json.dumps({
        'provenance': 'synthetic-reference-normalization-not-production-approval',
        'materializedTreeDigest': expected}, sort_keys=True))
    shutil.rmtree(normalized)
    return staged


def run(jdk, root, identity, *, observe=None):
    """Run finite synthetic attacks; return only named dimensions after observed success."""
    import restricted_native as native
    if os.geteuid() != 0 or not Path(native.__file__).resolve().is_relative_to('/opt'):
        raise ValueError('native-fixture-requires-installed-guest')
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    (root / 'sibling').write_text('synthetic-private-canary')
    observer = Path('/var/lib/cryptad-restricted/pr312-private-observer')
    observer.mkdir(mode=0o700, exist_ok=False)
    observer_state = observer / 'state.json'
    with observer_state.open('x') as stream:
        stream.write('synthetic-private-observer-canary')
    observer_state.chmod(0o600)
    if observer.stat().st_uid != 0 or observer_state.stat().st_uid != 0:
        raise ValueError('native-fixture-observer-owner-invalid')
    canary = Path('/etc/cryptad-certification/pr312-private-canary')
    canary.write_text('synthetic-private-canary')
    canary.chmod(0o600)
    jdk = _fixture_jdk(jdk, root)
    source = root / 'PackagedApiExport.java'
    source.write_text(SOURCE)
    classes = root / 'classes'
    classes.mkdir()
    # Trusted finite compiler output stays private; no candidate process runs here.
    with (root / 'compiler.log').open('xb') as log:
        subprocess.run([str(jdk / 'bin/javac'), '-d', str(classes), str(source)],
                       stdout=log, stderr=log, check=True, timeout=120)
        subprocess.run([str(jdk / 'bin/jar'), '--create', '--file', str(root / 'fixture.jar'),
                        '-C', str(classes), '.'], stdout=log, stderr=log, check=True, timeout=60)
    dimensions = []
    prior_result = None
    prior_bytes = None
    for mode in MODES:
        work = root / mode
        work.mkdir(mode=0o700)
        (work / 'cryptad.jar').write_bytes((root / 'fixture.jar').read_bytes())
        if mode == 'positive':
            setid = work / 'root-setid-probe'
            shutil.copyfile('/usr/bin/id', setid)
            setid.chmod(0o4755)
            if setid.stat().st_uid != 0 or setid.stat().st_mode & 0o4000 == 0:
                raise ValueError('native-fixture-setid-unavailable')
            filecap = work / 'root-filecap-probe'
            shutil.copyfile('/usr/bin/sleep', filecap)
            filecap.chmod(0o755)
            # Linux v2 VFS capability: effective CAP_DAC_OVERRIDE, no inheritable bits.
            # Root in the explicitly disposable guest sets it; the production copier must drop it.
            capability = struct.pack('<IIIII', 0x02000001, 2, 0, 0, 0)
            os.setxattr(filecap, 'security.capability', capability)
            if os.getxattr(filecap, 'security.capability') != capability:
                raise ValueError('native-fixture-filecap-unavailable')
        if mode == 'cross-operation':
            if prior_result is None or not prior_result.is_file():
                raise ValueError('native-fixture-prior-result-unavailable')
            prior_bytes = prior_result.read_bytes()
            (work / 'prior-result').write_text(str(prior_result))
            (work / 'observer-state').write_text(str(observer_state))
        (work / 'openat2.py').write_text(OPENAT2_SOURCE)
        (work / 'mode').write_text(mode)
        (work / 'uid').write_text(str(native._native_identity()[0]))
        (work / 'host-pid').write_text(str(os.getpid()))
        before = set(native.ROOT.iterdir())
        revocation = _SyntheticRevocation(native, before) if mode == 'synthetic-revocation' else None
        lost_start = _LostStartResponse(native) if mode == 'lost-start-response' else None
        transport = patch.object(native, '_manager', side_effect=lost_start) if lost_start else nullcontext()
        context = {'operationId': secrets.token_hex(32), 'registrationDigest': 'sha256:' + '0' * 64,
                   'bundleIdentity': identity, 'deadlineMonotonic': time.monotonic() + 120}
        rejected = False
        started = time.monotonic()
        started_ns = time.monotonic_ns()
        try:
            with transport, native.owning_boundary(context=context, check=revocation):
                result = native.run(_command(jdk, work), environment={
                    'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/tmp', 'TMPDIR': '/tmp'},
                    timeout=45 if mode == 'timeout' else 110, output_limit=8192, operation='package-api')
        except native.NativeBoundaryError:
            rejected = True
            result = b''
        _quiescent(native)
        stages = [path for path in set(native.ROOT.iterdir()) - before if path.is_dir()]
        if len(stages) != 1 or (mode != 'lost-start-response' and not (stages[0] / 'manager.json').exists()):
            raise ValueError('native-fixture-not-launched')
        if mode in ('positive', 'cross-operation'):
            if rejected or result != b'fixture-pass\n':
                raise ValueError('native-fixture-isolation-failed')
        elif mode == 'descendant':
            # PID namespace teardown may kill the orphan normally; either path must be quiescent.
            if not rejected and result != b'fixture-pass\n':
                raise ValueError('native-fixture-descendant-failed')
        elif not rejected:
            raise ValueError('native-fixture-fault-accepted')
        if mode == 'positive':
            prior_result = stages[0] / 'output/stdout'
            if not (stages[0] / 'complete.json').is_file():
                raise ValueError('native-fixture-prior-result-not-completed')
        if mode == 'cross-operation':
            if (prior_result.read_bytes() != prior_bytes
                    or observer_state.read_text() != 'synthetic-private-observer-canary'):
                raise ValueError('native-fixture-private-state-modified')
        if mode == 'synthetic-revocation':
            if (not revocation.fired or (stages[0] / 'complete.json').exists()
                    or not (stages[0] / 'failure.json').exists()):
                raise ValueError('native-fixture-revocation-not-observed')
        if mode == 'lost-start-response':
            if (not lost_start.fired or (stages[0] / 'complete.json').exists()
                    or not (stages[0] / 'failure.json').exists()):
                raise ValueError('native-fixture-lost-start-not-observed')
        if mode in ('timeout', 'overflow'):
            failure = json.loads((stages[0] / 'output/failure.json').read_bytes())
            expected = 'deadline' if mode == 'timeout' else 'output-limit'
            if failure.get('stage') != expected:
                raise ValueError('native-fixture-wrong-failure-stage')
        # A timeout/output rejection before the candidate entered its selected operation is
        # setup failure, never an executed security denial. These fixed diagnostics stay private.
        validate_attack_marker(native, stages[0], mode)
        case_ids = {'positive': ('hostile-setid', 'hostile-filecap', 'openat2-safe',
                    'hostile-openat2-hostile', 'hostile-descendant-userns', 'hostile-device-write',
                    'hostile-root-write', 'hostile-environment', 'hostile-fd', 'hostile-proc'),
                    'cross-operation': ('hostile-cross-operation',),
                    'overflow': ('hostile-pipe-overflow',), 'timeout': ('hostile-timeout',),
                    'descendant': ('hostile-setsid-descendant',),
                    'unexpected-output': ('hostile-unexpected-output',)}.get(mode, ())
        if observe is not None:
            emit_observations(native, stages[0], case_ids, started_ns, observe)
        (work / 'observation.json').write_text(json.dumps({'mode': mode, 'rejected': rejected,
            'elapsedSeconds': time.monotonic() - started, 'quiescent': True,
            'revocationTransport': 'synthetic-test-owner-callback' if revocation else None,
            'startResponseTransport': 'synthetic-test-owner-response-loss' if lost_start else None}))
        dimensions.append('installed-synthetic-native-' + mode)
        if mode == 'positive':
            dimensions.extend(['installed-synthetic-native-setid-stripped',
                               'installed-synthetic-native-filecap-no-gain',
                               'installed-synthetic-native-openat2-safe-and-hostile'])
    return dimensions


def emit_observations(native, stage, case_ids, started_ns, observe):
    """Export fixed private records only after the source-owned fixture checks succeeded."""
    from pr313_acceptance import CASES
    manager = json.loads((stage / 'manager.json').read_bytes())
    stdout = native._read_output(stage / 'diagnostics/stdout', 8192, allow_empty=True)
    stderr = native._read_output(stage / 'diagnostics/stderr', 8192, allow_empty=True)
    diagnostic_digest = hashlib.sha256(len(stdout).to_bytes(8, 'big') + stdout + stderr).hexdigest()
    state = native._manager('show')
    _quiescent(native)
    for name in case_ids:
        case = CASES[name]
        observe({'caseId': name, 'phase': case.phase, 'outcome': case.outcome,
            'managerInvocationId': manager['invocationId'],
            'attackWitness': {'operation': case.operation, 'operationMarker': name,
                'ownerOutcome': case.outcome, 'stdoutDigest': diagnostic_digest,
                'startedMonotonicNs': started_ns, 'finishedMonotonicNs': time.monotonic_ns()},
            'quiescent': {'activeState': state['ActiveState'], 'cgroupPopulated': False,
                          'activeRecordPresent': False}})


def validate_attack_marker(native, stage, mode):
    """Reject unrelated setup failures before crediting a timeout or candidate attack."""
    if mode in ('synthetic-revocation', 'lost-start-response'):
        return  # These older diagnostic-only dimensions have their own manager witnesses.
    diagnostic = native._read_output(stage / 'diagnostics/stderr', 8192, allow_empty=True)
    if ('fixture-mode-started:' + mode + '\n').encode() not in diagnostic:
        raise ValueError('native-fixture-attack-not-observed')
    if mode == 'descendant' and b'fixture-descendant-started\n' not in diagnostic:
        raise ValueError('native-fixture-descendant-not-observed')
