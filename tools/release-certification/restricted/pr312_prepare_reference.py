#!/usr/bin/python3
"""Prepare one pinned, synthetic reference VM using unprivileged extracted QEMU tools.

Only the new guest receives administrative commands. The input image is never changed. Apt
network access belongs to this trusted preparation stage; installed acceptance uses a separate
fresh overlay and the restricted network in pr312_reference_vm.py. No preparation output proves
installed acceptance or production authority. Private keys, disks and logs remain in --output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from pr312_reference_vm import (ACCELERATOR, CPU_MODEL, qemu_arguments, require_standalone_image,
                                snapshot_file, snapshot_executables)

IMAGE_SHA512 = 'a733e7d49442a03e70d03e4eb5aaf3967f3efc69ef70952f9bb10fc1ee2c4876eb95956b5ad2d31350e5fada768feb651352535fb8cd1233f61998a5a7d2e93c'
JDK_SHA256 = 'dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e'
PACKAGE_PINS = {
    'bubblewrap': '0.12.0-1~deb13u1', 'dbus': '1.16.2-2', 'gh': '2.46.0-3',
    'git': '1:2.47.3-0+deb13u1', 'openssl': '3.5.7-1~deb13u2', 'polkitd': '126-2',
    'python3.13': '3.13.5-2+deb13u5', 'sudo': '1.9.16p2-3+deb13u2',
    'systemd': '257.13-1~deb13u1', 'util-linux': '2.41.5-0+deb13u1',
}
DEPENDENCIES = ('python3', 'openssl', 'bubblewrap', 'util-linux', 'gh', 'git', 'sudo',
    'dbus', 'polkitd', 'ca-certificates', 'curl', 'libatomic1', 'libasound2t64',
    'libfontconfig1', 'libfreetype6', 'libx11-6', 'libxext6', 'libxi6', 'libxrender1',
    'libxtst6', 'libgtk-3-0t64', 'libnss3')


def digest(path, algorithm='sha256'):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def checked_path(path):
    selected = Path(path).resolve(strict=True)
    if any(character in str(selected) for character in (',', '\n', '\r', '\x00')):
        raise ValueError('reference-path-invalid')
    return selected


def validate_inputs(args):
    if getattr(os, 'geteuid', lambda: 0)() == 0:
        raise ValueError('reference-unprivileged-host-required')
    if not 1024 <= args.port <= 65535:
        raise ValueError('reference-loopback-port-invalid')
    root, image, jdk, seed_tool = map(checked_path,
        (args.qemu_root, args.image, args.jdk, args.seed_tool))
    if digest(image, 'sha512') != IMAGE_SHA512 or digest(jdk) != JDK_SHA256:
        raise ValueError('reference-pinned-input-mismatch')
    if seed_tool.name != 'genisoimage' or not seed_tool.is_file():
        raise ValueError('reference-seed-tool-invalid')
    for relative in ('usr/bin/qemu-img', 'usr/bin/qemu-system-x86_64',
                     'usr/share/seabios/bios-256k.bin'):
        if not (root / relative).is_file():
            raise ValueError('reference-extracted-qemu-unavailable')
    return root, image, jdk, seed_tool


def preparation_arguments(root, output, image, seed, port):
    arguments = qemu_arguments(root, output, image, seed, port)
    # Apt is deliberately enabled only for this trusted fresh-guest preparation stage.
    arguments[arguments.index('-netdev') + 1] = f'user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22'
    return arguments + ['-no-user-config']


def cloud_config(login_public, host_public, host_private):
    for public in (login_public, host_public):
        if re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.-]+)?', public.strip()) is None:
            raise ValueError('reference-generated-public-key-invalid')
    if (not host_private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
            or not host_private.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----')
            or len(host_private) > 8192):
        raise ValueError('reference-generated-host-key-invalid')
    private_lines = ''.join('    ' + line + '\n' for line in host_private.splitlines())
    return ('#cloud-config\nusers:\n  - name: vmadmin\n    groups: [sudo]\n'
        '    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    lock_passwd: true\n'
        '    ssh_authorized_keys:\n      - ' + login_public.strip() + '\n'
        'disable_root: true\nssh_pwauth: false\npackage_update: false\npackage_upgrade: false\n'
        'ssh_keys:\n  ed25519_private: |\n' + private_lines +
        '  ed25519_public: ' + host_public.strip() + '\n')


def ssh_arguments(output, port):
    return ['ssh', '-F', '/dev/null', '-i', str(output / 'guest-key'), '-p', str(port),
        '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(output / 'known_hosts'),
        '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', 'vmadmin@127.0.0.1']


def guest_script():
    # This fixed script is sent to sudo inside the explicitly selected synthetic guest only.
    script = ('set -eu\nexport DEBIAN_FRONTEND=noninteractive\n'
        'test "$(systemd-detect-virt --vm)" = qemu\n'
        'test "$(uname -r)" = 6.12.107+deb13-amd64\n'
        'apt-get update\napt-get install -y --no-install-recommends ' + ' '.join(DEPENDENCIES) + '\n')
    for package, version in sorted(PACKAGE_PINS.items()):
        script += 'test "$(dpkg-query -W -f=\'${Version}\' ' + package + ')" = ' + version + '\n'
    script += ("printf '%s\\n' '" + JDK_SHA256 + "  /home/vmadmin/jdk25.tar.gz' | sha256sum --check\n"
        'test ! -e /opt/pr312-jdk\nmkdir /opt/pr312-jdk\n'
        'tar -xzf /home/vmadmin/jdk25.tar.gz --strip-components=1 -C /opt/pr312-jdk\n'
        'for program in java javac jar jcmd; do\n'
        '  test ! -e /usr/local/bin/$program\n'
        '  ln -s /opt/pr312-jdk/bin/$program /usr/local/bin/$program\ndone\n'
        'systemctl start dbus.service polkit.service\n'
        'test "$(javac -version)" = "javac 25.0.4.1"\n')
    return script


def public_report(report):
    fields = ('schemaVersion', 'kind', 'executed', 'stage', 'status', 'guestStopped',
              'referenceImageSha512', 'jdkSha256', 'preparedImageSha256',
              'qemuSha256', 'qemuImgSha256', 'seedToolSha256')
    result = {key: report[key] for key in fields if key in report}
    result.update(productionAuthorityObserved=False, installedKeylessNativeAcceptanceSatisfied=False,
                  mandatoryIsolationTestSatisfied=False, cpuModel=CPU_MODEL, accelerator=ACCELERATOR)
    return result


def flatten_image(source, prepared, qemu_img, environment, call):
    """Publish a digest only after conversion and standalone-storage verification succeed."""
    call([str(qemu_img), 'convert', '-f', 'qcow2', '-O', 'qcow2',
          str(source), str(prepared)], timeout=300)
    require_standalone_image(prepared, qemu_img, environment)
    return digest(prepared)


def snapshot_tools(root, seed_tool, output):
    """Retain the exact executable copies used for preparation, without copying source modes."""
    sources = {'qemu-system-x86_64': root / 'usr/bin/qemu-system-x86_64',
               'qemu-img': root / 'usr/bin/qemu-img', 'genisoimage': seed_tool}
    return snapshot_executables(sources, output)


def snapshot_base_image(source, output, qemu_img, environment):
    image = output / 'reference-base.qcow2'
    if snapshot_file(source, image, 'sha512') != IMAGE_SHA512:
        raise ValueError('reference-pinned-input-mismatch')
    require_standalone_image(image, qemu_img, environment)
    return image


def run(args):
    os.umask(0o077)
    output = args.output.absolute()
    if any(character in str(output) for character in (',', '\n', '\r', '\x00')):
        raise ValueError('reference-output-path-invalid')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schemaVersion': 4, 'kind': 'pr312-reference-preparation', 'executed': False,
              'stage': 'input-verification', 'status': 'failed', 'guestStopped': True,
              'cpuModel': CPU_MODEL, 'accelerator': ACCELERATOR}
    process = None
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
    tool_environment = dict(environment)
    with (output / 'prepare.private.log').open('xb') as log:
        def call(arguments, timeout=120, **options):
            return subprocess.run(arguments, check=True, timeout=timeout,
                env=tool_environment if Path(arguments[0]).is_absolute() else environment,
                stdout=log, stderr=log, **({'stdin': subprocess.DEVNULL} if 'input' not in options and 'stdin' not in options else {}), **options)
        try:
            root, image, jdk, seed_tool = validate_inputs(args)
            tool_environment.update(LD_LIBRARY_PATH=str(root / 'usr/lib/x86_64-linux-gnu'),
                               QEMU_MODULE_DIR=str(root / 'usr/lib/x86_64-linux-gnu/qemu'))
            executables = snapshot_tools(root, seed_tool, output)
            qemu_img = executables['qemu-img']
            qemu = executables['qemu-system-x86_64']
            seed_tool = executables['genisoimage']
            report['stage'] = 'base-image-snapshot'
            image = snapshot_base_image(image, output, qemu_img, tool_environment)
            report.update(referenceImageSha512=IMAGE_SHA512, jdkSha256=JDK_SHA256,
                qemuSha256=digest(qemu),
                qemuImgSha256=digest(qemu_img), seedToolSha256=digest(seed_tool))
            report['stage'] = 'synthetic-seed'
            for name in ('guest-key', 'guest-host-key'):
                call(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'pr312-reference', '-f', str(output / name)])
            login_public = (output / 'guest-key.pub').read_text()
            host_public = (output / 'guest-host-key.pub').read_text()
            (output / 'user-data').write_text(cloud_config(login_public, host_public, (output / 'guest-host-key').read_text()))
            (output / 'meta-data').write_text('instance-id: pr312-reference\nlocal-hostname: pr312-reference\n')
            (output / 'known_hosts').write_text(f'[127.0.0.1]:{args.port} ' + host_public)
            seed = output / 'seed.iso'
            call([str(seed_tool), '-output', str(seed), '-volid', 'cidata', '-joliet', '-rock',
                  str(output / 'user-data'), str(output / 'meta-data')])
            call([str(qemu_img), 'create', '-f', 'qcow2', '-F', 'qcow2',
                  '-b', str(image), str(output / 'guest.qcow2')])
            call([str(qemu_img), 'resize', str(output / 'guest.qcow2'), '24G'])
            arguments = preparation_arguments(root, output, image, seed, args.port)
            arguments[0] = str(qemu)
            process = subprocess.Popen(arguments,
                env=tool_environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            report.update(executed=True, guestStopped=False, stage='guest-boot')
            ssh = ssh_arguments(output, args.port)
            deadline = time.monotonic() + 240
            while True:
                try:
                    probe = subprocess.run([*ssh, 'true'], stdin=subprocess.DEVNULL, stdout=log,
                        stderr=log, env=environment, timeout=10)
                    if probe.returncode == 0:
                        break
                except subprocess.TimeoutExpired:
                    pass
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError('reference-guest-boot-unavailable')
                time.sleep(2)
            report['stage'] = 'guest-dependencies'
            with jdk.open('rb') as stream:
                call([*ssh, 'cat > /home/vmadmin/jdk25.tar.gz'], stdin=stream, timeout=180)
            script = guest_script()
            (output / 'guest-prepare.sh').write_text(script)
            call([*ssh, 'sudo bash -s'], input=script.encode(), timeout=900)
            inventory = ('uname -r; /usr/lib/systemd/systemd --version; python3 --version; '
                         '/usr/bin/bwrap --version; java -version; javac -version; '
                         "dpkg-query -W -f='${Package} ${Version}\\n'")
            with (output / 'guest-identities.private.txt').open('xb') as identities:
                subprocess.run([*ssh, inventory], check=True, stdin=subprocess.DEVNULL,
                    stdout=identities, stderr=log, env=environment, timeout=30)
            report['stage'] = 'guest-shutdown'
            call([*ssh, 'sudo poweroff'], timeout=20)
            if process.wait(timeout=45) != 0:
                raise ValueError('reference-guest-shutdown-failed')
            # Flatten after clean shutdown: hashing an overlay alone cannot bind its backing bytes.
            report['stage'] = 'image-flattening'
            prepared = output / 'prepared-pristine.qcow2'
            prepared_digest = flatten_image(output / 'guest.qcow2', prepared,
                qemu_img, tool_environment, call)
            report.update(preparedImageSha256=prepared_digest, status='prepared', stage='complete')
        except (OSError, ValueError, subprocess.SubprocessError):
            report['status'] = 'failed'
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                report['guestStopped'] = process.poll() is not None
            (output / 'preparation-report.json').write_text(json.dumps(public_report(report), indent=2) + '\n')
    print(json.dumps(public_report(report), sort_keys=True))
    return 0 if report['status'] == 'prepared' else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu-root', 'image', 'jdk', 'seed-tool', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--port', type=int, default=23112)
    try:
        return run(parser.parse_args())
    except (OSError, ValueError):
        print(json.dumps(public_report({'schemaVersion': 4, 'kind': 'pr312-reference-preparation',
            'executed': False, 'stage': 'output-creation', 'status': 'failed', 'guestStopped': True})))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
