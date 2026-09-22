#!/usr/bin/python3
"""Manager-only root ExecStartPre receipt, binding intent before candidate execution."""
import os
from pathlib import Path
import re
import sys

# ExecStartPre runs as root outside the unprivileged role's mount boundary. Imports
# must not add bytecode files to the exact immutable installation inventory.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import restricted_workload as workload


def main():
    if (not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0
            or len(sys.argv) != 2 or sys.argv[1] not in workload.ROLES):
        workload.reject('manager-receipt-entry-invalid')
    role = sys.argv[1]
    invocation = os.environ.get('INVOCATION_ID', '')
    if (re.fullmatch('[0-9a-f]{32}', invocation) is None
            or Path('/proc/self/cgroup').read_text().strip() != '0::/system.slice/' + workload.unit(role)):
        workload.reject('manager-receipt-scope-invalid')
    os.environ.clear()
    record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
    campaign = workload.read(workload.ROOT / 'campaign.json')
    workload.current(campaign)
    if record['state'] != 'launching' or record['bootId'] != workload.boot():
        workload.reject('manager-receipt-intent-invalid')
    info = workload.group(role).stat()
    workload.write(workload.ROOT / 'authority' / (role + '-start.json'), {
        'generation': record['generation'], 'bootId': record['bootId'],
        'managerInvocation': invocation, 'cgroupIdentity': [info.st_dev, info.st_ino]})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(1) from None
