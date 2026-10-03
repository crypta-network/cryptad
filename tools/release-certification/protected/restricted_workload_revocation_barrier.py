#!/usr/bin/python3
"""Fixed root-owned reply barrier for the isolated revocation test kit.

Normal requests have no barrier. Only a root-prepared record bound to the
campaign and both actual process instances can hold a refused request while
the administrator observes its original controller and running roles.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

POLICY = 'pr315-revocation-accepted-rpc-v1'
REQUEST_NAME = 'pr315-revocation-request.json'
PHASE_NAME = 'pr315-revocation-phase.json'
RELEASE_NAME = 'pr315-revocation-release.json'


def _private_record(path):
    import restricted_workload as workload
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or info.st_mode & 0o077
            or not 0 < info.st_size <= 8192):
        workload.reject('revocation-barrier-private-record-invalid')
    return workload.read(path)


def prepare(connection, observer_uid):
    """Return a token only for one measured root-selected live socket peer."""
    import restricted_workload as workload
    path = workload.ROOT / 'authority' / REQUEST_NAME
    if not os.path.lexists(path):
        return None
    selected = _private_record(path)
    fields = {'schemaVersion', 'policy', 'caseId', 'nonceDigest', 'campaign',
              'bootId', 'controllerPid', 'controllerStartTicks',
              'observerPid', 'observerStartTicks', 'markerDigest', 'sourceDigest'}
    peer_pid, peer_uid, _gid = struct.unpack('3i', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    campaign = workload.read(workload.ROOT / 'campaign.json')
    own_ticks = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
    peer = Path('/proc') / str(peer_pid)
    peer_ticks = int(peer.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19])
    uids = next(line for line in peer.joinpath('status').read_text().splitlines()
                if line.startswith('Uid:'))
    if (not isinstance(selected, dict) or set(selected) != fields
            or type(selected['schemaVersion']) is not int
            or selected['schemaVersion'] != 1 or selected['policy'] != POLICY
            or selected['caseId'] != 'revocation-running'
            or selected['campaign'] != campaign['generation']
            or selected['bootId'] != workload.boot()
            or selected['controllerPid'] != os.getpid()
            or selected['controllerStartTicks'] != own_ticks
            or selected['observerPid'] != peer_pid or peer_uid != observer_uid
            or set(map(int, uids.split()[1:])) != {observer_uid}
            or selected['observerStartTicks'] != peer_ticks
            or any(type(selected[key]) is not int or selected[key] <= 0 for key in (
                'controllerPid', 'controllerStartTicks', 'observerPid', 'observerStartTicks'))
            or selected['sourceDigest'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or any(re.fullmatch('[0-9a-f]{64}', str(selected[key])) is None
                   for key in ('nonceDigest', 'markerDigest'))
            or os.path.lexists(workload.ROOT / 'revoked')
            or campaign['deadlineMonotonicNs'] <= time.monotonic_ns()):
        workload.reject('revocation-barrier-instance-invalid')
    return {**selected, 'acceptedMonotonicNs': time.monotonic_ns(),
            'campaignDeadlineNs': campaign['deadlineMonotonicNs']}


def refused(token, error):
    """Hold only a real revoked-authority error, within the original deadline."""
    import restricted_workload as workload
    if token is None:
        return
    selected = _private_record(workload.ROOT / 'authority' / REQUEST_NAME)
    original = {key: value for key, value in token.items() if key not in {
        'acceptedMonotonicNs', 'campaignDeadlineNs', 'requestDigest'}}
    if json.dumps(selected, sort_keys=True) != json.dumps(original, sort_keys=True):
        workload.reject('revocation-barrier-request-changed')
    marker = workload.ROOT / 'revoked'
    info = marker.lstat()
    if (str(error) != 'restricted-workload-authority-expired-or-revoked'
            or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size != 32
            or hashlib.sha256(marker.read_bytes()).hexdigest() != token['markerDigest']):
        workload.reject('revocation-barrier-wrong-denial')
    proof = {key: token[key] for key in (
        'policy', 'caseId', 'nonceDigest', 'campaign', 'bootId',
        'controllerPid', 'controllerStartTicks', 'observerPid',
        'observerStartTicks', 'markerDigest', 'sourceDigest', 'acceptedMonotonicNs')}
    proof.update(schemaVersion=1, kind='pr315-fixed-revocation-denial',
                 requestDigest=token['requestDigest'],
                 replyEnqueuedMonotonicNs=time.monotonic_ns(),
                 errorCode='authority-expired-or-revoked')
    workload.write(workload.ROOT / 'authority' / PHASE_NAME, proof, create=True)
    until = min(time.monotonic_ns() + 5_000_000_000, token['campaignDeadlineNs'])
    release = workload.ROOT / 'authority' / RELEASE_NAME
    while not os.path.lexists(release):
        if time.monotonic_ns() >= until:
            workload.reject('revocation-barrier-release-timeout')
        time.sleep(.01)
    value = _private_record(release)
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'policy', 'nonce'}
            or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['policy'] != POLICY
            or re.fullmatch('[0-9a-f]{64}', str(value['nonce'])) is None
            or hashlib.sha256(value['nonce'].encode()).hexdigest() != token['nonceDigest']
            or time.monotonic_ns() >= token['campaignDeadlineNs']):
        workload.reject('revocation-barrier-release-invalid')
