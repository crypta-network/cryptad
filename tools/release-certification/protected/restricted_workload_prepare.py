"""Trusted preparation of the fixed four-role source-build workload profile.

This is an in-process owner API, not a client request. Production artifact campaigns
continue to require the existing original product admission and protected activation.
The initial implemented lane is explicitly synthetic and cannot reopen that channel.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

import restricted_workload as workload
from restricted_workload_storage import copy_tree
from restricted_workload_launcher import (budget_launcher_policy, launcher_policy,
                                           verify_wrapper_options)
from restricted_native_launcher import tree_identity


MAIL_EXECUTION_CLASS = 'pr316-installed-mail-runtime-v1'
MAIL_EXPERIMENT = 'pr316-installed-mail-runtime'
BUDGET_EXECUTION_CLASS = 'pr317-namespace-bound-composed-budget-v1'
STORAGE_EXECUTION_CLASS = 'pr318-fixed-window-partial-store-v1'
RESTART_EXECUTION_CLASS = 'pr319-composed-budget-restart-diagnostics-v1'
BUDGET_EXPERIMENT = 'pr317-namespace-bound-composed-budget'
BUDGET_APP_IDS = ('feed-reader', 'budget-importer', 'budget-no-trust', 'budget-no-fetch')


def valid_execution_selection(plan, private, authorization):
    """Recognize legacy, fixed PR-316 Mail, or the distinct PR-317 budget class."""
    execution_class = authorization.get('executionClass')
    if execution_class is None:
        return ('executionClass' not in authorization
                and 'selectionDigest' not in authorization)
    if execution_class == RESTART_EXECUTION_CLASS:
        import pr319_restart_contract
        return pr319_restart_contract.verify_selection_contract(plan, private, authorization)
    if execution_class == STORAGE_EXECUTION_CLASS:
        import pr318_storage_contract
        return pr318_storage_contract.verify_selection_contract(plan, private, authorization)
    if execution_class == BUDGET_EXECUTION_CLASS:
        import pr317_budget_contract
        return pr317_budget_contract.verify_selection_contract(plan, private, authorization)
    selected_digest = 'sha256:' + hashlib.sha256(json.dumps({
        'executionClass': execution_class,
        'planDigest': authorization.get('planDigest')}, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    return (execution_class == MAIL_EXECUTION_CLASS
            and plan.get('experimentId') == MAIL_EXPERIMENT
            and private.get('root') ==
                '/var/lib/cryptad-cross-version/experiments/' + MAIL_EXPERIMENT
            and authorization.get('experimentId') == MAIL_EXPERIMENT
            and authorization.get('root') == private.get('root')
            and authorization.get('selectionDigest') == selected_digest)


def _wait_storage_child(child, campaign_deadline_ns):
    """Bound initialization and reap only its still-owned direct fork child.

    No state is removed on failure. An uncertain reap leaves preparation incomplete;
    the two-second termination allowance cannot authorize further campaign work.
    """
    deadline = min(campaign_deadline_ns / 1e9, time.monotonic() + 5)
    while True:
        try:
            observed, status = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            observed = 0
        except ChildProcessError:
            workload.reject('role-storage-child-reconciliation-required')
        if observed == child:
            if time.monotonic() >= deadline:
                workload.reject('role-storage-initialization-timeout')
            if status != 0:
                workload.reject('role-storage-initialization-failed')
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(.01, remaining))
    # No wait has reaped this direct child, so its PID cannot yet be reused.
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    reap_deadline = time.monotonic() + 2
    while True:
        try:
            observed, _status = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            observed = 0
        except ChildProcessError:
            workload.reject('role-storage-child-reconciliation-required')
        if observed == child:
            workload.reject('role-storage-initialization-timeout')
        remaining = reap_deadline - time.monotonic()
        if remaining <= 0:
            workload.reject('role-storage-child-reconciliation-required')
        time.sleep(min(.01, remaining))


def configuration(role):
    """Prospective fixed namespace config; historical layout-2 pins are never relabelled."""
    from restricted_workload_network import address, FNP_PORT, FCP_PORT, HTTP_PORT
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
    import cross_version_runtime as runtime
    workload.unit(role)
    with tempfile.TemporaryDirectory(prefix='cryptad-workload-config-') as temporary:
        node = Path(temporary) / 'node'
        config = runtime.make_runtime_config(node, runtime.interop.Ports(FNP_PORT, FCP_PORT, 0, 0), HTTP_PORT)
        text = config.read_text().replace(str(node), '/node')
    return (text.replace('node.bindTo=127.0.0.1', 'node.bindTo=' + address(role))
            .replace('node.ipAddressOverride=127.0.0.1', 'node.ipAddressOverride=' + address(role))
            .replace('node.includeLocalAddressesInNoderefs=false', 'node.includeLocalAddressesInNoderefs=true')
            # The finite synthetic fixture supplies setup choices before launch. Without
            # this flag the normal HTTP router redirects host bootstrap to the wizard.
            .replace('End\n', 'fproxy.hasCompletedWizard=true\nEnd\n'))


def configuration_identity(role, trust_digest, execution_class=None):
    text = configuration(role)
    from cross_version_runtime import canonical_digest
    value = {'profile': workload.PROFILE, 'role': role,
             'configuration': text, 'appTrustDigest': trust_digest,
             'launcherPolicy': launcher_policy()}
    if execution_class in (BUDGET_EXECUTION_CLASS, STORAGE_EXECUTION_CLASS, RESTART_EXECUTION_CLASS):
        value['budgetLauncherPolicy'] = budget_launcher_policy(execution_class)
    elif execution_class is not None:
        if execution_class != MAIL_EXECUTION_CLASS:
            workload.reject('profile-execution-class-unsupported')
    return canonical_digest(value)


def prepare(plan, private, authorization):
    """Stage a bounded source-built comparison using existing package/app validation.

    The caller is a trusted installed owner or the separately installed administrator
    test kit. All source ancestors must be root owned. No observer controls these paths.
    One retained campaign reserves the entire static pool; reuse requires explicit
    administrator reconciliation outside this API.
    """
    from restricted_workload_network import setup, FNP_PORT, FCP_PORT, HTTP_PORT
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'interop'))
    import cross_version_runtime as runtime
    execution_class = authorization.get('executionClass')
    budget_class = execution_class in (BUDGET_EXECUTION_CLASS, STORAGE_EXECUTION_CLASS, RESTART_EXECUTION_CLASS)
    if (plan.get('provenanceClass') != 'source-build-comparison'
            or set(private) != {'root', 'nodes'}
            or (not budget_class and plan.get('workloadInputs'))
            or set(private['nodes']) != set(workload.ROLES)
            or [row['role'] for row in plan['nodes']] != list(workload.ROLES)
            or plan.get('cohorts')
            or (not budget_class and plan.get('composedBudgetInputs'))
            or authorization.get('syntheticContent') is not True
            or authorization.get('planDigest') != runtime.canonical_digest(plan)
            or authorization.get('experimentId') != plan.get('experimentId')
            or type(authorization.get('maxSeconds')) is not int
            or not 30 <= authorization['maxSeconds'] <= workload.MAX_SECONDS
            or type(authorization.get('maxOperations')) is not int
            or not 1 <= authorization['maxOperations'] <= 10000
            or not valid_execution_selection(plan, private, authorization)):
        workload.reject('profile-selection-unsupported')
    for index, role in enumerate(workload.ROLES):
        selected = plan['nodes'][index]
        row = private['nodes'][role]
        app_ids = [app.get('appId') for app in row.get('apps', [])] if isinstance(row.get('apps'), list) else []
        expected_row = {'archivePath', 'javaHome', 'fnpPort', 'fcpPort', 'httpPort',
                        'apps', 'trustedKeysPath', 'trustedKeysDigest'}
        if budget_class and role == 'candidate-sender':
            expected_row |= {'budgetStatementPath', 'budgetStatementDigest'}
        if (selected.get('product') != 'cryptad'
                or set(row) != expected_row
                or (row['fnpPort'], row['fcpPort'], row['httpPort']) != (FNP_PORT, FCP_PORT, HTTP_PORT)
                or not isinstance(row.get('apps'), list)
                or execution_class == MAIL_EXECUTION_CLASS and app_ids != {
                    'candidate-sender': ['mail-prototype'],
                    'candidate-recipient': ['mail-prototype'],
                    'previous': [], 'relay-no-apps': []}[role]
                or budget_class and app_ids != {
                    'candidate-sender': list(BUDGET_APP_IDS),
                    'candidate-recipient': [], 'previous': [],
                    'relay-no-apps': []}[role]
                or execution_class is None and role == 'candidate-sender' and app_ids not in
                    (['mail-prototype'], ['mail-prototype', 'pr315-probe'])
                or execution_class is None and role == 'candidate-recipient' and
                    app_ids != ['mail-prototype']
                or execution_class is None and role == 'relay-no-apps' and app_ids != []
                or execution_class is None and role == 'previous' and
                    app_ids not in ([], ['mail-prototype'])
                or sorted(app.get('bundleDigest', '') for app in row['apps']) != sorted(selected.get('appDigests', []))):
            workload.reject('profile-app-selection-unsupported')
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from cryptad_certification.cross_version_evidence import validate_plan
    validate_plan(plan)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'restricted'))
    import workload_installation
    implementation = workload_installation.verify()
    if (plan['producer']['sourceCommit'] != implementation['sourceCommit']
            or plan['producer'] != runtime.runner_identity()):
        workload.reject('installed-source-selection-mismatch')
    configurations = {}
    for index, role in enumerate(workload.ROLES):
        selected = plan['nodes'][index]
        if selected['configDigest'] != configuration_identity(
                role, private['nodes'][role]['trustedKeysDigest'], execution_class):
            workload.reject('profile-config-selection-mismatch')
        configurations[role] = configuration(role)
    with workload.locked():
        if (workload.ROOT / 'campaign.json').exists():
            workload.reject('retained-campaign-requires-reconciliation')
        users = [workload.account(role) for role in workload.ROLES]
        if len({user.pw_uid for user in users}) != 4 or len({user.pw_gid for user in users}) != 4:
            workload.reject('role-pool-not-distinct')
        reserved_uids = {user.pw_uid for user in users}
        # Initial reservation also rejects processes outside the expected units. Only UIDs
        # are inspected; no unrelated process environment, executable or command is read.
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                if entry.stat().st_uid in reserved_uids:
                    workload.reject('role-identity-already-live')
            except FileNotFoundError:
                pass
        for role in workload.ROLES:
            state = workload.manager(role, 'show')
            if state['ActiveState'] not in {'inactive', 'failed'} or not workload.quiescent(role):
                workload.reject('role-pool-busy')
        # Admission is a conservative allocation bound, not a filesystem quota. Candidate
        # writable bytes have a separate hard tmpfs limit. Keep headroom for retained failures.
        space = os.statvfs(workload.ROOT)
        if space.f_bavail * space.f_frsize < 16 * 1024**3:
            workload.reject('staging-storage-reserve-unavailable')
        selection = {'plan': plan, 'private': private, 'authorization': authorization}
        generation = secrets.token_hex(32)
        deadline = time.monotonic_ns() + authorization['maxSeconds'] * 10**9
        handles = {role: secrets.token_hex(32) for role in workload.ROLES}
        java_digests = {}
        daemon_digests = {}
        campaign = {'schemaVersion': 1, 'profile': workload.PROFILE, 'generation': generation,
            'implementationIdentity': implementation,
            'executionRecordDigest': workload.execution_record_digest(),
            'classification': 'synthetic-source-build-not-original-authority', 'bootId': workload.boot(),
            'deadlineMonotonicNs': deadline, 'maxOperations': authorization['maxOperations'],
            'selectionDigest': hashlib.sha256(json.dumps(selection, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'handles': handles, 'state': 'preparing'}
        if execution_class is not None:
            campaign['executionClass'] = execution_class
        if budget_class:
            campaign['budgetSelectionDigest'] = authorization['selectionDigest']
        workload.write(workload.ROOT / 'selection.json', selection, create=True)
        workload.write(workload.ROOT / 'campaign.json', campaign, create=True)
        for directory, mode in (('authority', 0o700), ('staging', 0o700), ('roles', 0o711), ('state', 0o711)):
            path = workload.ROOT / directory
            path.mkdir(mode=0o700)
            path.chmod(mode)
        # Paths and generated daemon configuration use controller constants, never
        # values carried by the private selection. Roster order was checked above.
        for index, role in enumerate(workload.ROLES):
            selected = plan['nodes'][index]
            user = workload.account(role)
            row = private['nodes'][role]
            # Pin complete administrator inputs before parsing/extracting candidate archives.
            for key in ('archivePath', 'javaHome'):
                workload.secured(Path(row[key]))
            if tree_identity(row['javaHome'], deadline=deadline / 1e9)['sizeBytes'] > 512 * 1024**2:
                workload.reject('jdk-staging-budget-exceeded')
            total, count = 0, 0
            with tarfile.open(row['archivePath'], 'r:*') as archive:
                for member in archive:
                    total += member.size
                    count += 1
                    if time.monotonic_ns() >= deadline or total > 512 * 1024**2 or count > 30000:
                        workload.reject('package-staging-budget-exceeded')
            staging = workload.ROOT / 'staging' / role
            staging.mkdir(mode=0o700)
            package = runtime.extract_package(row['archivePath'], staging / 'package',
                                              selected['artifactDigest'], selected['artifactSize'])
            verify_wrapper_options(package)
            daemon_digests[role] = runtime.packaged_daemon_identity(package, selected['sourceCommit'])
            runtime.require_native_target(package, selected['packageTarget'], row['javaHome'])
            if runtime.tree_digest(row['javaHome']) != selected['runtimeDigest']:
                workload.reject('jdk-selection-mismatch')
            apps, public = staging / 'apps', staging / 'public'
            apps.mkdir(mode=0o700)
            public.mkdir(mode=0o700)
            if sorted(app['bundleDigest'] for app in row['apps']) != sorted(selected['appDigests']):
                workload.reject('app-selection-mismatch')
            for app in row['apps']:
                allowed = (set(BUDGET_APP_IDS)
                           if budget_class and role == 'candidate-sender'
                           else {'mail-prototype', 'pr315-probe'})
                if (app['appId'] not in allowed
                        or app['appId'] == 'pr315-probe' and role != 'candidate-sender'
                        or role == 'relay-no-apps'):
                    workload.reject('app-adapter-unsupported')
                workload.secured(Path(app['bundlePath']))
                runtime.extract_app_bundle(app['bundlePath'], apps / app['appId'], app['bundleDigest'])
            if (not budget_class and (role == 'candidate-sender'
                    and [app['appId'] for app in row['apps']] not in
                    (['mail-prototype'], ['mail-prototype', 'pr315-probe'])
                    or role == 'candidate-recipient'
                    and [app['appId'] for app in row['apps']] != ['mail-prototype'])):
                workload.reject('mail-selection-required')
            trust = b''
            if row['apps']:
                trust_path = workload.secured(Path(row['trustedKeysPath']))
                with trust_path.open('rb') as stream:
                    trust = stream.read(65537)
                if len(trust) > 65536 or 'sha256:' + hashlib.sha256(trust).hexdigest() != row['trustedKeysDigest']:
                    workload.reject('trust-selection-mismatch')
            (public / 'trusted-app-keys.properties').write_bytes(trust)
            if budget_class and role == 'candidate-sender':
                statement_path = workload.secured(Path(row['budgetStatementPath']))
                with statement_path.open('rb') as stream:
                    statement = stream.read(65537)
                if (not 1 <= len(statement) <= 65536
                        or 'sha256:' + hashlib.sha256(statement).hexdigest()
                            != row['budgetStatementDigest']
                        or row['budgetStatementDigest'] !=
                            authorization['budgetSelection']['statementDigest']):
                    workload.reject('budget-statement-selection-mismatch')
                (public / 'budget-statement.json').write_bytes(statement)
            inputs = workload.ROOT / 'roles' / role
            inputs.mkdir(mode=0o700)
            os.chown(inputs, 0, user.pw_gid)
            inputs.chmod(0o750)
            expected = {}
            for name, source in (('package', package), ('jdk', Path(row['javaHome'])), ('apps', apps), ('public', public)):
                copy_tree(source, inputs / name, deadline / 1e9)
                expected[name] = tree_identity(inputs / name)
            node = workload.ROOT / 'state' / role
            node.mkdir(mode=0o700)
            # A finite tmpfs contains every writable role byte, retained across daemon restart.
            # This source-build profile deliberately does not support host-reboot continuation.
            subprocess.run(['/usr/bin/mount', '-t', 'tmpfs', '-o',
                'size=512M,nr_inodes=32768,nosuid,nodev,mode=0700,uid=' + str(user.pw_uid) + ',gid=' + str(user.pw_gid),
                'cryptad-workload-' + role, str(node)], check=True, env=workload.ENV, timeout=10,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Initialize as the selected UID: never recursively chown a candidate tree.
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(user.pw_gid)
                    os.setuid(user.pw_uid)
                    config = runtime.make_runtime_config(node, runtime.interop.Ports(FNP_PORT, FCP_PORT, 0, 0), HTTP_PORT)
                    config.write_text(configurations[role])
                    (node / 'tmp').mkdir(mode=0o700)
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            _wait_storage_child(child, deadline)
            # Expected initial bytes stay in root authority, separate from normalized runtime config.
            expected_config = hashlib.sha256((node / 'config/cryptad.ini').read_bytes()).hexdigest()
            java_digests[role] = runtime.digest_file(inputs / 'jdk/bin/java')
            launch = {'role': role, 'bootId': campaign['bootId'], 'deadlineMonotonicNs': deadline,
                      'javaDigest': java_digests[role], 'inputs': expected}
            if budget_class:
                launch['executionClass'] = execution_class
                launch['budgetSelectionDigest'] = authorization['selectionDigest']
                launch['budgetAppIdentities'] = {}
                if role == 'candidate-sender':
                    launch['budgetExecutableDigest'] = runtime.digest_file('/usr/bin/sleep')
                    launch['budgetStatementDigest'] = row['budgetStatementDigest']
                    for app_id in BUDGET_APP_IDS:
                        identity = tree_identity(inputs / 'apps' / app_id)
                        if (identity['sizeBytes'] > 64 * 1024 * 1024
                                or identity['fileCount'] > 4095):
                            workload.reject('app-observation-budget-exceeded')
                        launch['budgetAppIdentities'][app_id] = identity
            elif row['apps']:
                launch['mailIdentity'] = tree_identity(inputs / 'apps/mail-prototype')
                if launch['mailIdentity']['sizeBytes'] > 64 * 1024 * 1024 or launch['mailIdentity']['fileCount'] > 4095:
                    workload.reject('app-observation-budget-exceeded')
                if role == 'candidate-sender' and len(row['apps']) == 2:
                    launch['probeIdentity'] = tree_identity(inputs / 'apps/pr315-probe')
                    if (launch['probeIdentity']['sizeBytes'] > 64 * 1024 * 1024
                            or launch['probeIdentity']['fileCount'] > 4095):
                        workload.reject('probe-observation-budget-exceeded')
            workload.write(inputs / 'launch.json', launch, create=True, mode=0o444)
            record = {'handle': handles[role], 'campaign': generation, 'bootId': campaign['bootId'],
                'generation': None, 'managerInvocation': None, 'cgroupIdentity': None,
                'state': 'prepared', 'stopReason': None, 'initialConfigDigest': expected_config}
            workload.write(workload.ROOT / 'authority' / (role + '.json'), record, create=True)
        if daemon_digests['previous'] == daemon_digests['candidate-sender']:
            workload.reject('previous-repackages-current-daemon')
        setup()
        campaign['state'] = 'prepared'
        workload.write(workload.ROOT / 'campaign.json', campaign)
        return {'profile': workload.PROFILE, 'handles': handles, 'expectedJdkDigests': java_digests,
                'deadlineMonotonicNs': campaign['deadlineMonotonicNs'],
                'implementationIdentity': implementation,
                'classification': campaign['classification']}
