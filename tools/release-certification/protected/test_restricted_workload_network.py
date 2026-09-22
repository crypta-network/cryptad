"""Offline command-policy and retained-state tests; never installed kernel acceptance."""
import copy
import importlib.util
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'restricted_workload_network', Path(__file__).with_name('restricted_workload_network.py'))
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)


class NetworkPolicyTests(unittest.TestCase):
    def test_fixed_roster_has_four_distinct_addresses_and_names(self):
        self.assertEqual(len(set(map(network.address, network.ROLES))), 4)
        self.assertEqual(len(set(map(network.namespace, network.ROLES))), 4)
        for bad in ('unknown', '../relay-no-apps', 'candidate-sender; id', ''):
            with self.subTest(role=bad), self.assertRaises(network.NetworkBoundaryError):
                network.namespace(bad)

    def test_leaf_udp_policy_has_only_relay_peer_and_drops_other_traffic(self):
        rules = network.role_rules('candidate-sender')
        self.assertIn('ip daddr { 10.231.0.4 }', rules)
        self.assertNotIn('10.231.0.2', rules)
        self.assertNotIn('10.231.0.3', rules)
        self.assertEqual(rules.count('policy drop'), 3)
        self.assertEqual(rules.count('udp sport 19400 udp dport 19400'), 2)
        self.assertNotIn('ct state', rules)
        self.assertNotIn('tcp', rules)

    def test_relay_rules_preserve_all_three_peer_links(self):
        rules = network.role_rules('relay-no-apps')
        self.assertIn('{ 10.231.0.1, 10.231.0.2, 10.231.0.3 }', rules)
        self.assertEqual(rules.count('policy drop'), 3)

    def test_switch_validates_ingress_egress_and_addresses(self):
        rules = network.switch_rules()
        for index in range(3):
            self.assertIn(f'iifname "sw{index}" oifname "sw3" ether type ip '
                          f'ip saddr 10.231.0.{index + 1} ip daddr 10.231.0.4', rules)
            self.assertIn(f'iifname "sw3" oifname "sw{index}" ether type ip '
                          f'ip saddr 10.231.0.4 ip daddr 10.231.0.{index + 1}', rules)
        self.assertNotIn('iifname "sw0" oifname "sw1"', rules)
        self.assertEqual(rules.count('ether type arp accept'), 6)
        self.assertEqual(rules.count('udp sport 19400 udp dport 19400'), 6)

    def test_non_root_setup_is_rejected_before_mutation(self):
        with patch.object(network.os, 'geteuid', return_value=1234), patch.object(network, '_run') as run:
            with self.assertRaises(network.NetworkBoundaryError):
                network.setup()
            run.assert_not_called()

    def test_authority_leaf_must_remain_private_even_when_ancestors_are_traversable(self):
        self.assertEqual(network.ROOT.name, 'authority')
        root_owned_traversable = SimpleNamespace(st_mode=0o040711, st_uid=0)
        root_owned_private = SimpleNamespace(st_mode=0o040700, st_uid=0)
        with patch.object(network.os, 'geteuid', return_value=0), \
                patch.object(Path, 'lstat', return_value=root_owned_traversable), \
                patch.object(Path, 'stat', return_value=root_owned_private):
            network._guard()
        with patch.object(network.os, 'geteuid', return_value=0), \
                patch.object(Path, 'lstat', return_value=root_owned_traversable), \
                patch.object(Path, 'stat', return_value=root_owned_traversable):
            with self.assertRaises(network.NetworkBoundaryError):
                network._guard()

    def test_arbitrary_connection_selection_is_rejected_before_state_access(self):
        with patch.object(network, '_load') as load:
            for endpoint in ('19402', 'http://127.0.0.1:1234', 'app', '/run/netns/host'):
                with self.subTest(endpoint=endpoint), self.assertRaises(network.NetworkBoundaryError):
                    network.connect('candidate-sender', endpoint)
            load.assert_not_called()


class SetupStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.namespaces = self.root / 'namespaces'
        self.namespaces.mkdir()
        self.saved = []
        self.commands = []
        self.state = None
        for name, value in (('ROOT', self.root), ('NETNS_ROOT', self.namespaces)):
            holder = patch.object(network, name, value)
            holder.start()
            self.addCleanup(holder.stop)
        for name, replacement in (('_guard', lambda: None), ('_boot', lambda: 'test-boot'),
                                  ('_save', self.save), ('_run', self.record_command),
                                  ('_namespace_identity', lambda name: [11, len(name)])):
            holder = patch.object(network, name, replacement)
            holder.start()
            self.addCleanup(holder.stop)

    def save(self, value, initial=False):
        self.state = copy.deepcopy(value)
        self.saved.append(copy.deepcopy(value))

    def record_command(self, arguments, script=None):
        self.commands.append((arguments, script))

    def test_setup_retains_intent_before_creation_and_filters_before_link_up(self):
        def checked_run(arguments, script=None):
            if arguments[1:3] == ['netns', 'add']:
                self.assertEqual(self.state['pending'], arguments[-1])
                self.assertEqual(self.state['phase'], 'preparing')
            if arguments[-2:] == ['data0', 'up']:
                role_namespace = arguments[2]
                prior = [command for command, _ in self.commands]
                self.assertIn([network.IP, 'netns', 'exec', role_namespace, network.NFT, '-f', '-'], prior)
            self.record_command(arguments, script)
        with patch.object(network, '_run', checked_run):
            network.setup()
        self.assertEqual(self.state['phase'], 'ready')
        self.assertEqual(len(self.state['namespaces']), 5)
        self.assertIsNone(self.state['pending'])
        self.assertEqual(sum(arguments[1:3] == ['netns', 'add'] for arguments, _ in self.commands), 5)
        # No host-side link creation, routing or nft table exists even transiently.
        for command, _ in self.commands:
            if 'link' in command or 'route' in command or 'address' in command:
                self.assertEqual(command[1], '-n')
            if network.NFT in command:
                self.assertEqual(command[1:3], ['netns', 'exec'])
            self.assertNotIn('default', command)

    def test_preexisting_namespace_rejects_without_creating_state(self):
        (self.namespaces / network.namespace('previous')).touch()
        with self.assertRaises(network.NetworkBoundaryError):
            network.setup()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.saved, [])

    def test_dangling_namespace_symlink_also_rejects(self):
        (self.namespaces / network.SWITCH).symlink_to(self.root / 'absent')
        with self.assertRaises(network.NetworkBoundaryError):
            network.setup()
        self.assertEqual(self.commands, [])

    def test_retained_record_prevents_identity_recycling(self):
        (self.root / 'network.json').write_text('{}')
        with self.assertRaises(network.NetworkBoundaryError):
            network.setup()
        self.assertEqual(self.commands, [])

    def test_lost_add_response_retains_uncertain_intent_and_does_not_delete(self):
        def fail(arguments, script=None):
            self.record_command(arguments, script)
            raise network.NetworkBoundaryError('injected-loss')
        with patch.object(network, '_run', fail), self.assertRaises(network.NetworkBoundaryError):
            network.setup()
        self.assertEqual(self.state['pending'], network.SWITCH)
        self.assertEqual(self.state['phase'], 'preparing')
        self.assertEqual(len(self.commands), 1)
        with patch.object(network, '_load', return_value=self.state):
            with self.assertRaises(network.NetworkBoundaryError):
                network.teardown()

    def test_filter_failure_never_marks_ready_or_erases_partial_fabric(self):
        def fail_filter(arguments, script=None):
            self.record_command(arguments, script)
            if network.NFT in arguments:
                raise network.NetworkBoundaryError('injected-filter-failure')
        with patch.object(network, '_run', fail_filter), self.assertRaises(network.NetworkBoundaryError):
            network.setup()
        self.assertEqual(self.state['phase'], 'preparing')
        self.assertEqual(len(self.state['namespaces']), 5)
        self.assertFalse(any('delete' in arguments for arguments, _ in self.commands))
        self.assertFalse(any(arguments[-1] == 'up' for arguments, _ in self.commands))

    def test_connect_rejects_changed_namespace_before_fork(self):
        network.setup()
        with patch.object(network, '_load', return_value=self.state), \
                patch.object(network, '_namespace_identity', return_value=[0, 0]), \
                patch.object(network.os, 'fork') as fork:
            with self.assertRaises(network.NetworkBoundaryError):
                network.connect('previous', 'http')
            fork.assert_not_called()

    def test_teardown_rejects_changed_namespace_without_deleting_anything(self):
        network.setup()
        self.commands.clear()
        with patch.object(network, '_load', return_value=self.state), \
                patch.object(network, '_namespace_identity', return_value=[0, 0]):
            with self.assertRaises(network.NetworkBoundaryError):
                network.teardown()
        self.assertEqual(self.commands, [])


class SocketTransferTests(unittest.TestCase):
    def test_real_fork_passes_connected_socket_without_changing_parent_namespace(self):
        # This tests SCM_RIGHTS only. setns is deliberately mocked, so it is NOT evidence
        # of installed role isolation or active sibling denial.
        role = 'candidate-sender'
        with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
            root = Path(directory)
            target = root / network.namespace(role)
            target.touch()
            info = target.stat()
            identity = [info.st_dev, info.st_ino]
            state = {'phase': 'ready', 'pending': None,
                     'namespaces': {network.namespace(role): identity}}
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(3)
            parent_namespace = Path('/proc/self/ns/net').stat().st_ino
            with patch.object(network, 'NETNS_ROOT', root), \
                    patch.object(network, '_load', return_value=state), \
                    patch.object(network, '_namespace_identity', return_value=identity), \
                    patch.object(network.os, 'setns', return_value=None) as setns:
                with network._connect_port(role, listener.getsockname()[1]) as connected:
                    peer, _ = listener.accept()
                    with peer:
                        peer.sendall(b'fixed-canary')
                        self.assertEqual(connected.recv(32), b'fixed-canary')
                        connected.sendall(b'ack')
                        self.assertEqual(peer.recv(3), b'ack')
                    self.assertFalse(os.get_inheritable(connected.fileno()))
                # Calls in the forked child do not modify the parent's mock or namespace.
                setns.assert_not_called()
            self.assertEqual(Path('/proc/self/ns/net').stat().st_ino, parent_namespace)


if __name__ == '__main__':
    unittest.main()
