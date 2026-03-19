package network.crypta.node.runtime;

import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.OpennetManager;
import network.crypta.node.SecurityLevels;
import network.crypta.runtime.spi.PageChromeSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyPageChromePortTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private SecurityLevels securityLevels;
  @Mock private OpennetManager opennetManager;
  @Mock private DarknetPeerNode enabledPeer;
  @Mock private DarknetPeerNode disabledPeer;

  @Test
  void snapshot_whenCalled_mapsThreatLevelsAndPeerCounts() {
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getNetworkThreatLevel())
        .thenReturn(SecurityLevels.NETWORK_THREAT_LEVEL.HIGH);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
    when(node.network().peers().countConnectedPeers()).thenReturn(4);
    when(node.network().peers().countConnectedDarknetPeers()).thenReturn(2);
    when(node.network().peers().countConnectedOpennetPeers()).thenReturn(2);
    when(node.network().peers().roster().getDarknetPeers())
        .thenReturn(new DarknetPeerNode[] {enabledPeer, disabledPeer, null});
    when(enabledPeer.isDisabled()).thenReturn(false);
    when(disabledPeer.isDisabled()).thenReturn(true);
    when(node.network().opennet()).thenReturn(opennetManager);
    when(opennetManager.getNumberOfConnectedPeersToAimIncludingDarknet()).thenReturn(10);

    LegacyPageChromePort port = new LegacyPageChromePort(node);

    PageChromeSnapshot snapshot = port.snapshot();

    assertEquals(SecurityNetworkThreatLevel.HIGH, snapshot.networkThreatLevel());
    assertEquals(SecurityPhysicalThreatLevel.MAXIMUM, snapshot.physicalThreatLevel());
    assertEquals(4, snapshot.connectedPeerCount());
    assertEquals(2, snapshot.connectedDarknetPeerCount());
    assertEquals(2, snapshot.connectedOpennetPeerCount());
    assertEquals(1, snapshot.enabledDarknetPeerCount());
    assertTrue(snapshot.opennetEnabled());
    assertEquals(10, snapshot.opennetTargetIncludingDarknetPeerCount());
  }
}
