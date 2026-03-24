package network.crypta.node;

import java.lang.reflect.Field;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.runtime.alerts.PeerManagerUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerAlertCoordinatorTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerRoster roster;
  @Mock private PeerStatusBook statusBook;
  @Mock private NodeClientCore clientCore;
  @Mock private UserAlertManager alertManager;
  @Mock private NodeStats nodeStats;
  @Mock private NodeUpdateManager nodeUpdateManager;

  @Test
  void update_whenAlertNotInitialized_expectNoInteractions() {
    // Arrange
    PeerAlertCoordinator coordinator = new PeerAlertCoordinator(node, roster, statusBook);

    // Act
    coordinator.update();

    // Assert
    verifyNoInteractions(node, roster, statusBook);
  }

  @Test
  void update_whenOpennetDisabled_expectCountersSetAndNoNotification() {
    // Arrange
    PeerAlertCoordinator coordinator = new PeerAlertCoordinator(node, roster, statusBook);
    PeerManagerUserAlert alert = mock(PeerManagerUserAlert.class);
    setAlert(coordinator, alert);

    when(roster.getDarknetPeers()).thenReturn(new DarknetPeerNode[2]);
    when(roster.getOpennetPeers()).thenReturn(new OpennetPeerNode[1]);
    when(roster.anyConnectedPeers()).thenReturn(false);

    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true))
        .thenReturn(1);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, true))
        .thenReturn(1);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false))
        .thenReturn(2);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false))
        .thenReturn(0);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED, true))
        .thenReturn(4);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM, false))
        .thenReturn(1);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONN_ERROR, true))
        .thenReturn(3);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true))
        .thenReturn(2);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false))
        .thenReturn(5);

    when(node.network().opennet()).thenReturn(null);

    NodeCrypto darknetCrypto = mock(NodeCrypto.class);
    NodeCryptoConfig darknetConfig = mock(NodeCryptoConfig.class);
    when(node.network().darknetCrypto()).thenReturn(darknetCrypto);
    when(darknetCrypto.getConfig()).thenReturn(darknetConfig);
    when(darknetConfig.alwaysHandshakeAggressively()).thenReturn(true);
    when(node.network().darknetDefinitelyPortForwarded()).thenReturn(true);

    // Act
    coordinator.update();

    // Assert
    verify(alert).setOpennetDefinitelyPortForwarded(false);
    verify(alert).setDarknetDefinitelyPortForwarded(true);
    verify(alert).setOpennetAssumeNAT(false);
    verify(alert).setDarknetAssumeNAT(true);
    verify(alert).setDarknetConns(2);
    verify(alert).setConns(2);
    verify(alert).setDarknetPeers(2);
    verify(alert).setDisconnDarknetPeers(0);
    verify(alert).setPeers(3);
    verify(alert).setNeverConn(4);
    verify(alert).setClockProblem(1);
    verify(alert).setConnError(3);
    verify(alert).setOpennetEnabled(false);
    verify(alert).setTooNewPeersDarknet(2);
    verify(alert).setTooNewPeersTotal(5);
    verify(node.network(), never()).onConnectedPeer();
  }

  @Test
  void update_whenOpennetEnabledAndPeersConnected_expectOpennetFlagsAndNotify() {
    // Arrange
    PeerAlertCoordinator coordinator = new PeerAlertCoordinator(node, roster, statusBook);
    PeerManagerUserAlert alert = mock(PeerManagerUserAlert.class);
    setAlert(coordinator, alert);

    when(roster.getDarknetPeers()).thenReturn(new DarknetPeerNode[1]);
    when(roster.getOpennetPeers()).thenReturn(new OpennetPeerNode[2]);
    when(roster.anyConnectedPeers()).thenReturn(true);

    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true))
        .thenReturn(1);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, true))
        .thenReturn(0);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false))
        .thenReturn(2);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false))
        .thenReturn(1);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED, true))
        .thenReturn(0);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM, false))
        .thenReturn(0);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONN_ERROR, true))
        .thenReturn(0);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true))
        .thenReturn(1);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false))
        .thenReturn(2);

    OpennetManager opennet = mock(OpennetManager.class);
    NodeCrypto opennetCrypto = mock(NodeCrypto.class);
    NodeCryptoConfig opennetConfig = mock(NodeCryptoConfig.class);
    when(node.network().opennet()).thenReturn(opennet);
    when(opennet.getCrypto()).thenReturn(opennetCrypto);
    when(opennetCrypto.definitelyPortForwarded()).thenReturn(true);
    when(opennetCrypto.getConfig()).thenReturn(opennetConfig);
    when(opennetConfig.alwaysHandshakeAggressively()).thenReturn(true);

    NodeCrypto darknetCrypto = mock(NodeCrypto.class);
    NodeCryptoConfig darknetConfig = mock(NodeCryptoConfig.class);
    when(node.network().darknetCrypto()).thenReturn(darknetCrypto);
    when(darknetCrypto.getConfig()).thenReturn(darknetConfig);
    when(darknetConfig.alwaysHandshakeAggressively()).thenReturn(false);
    when(node.network().darknetDefinitelyPortForwarded()).thenReturn(false);

    // Act
    coordinator.update();

    // Assert
    verify(alert).setOpennetEnabled(true);
    verify(alert).setOpennetDefinitelyPortForwarded(true);
    verify(alert).setOpennetAssumeNAT(true);
    verify(alert).setDarknetDefinitelyPortForwarded(false);
    verify(alert).setDarknetAssumeNAT(false);
    verify(alert).setDarknetConns(1);
    verify(alert).setConns(3);
    verify(alert).setDarknetPeers(1);
    verify(alert).setDisconnDarknetPeers(0);
    verify(alert).setPeers(3);
    verify(alert).setTooNewPeersDarknet(1);
    verify(alert).setTooNewPeersTotal(2);
    verify(node.network(), times(1)).onConnectedPeer();
  }

  @Test
  void start_whenCalled_expectRegistersAlertAndUpdates() {
    // Arrange
    PeerAlertCoordinator coordinator = new PeerAlertCoordinator(node, roster, statusBook);

    when(node.network().stats()).thenReturn(nodeStats);
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alertManager);

    when(roster.getDarknetPeers()).thenReturn(new DarknetPeerNode[0]);
    when(roster.getOpennetPeers()).thenReturn(new OpennetPeerNode[0]);
    when(roster.anyConnectedPeers()).thenReturn(false);

    NodeCrypto darknetCrypto = mock(NodeCrypto.class);
    NodeCryptoConfig darknetConfig = mock(NodeCryptoConfig.class);
    when(node.network().darknetCrypto()).thenReturn(darknetCrypto);
    when(darknetCrypto.getConfig()).thenReturn(darknetConfig);
    when(darknetConfig.alwaysHandshakeAggressively()).thenReturn(false);

    // Act
    coordinator.start();

    // Assert
    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);
    verify(alertManager).register(alertCaptor.capture());
    assertNotNull(alertCaptor.getValue());
    assertInstanceOf(PeerManagerUserAlert.class, alertCaptor.getValue());
    verify(statusBook).getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true);
    verify(roster).getDarknetPeers();
    verify(roster).getOpennetPeers();
  }

  @SuppressWarnings("java:S3011")
  private static void setAlert(PeerAlertCoordinator coordinator, PeerManagerUserAlert alert) {
    try {
      Field alertField = PeerAlertCoordinator.class.getDeclaredField("alert");
      alertField.setAccessible(true);
      alertField.set(coordinator, alert);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Unable to set PeerAlertCoordinator alert", e);
    }
  }
}
