package network.crypta.node.updater;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.util.Random;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTransport;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UpdateOverMandatoryManagerTest {

  @Mock private NodeUpdateManager updateManager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore clientCore;
  @Mock private UserAlertManager alertManager;
  @Mock private Ticker ticker;
  @Mock private ByteCounter byteCounter;

  private UpdateOverMandatoryManager uom;

  @BeforeEach
  void setUp() {
    // Common node/updateManager wiring used across tests
    when(updateManager.getNode()).thenReturn(node);
    when(updateManager.getByteCounter()).thenReturn(byteCounter);
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alertManager);
    when(node.network().ticker()).thenReturn(ticker);
    // Do nothing when jobs are queued in tests to keep determinism
    doAnswer(invocation -> null).when(ticker).queueTimedJob(any(Runnable.class), anyLong());
    // Random used for message UIDs (RandomSource is required by Node API)
    network.crypta.crypt.RandomSource rs =
        new network.crypta.crypt.RandomSource() {
          private final Random delegate = new Random(1234);

          @Override
          public int acceptEntropy(
              network.crypta.crypt.EntropySource source, long data, int entropyGuess) {
            return 0;
          }

          @Override
          public int acceptTimerEntropy(network.crypta.crypt.EntropySource timer) {
            return 0;
          }

          @Override
          public int acceptTimerEntropy(
              network.crypta.crypt.EntropySource fnpTimingSource, double bias) {
            return 0;
          }

          @Override
          public int acceptEntropyBytes(
              network.crypta.crypt.EntropySource myPacketDataSource,
              byte[] buf,
              int offset,
              int length,
              double bias) {
            return 0;
          }

          @Override
          public void close() {
            // No-op for test RandomSource: this stub does not acquire resources
            // and exists solely to provide deterministic randomness in tests.
          }

          @Override
          public long nextLong() {
            return delegate.nextLong();
          }

          @Override
          protected synchronized int next(int bits) {
            return delegate.nextInt() >>> (32 - bits);
          }
        };
    when(node.getRandom()).thenReturn(rs);

    // Default: auto-update enabled.
    when(updateManager.isEnabled()).thenReturn(true);

    uom = new UpdateOverMandatoryManager(updateManager);
  }

  @Test
  void handleAnnounce_whenRevocationKeyMatches_expectPeerClaimedAndAlertRegistered()
      throws MalformedURLException, NotConnectedException {
    // Arrange
    Message m = org.mockito.Mockito.mock(Message.class);
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);

    when(m.getString(DMT.REVOCATION_KEY)).thenReturn("KSK@revoked");
    when(m.getBoolean(DMT.HAVE_REVOCATION_KEY)).thenReturn(true);
    // Unused here but read; provide safe defaults
    when(m.getString(DMT.MAIN_JAR_KEY)).thenReturn("KSK@unused");
    when(m.getInt(DMT.MAIN_JAR_VERSION)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED)).thenReturn(0L);
    when(m.getInt(DMT.REVOCATION_KEY_DNF_COUNT)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH)).thenReturn(1L);
    when(m.getLong(DMT.MAIN_JAR_FILE_LENGTH)).thenReturn(0L);
    when(m.getInt(DMT.PING_TIME)).thenReturn(0);
    when(m.getInt(DMT.BWLIMIT_DELAY_TIME)).thenReturn(0);

    when(peer.userToString()).thenReturn("peer-1");
    when(peer.getSimpleVersion()).thenReturn(1);
    when(peer.isConnected()).thenReturn(true);

    when(updateManager.isBlown()).thenReturn(false);
    when(updateManager.getRevocationURI()).thenReturn(new FreenetURI("KSK@revoked"));

    // Do nothing on send; callback is not used for the success-path assertion here
    doAnswer(invocation -> null)
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    // Act
    boolean handled = uom.handleAnnounce(m, peer);

    // Assert
    assertTrue(handled);
    verify(updateManager, times(1)).peerClaimsKeyBlown();

    // An alert is registered exactly once for the first matching announce
    ArgumentCaptor<network.crypta.node.useralerts.UserAlert> alertCaptor =
        ArgumentCaptor.forClass(network.crypta.node.useralerts.UserAlert.class);
    verify(alertManager, times(1)).register(alertCaptor.capture());
    assertNotNull(alertCaptor.getValue(), "Alert instance must be non-null");

    // Node classification should show the peer as "connected" (not failed/disconnected)
    PeerNode[][] classified = uom.getNodesSayBlown();
    assertEquals(1, classified[0].length, "connectedSayBlown count");
    assertEquals(0, classified[1].length, "disconnectedSayBlown count");
    assertEquals(0, classified[2].length, "failedTransferSayBlown count");
    assertEquals(peer, classified[0][0]);
  }

  @Test
  void handleAnnounce_whenRevocationKeyMalformed_expectIgnored() {
    // Arrange
    Message m = org.mockito.Mockito.mock(Message.class);
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);

    when(m.getString(DMT.REVOCATION_KEY)).thenReturn("NOT_A_URI");
    when(m.getBoolean(DMT.HAVE_REVOCATION_KEY)).thenReturn(true);
    when(updateManager.isBlown()).thenReturn(false);

    // Unused fields but read during logging
    when(m.getString(DMT.MAIN_JAR_KEY)).thenReturn("KSK@unused");
    when(m.getInt(DMT.MAIN_JAR_VERSION)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED)).thenReturn(0L);
    when(m.getInt(DMT.REVOCATION_KEY_DNF_COUNT)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH)).thenReturn(0L);
    when(m.getLong(DMT.MAIN_JAR_FILE_LENGTH)).thenReturn(0L);
    when(m.getInt(DMT.PING_TIME)).thenReturn(0);
    when(m.getInt(DMT.BWLIMIT_DELAY_TIME)).thenReturn(0);

    // Act
    boolean handled = uom.handleAnnounce(m, peer);

    // Assert
    assertTrue(handled);
    verify(updateManager, never()).peerClaimsKeyBlown();
    PeerNode[][] classified = uom.getNodesSayBlown();
    assertArrayEquals(new PeerNode[0], classified[0], "connectedSayBlown should be empty");
    assertArrayEquals(new PeerNode[0], classified[1], "disconnectedSayBlown should be empty");
    assertArrayEquals(new PeerNode[0], classified[2], "failedTransferSayBlown should be empty");
  }

  @Test
  void handleAnnounce_whenRevocationSendFailsNotConnected_expectRemovedFromState()
      throws MalformedURLException, NotConnectedException {
    // Arrange
    Message m = org.mockito.Mockito.mock(Message.class);
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);

    when(m.getString(DMT.REVOCATION_KEY)).thenReturn("KSK@revoked");
    when(m.getBoolean(DMT.HAVE_REVOCATION_KEY)).thenReturn(true);
    // Logging related fields
    when(m.getString(DMT.MAIN_JAR_KEY)).thenReturn("KSK@unused");
    when(m.getInt(DMT.MAIN_JAR_VERSION)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED)).thenReturn(0L);
    when(m.getInt(DMT.REVOCATION_KEY_DNF_COUNT)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH)).thenReturn(1L);
    when(m.getLong(DMT.MAIN_JAR_FILE_LENGTH)).thenReturn(0L);
    when(m.getInt(DMT.PING_TIME)).thenReturn(0);
    when(m.getInt(DMT.BWLIMIT_DELAY_TIME)).thenReturn(0);

    when(peer.userToString()).thenReturn("peer-2");
    when(peer.getSimpleVersion()).thenReturn(2);
    when(updateManager.isBlown()).thenReturn(false);
    when(updateManager.getRevocationURI()).thenReturn(new FreenetURI("KSK@revoked"));

    // Simulate immediate NotConnected on send
    doThrow(new NotConnectedException())
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    // Act
    boolean handled = uom.handleAnnounce(m, peer);

    // Assert: we still claimed blown once, but then removed the peer from state
    assertTrue(handled);
    verify(updateManager, times(1)).peerClaimsKeyBlown();
    PeerNode[][] classified = uom.getNodesSayBlown();
    assertEquals(
        0,
        classified[0].length + classified[1].length + classified[2].length,
        "All revocation sets should be empty after NotConnected");
  }

  @Test
  void getNodesSayBlown_whenMixedPeers_expectCorrectClassification()
      throws MalformedURLException, NotConnectedException {
    // Arrange common message fields
    Message m = org.mockito.Mockito.mock(Message.class);
    when(m.getString(DMT.REVOCATION_KEY)).thenReturn("KSK@revoked");
    when(m.getBoolean(DMT.HAVE_REVOCATION_KEY)).thenReturn(true);
    when(m.getString(DMT.MAIN_JAR_KEY)).thenReturn("KSK@unused");
    when(m.getInt(DMT.MAIN_JAR_VERSION)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED)).thenReturn(0L);
    when(m.getInt(DMT.REVOCATION_KEY_DNF_COUNT)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH)).thenReturn(1L);
    when(m.getLong(DMT.MAIN_JAR_FILE_LENGTH)).thenReturn(0L);
    when(m.getInt(DMT.PING_TIME)).thenReturn(0);
    when(m.getInt(DMT.BWLIMIT_DELAY_TIME)).thenReturn(0);

    when(updateManager.isBlown()).thenReturn(false);
    when(updateManager.getRevocationURI()).thenReturn(new FreenetURI("KSK@revoked"));

    PeerNode connected = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport connectedTransport = org.mockito.Mockito.mock(PeerTransport.class);
    when(connected.transport()).thenReturn(connectedTransport);
    when(connected.userToString()).thenReturn("connected");
    when(connected.getSimpleVersion()).thenReturn(10);
    when(connected.isConnected()).thenReturn(true);
    doAnswer(inv -> null)
        .when(connectedTransport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    PeerNode disconnected = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport disconnectedTransport = org.mockito.Mockito.mock(PeerTransport.class);
    when(disconnected.transport()).thenReturn(disconnectedTransport);
    when(disconnected.userToString()).thenReturn("disconnected");
    when(disconnected.getSimpleVersion()).thenReturn(11);
    when(disconnected.isConnected()).thenReturn(false);
    doAnswer(inv -> null)
        .when(disconnectedTransport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    PeerNode failed = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport failedTransport = org.mockito.Mockito.mock(PeerTransport.class);
    when(failed.transport()).thenReturn(failedTransport);
    when(failed.userToString()).thenReturn("failed");
    when(failed.getSimpleVersion()).thenReturn(12);
    when(failed.isConnected()).thenReturn(true);
    // Trigger callback.disconnected() path to mark as failed transfer
    doAnswer(
            invocation -> {
              AsyncMessageCallback cb = invocation.getArgument(1);
              if (cb != null) cb.disconnected();
              return null;
            })
        .when(failedTransport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    // Act
    assertTrue(uom.handleAnnounce(m, connected));
    assertTrue(uom.handleAnnounce(m, disconnected));
    assertTrue(uom.handleAnnounce(m, failed));

    // Assert
    PeerNode[][] classified = uom.getNodesSayBlown();
    assertEquals(1, classified[0].length, "connectedSayBlown");
    assertEquals(1, classified[1].length, "disconnectedSayBlown");
    assertEquals(1, classified[2].length, "failedTransferSayBlown");
  }

  @Test
  void flags_and_fetching_state_expectDefaultsWhenJarUomDisabled()
      throws MalformedURLException, NotConnectedException {
    // Arrange defaults
    assertFalse(uom.persistent());
    assertFalse(uom.realTimeFlag());
    assertFalse(uom.isFetchingMain());

    // Prepare a main-jar offer scenario. In package-based mode this should be ignored.
    when(updateManager.isBlown()).thenReturn(false);
    when(node.isOutdated()).thenReturn(true); // intentionally spelled as in production code
    when(updateManager.newMainJarVersion()).thenReturn(0);
    when(updateManager.getMainVersion()).thenReturn(0);
    when(updateManager.getURI()).thenReturn(new FreenetURI("KSK@main"));

    Message m = org.mockito.Mockito.mock(Message.class);
    when(m.getString(DMT.MAIN_JAR_KEY)).thenReturn("KSK@main");
    when(m.getInt(DMT.MAIN_JAR_VERSION)).thenReturn(5); // > current build number (likely 0 in dev)
    when(m.getLong(DMT.MAIN_JAR_FILE_LENGTH)).thenReturn(1024L);
    when(m.getBoolean(DMT.HAVE_REVOCATION_KEY)).thenReturn(false);
    when(m.getString(DMT.REVOCATION_KEY)).thenReturn("KSK@revoked");
    when(m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED)).thenReturn(0L);
    when(m.getInt(DMT.REVOCATION_KEY_DNF_COUNT)).thenReturn(0);
    when(m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH)).thenReturn(0L);
    when(m.getInt(DMT.PING_TIME)).thenReturn(0);
    when(m.getInt(DMT.BWLIMIT_DELAY_TIME)).thenReturn(0);

    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.isConnected()).thenReturn(true);
    when(peer.isSeed()).thenReturn(false);
    // sendUOMRequest will set offered version on the peer and then read it; return the offered
    // value
    when(peer.getMainJarOfferedVersion()).thenReturn(5);
    doAnswer(invocation -> null)
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    // Act
    assertTrue(uom.handleAnnounce(m, peer));

    // Assert transitions
    assertFalse(uom.isFetchingMain(), "main-jar UOM must stay disabled");
    assertFalse(uom.fetchingUOM(), "fetchingUOM must stay false when jar UOM is disabled");
  }
}
