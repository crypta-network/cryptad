package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import network.crypta.node.SeedServerTestPeerNode.FATE;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "java:S106", "java:S112", "java:S3011"})
@ExtendWith(MockitoExtension.class)
class SeedServerTestPeerNodeTest {

  private PrintStream originalErr;
  private ByteArrayOutputStream errBuffer;

  @BeforeEach
  void setUpStreams() {
    originalErr = System.err;
    errBuffer = new ByteArrayOutputStream(256);
    System.setErr(new PrintStream(errBuffer));
  }

  @AfterEach
  void restoreStreams() {
    System.setErr(originalErr);
  }

  // -------- getFate() --------

  @Test
  @DisplayName("getFate when connected and no packets -> CONNECTED_NO_PACKETS_RECEIVED")
  void getFate_whenConnectedNoPackets_expectCONNECTED_NO_PACKETS_RECEIVED() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);
    doReturn(true).when(sut).isConnected();
    doReturn(0L).when(sut).lastReceivedDataPacketTime();

    FATE fate = sut.getFate();

    assertEquals(FATE.CONNECTED_NO_PACKETS_RECEIVED, fate);
  }

  @Test
  @DisplayName("getFate when connected and too old -> CONNECTED_TOO_OLD")
  void getFate_whenConnectedTooOld_expectCONNECTED_TOO_OLD() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);
    doReturn(true).when(sut).isConnected();
    doReturn(123L).when(sut).lastReceivedDataPacketTime();
    doReturn(true).when(sut).isUnroutableOlderVersion();

    FATE fate = sut.getFate();

    assertEquals(FATE.CONNECTED_TOO_OLD, fate);
  }

  @Test
  @DisplayName("getFate when connected and packets received -> CONNECTED_SUCCESS")
  void getFate_whenConnectedPackets_expectCONNECTED_SUCCESS() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);
    doReturn(true).when(sut).isConnected();
    doReturn(999L).when(sut).lastReceivedDataPacketTime();
    doReturn(false).when(sut).isUnroutableOlderVersion();

    FATE fate = sut.getFate();

    assertEquals(FATE.CONNECTED_SUCCESS, fate);
  }

  @Test
  @DisplayName("getFate when never connected -> NEVER_CONNECTED")
  void getFate_whenNeverConnected_expectNEVER_CONNECTED() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);
    doReturn(false).when(sut).isConnected();
    doReturn(-1L).when(sut).lastReceivedDataPacketTime();
    doReturn(0L).when(sut).timeLastConnectionCompleted();

    FATE fate = sut.getFate();

    assertEquals(FATE.NEVER_CONNECTED, fate);
  }

  @Test
  @DisplayName(
      "getFate when disconnected, had connection, and no packets ->"
          + " CONNECTED_TIMEOUT_NO_PACKETS_RECEIVED")
  void getFate_whenDisconnectedAfterConnectNoPackets_expectTIMEOUT_NO_PACKETS() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);
    doReturn(false).when(sut).isConnected();
    doReturn(-1L).when(sut).lastReceivedDataPacketTime();
    doReturn(42L).when(sut).timeLastConnectionCompleted();

    FATE fate = sut.getFate();

    assertEquals(FATE.CONNECTED_TIMEOUT_NO_PACKETS_RECEIVED, fate);
  }

  @Test
  @DisplayName("getFate when disconnected after packets -> CONNECTED_DISCONNECTED_UNKNOWN")
  void getFate_whenDisconnectedAfterPackets_expectDISCONNECTED_UNKNOWN() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);
    doReturn(false).when(sut).isConnected();
    doReturn(10L).when(sut).lastReceivedDataPacketTime();
    doReturn(100L).when(sut).timeLastConnectionCompleted();

    FATE fate = sut.getFate();

    assertEquals(FATE.CONNECTED_DISCONNECTED_UNKNOWN, fate);
  }

  // -------- shouldDisconnectAndRemoveNow() --------

  @Test
  @DisplayName("shouldDisconnectAndRemoveNow is always false in test subclass")
  void shouldDisconnectAndRemoveNow_alwaysFalse() {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);

    assertFalse(sut.shouldDisconnectAndRemoveNow());
  }

  // -------- onRemove() log classification --------

  @Test
  @DisplayName("onRemove prints NEVER CONNECTED and calls cleanup path")
  void onRemove_whenNeverConnected_printsNeverConnectedAndCleansUp() throws Exception {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);

    doReturn("ID-ABC").when(sut).getIdentityString();
    doReturn(-1L).when(sut).lastReceivedDataPacketTime();
    doReturn(0L).when(sut).timeLastConnectionCompleted();

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Ticker ticker = mock(Ticker.class);
    doNothing().when(ticker).removeQueuedJob(any());
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(ticker).when(network).ticker();
    setNodeOnPeerNode(sut, node);

    doReturn(true).when(sut).disconnected(true, true);
    doNothing().when(sut).stopARKFetcher();

    sut.onRemove();

    String err = errBuffer.toString();
    verify(sut, times(1)).disconnected(true, true);
    verify(ticker, times(1)).removeQueuedJob(any());
    // Expect the NEVER CONNECTED classification
    // Message format: "<id> : REMOVED: NEVER CONNECTED"
    org.hamcrest.MatcherAssert.assertThat(
        err, org.hamcrest.Matchers.containsString("ID-ABC : REMOVED: NEVER CONNECTED"));
  }

  @Test
  @DisplayName("onRemove prints TIMEOUT NO PACKETS after successful setup")
  void onRemove_whenTimeoutNoPackets_printsTimeoutNoPackets() throws Exception {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);

    doReturn("ID-XYZ").when(sut).getIdentityString();
    doReturn(0L).when(sut).lastReceivedDataPacketTime();
    doReturn(123L).when(sut).timeLastConnectionCompleted();

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Ticker ticker = mock(Ticker.class);
    doNothing().when(ticker).removeQueuedJob(any());
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(ticker).when(network).ticker();
    setNodeOnPeerNode(sut, node);

    doReturn(true).when(sut).disconnected(true, true);
    doNothing().when(sut).stopARKFetcher();

    sut.onRemove();

    String err = errBuffer.toString();
    org.hamcrest.MatcherAssert.assertThat(
        err,
        org.hamcrest.Matchers.containsString(
            "ID-XYZ : REMOVED: TIMEOUT: NO PACKETS RECEIVED AFTER SUCCESSFUL CONNECTION SETUP"));
  }

  @Test
  @DisplayName("onRemove prints UNKNOWN CAUSE when previously connected with data")
  void onRemove_whenUnknown_printsUnknownCause() throws Exception {
    SeedServerTestPeerNode sut = mock(SeedServerTestPeerNode.class, CALLS_REAL_METHODS);

    doReturn("ID-UNK").when(sut).getIdentityString();
    doReturn(999L).when(sut).lastReceivedDataPacketTime();
    doReturn(888L).when(sut).timeLastConnectionCompleted();

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Ticker ticker = mock(Ticker.class);
    doNothing().when(ticker).removeQueuedJob(any());
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(ticker).when(network).ticker();
    setNodeOnPeerNode(sut, node);

    doReturn(true).when(sut).disconnected(true, true);
    doNothing().when(sut).stopARKFetcher();

    sut.onRemove();

    String err = errBuffer.toString();
    org.hamcrest.MatcherAssert.assertThat(
        err, org.hamcrest.Matchers.containsString("ID-UNK : REMOVED: UNKNOWN CAUSE"));
  }

  // -------- helpers --------

  private static void setNodeOnPeerNode(Object target, Node node) throws Exception {
    Field f = PeerNode.class.getDeclaredField("node");
    f.setAccessible(true);
    f.set(target, node);
  }
}
