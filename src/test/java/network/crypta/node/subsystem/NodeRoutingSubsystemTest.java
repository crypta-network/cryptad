package network.crypta.node.subsystem;

import java.lang.reflect.Field;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.node.InsertTag;
import network.crypta.node.Node;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.RequestTag;
import network.crypta.runtime.bootstrap.NodeBootstrap;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeRoutingSubsystemTest {
  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private NodeStorageSubsystem storage;
  @Mock private NodeBootstrap bootstrap;
  @Mock private RandomSource random;

  private NodeRoutingSubsystem subsystem;

  @BeforeEach
  void setUp() {
    subsystem = new NodeRoutingSubsystem(node);
  }

  @Test
  void init_whenCalled_setsTrackerAndFailureTable() {
    PeerManager peers = mock(PeerManager.class);
    Ticker ticker = mock(Ticker.class);
    when(node.network()).thenReturn(network);
    when(network.peers()).thenReturn(peers);
    when(network.ticker()).thenReturn(ticker);
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.random()).thenReturn(random);

    subsystem.init();

    assertNotNull(subsystem.tracker());
    assertNotNull(subsystem.failureTable());
  }

  @Test
  void initDecrementPolicy_whenRandomBelowThreshold_setsFlagsTrue() throws Exception {
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.random()).thenReturn(random);
    when(random.nextDouble()).thenReturn(0.0, 0.0);

    subsystem.initDecrementPolicy();

    assertTrue(getPrivateBoolean(subsystem, "decrementAtMax"));
    assertTrue(getPrivateBoolean(subsystem, "decrementAtMin"));
  }

  @Test
  void initDecrementPolicy_whenRandomAboveThreshold_setsFlagsFalse() throws Exception {
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.random()).thenReturn(random);
    when(random.nextDouble()).thenReturn(1.0, 1.0);

    subsystem.initDecrementPolicy();

    assertFalse(getPrivateBoolean(subsystem, "decrementAtMax"));
    assertFalse(getPrivateBoolean(subsystem, "decrementAtMin"));
  }

  @Test
  void shouldStoreDeep_whenSourceCloserAndHighUptime_expectFalse() {
    Key key = mock(Key.class);
    when(key.toNormalizedDouble()).thenReturn(0.2);
    when(node.network()).thenReturn(network);
    when(network.location()).thenReturn(0.1);

    PeerNode source = mock(PeerNode.class);
    when(source.isLowUptime()).thenReturn(false);
    when(source.getLocation()).thenReturn(0.15);

    boolean result = subsystem.shouldStoreDeep(key, source, new PeerNode[0]);

    assertFalse(result);
  }

  @Test
  void shouldStoreDeep_whenRoutedPeerCloserAndHighUptime_expectFalse() {
    Key key = mock(Key.class);
    when(key.toNormalizedDouble()).thenReturn(0.2);
    when(node.network()).thenReturn(network);
    when(network.location()).thenReturn(0.1);

    PeerNode routedPeer = mock(PeerNode.class);
    when(routedPeer.isLowUptime()).thenReturn(false);
    when(routedPeer.getLocation()).thenReturn(0.15);

    boolean result = subsystem.shouldStoreDeep(key, null, new PeerNode[] {routedPeer});

    assertFalse(result);
  }

  @Test
  void shouldStoreDeep_whenCloserPeersLowUptime_expectTrue() {
    Key key = mock(Key.class);
    when(key.toNormalizedDouble()).thenReturn(0.2);
    when(node.network()).thenReturn(network);
    when(network.location()).thenReturn(0.1);

    PeerNode source = mock(PeerNode.class);
    when(source.isLowUptime()).thenReturn(true);

    PeerNode routedPeer = mock(PeerNode.class);
    when(routedPeer.isLowUptime()).thenReturn(true);

    boolean result = subsystem.shouldStoreDeep(key, source, new PeerNode[] {routedPeer});

    assertTrue(result);
  }

  @ParameterizedTest
  @CsvSource({"8,true", "9,false"})
  void canWriteDatastoreRequest_whenBoundaryValues_expectCorrectResult(int htl, boolean expected) {
    when(node.maxHTL()).thenReturn((short) 10);
    boolean result = subsystem.canWriteDatastoreRequest((short) htl);

    assertEquals(expected, result);
  }

  @ParameterizedTest
  @CsvSource({"7,true", "8,false"})
  void canWriteDatastoreInsert_whenBoundaryValues_expectCorrectResult(int htl, boolean expected) {
    when(node.maxHTL()).thenReturn((short) 10);
    boolean result = subsystem.canWriteDatastoreInsert((short) htl);

    assertEquals(expected, result);
  }

  @Test
  void decrementHTL_whenSourceProvided_delegatesToSource() {
    PeerNode source = mock(PeerNode.class);
    when(source.decrementHTL((short) 4)).thenReturn((short) 2);

    short result = subsystem.decrementHTL(source, (short) 4);

    assertEquals(2, result);
    verify(source).decrementHTL((short) 4);
    verifyNoInteractions(node);
  }

  @Test
  void decrementHTL_whenAtMaxAndProbabilisticEnabled_expectNoDecrement() throws Exception {
    setPrivateBooleanFalse(subsystem, "decrementAtMax");
    when(node.maxHTL()).thenReturn((short) 10);
    when(node.isDisableProbabilisticHTLs()).thenReturn(false);

    short result = subsystem.decrementHTL(null, (short) 10);

    assertEquals(10, result);
  }

  @Test
  void decrementHTL_whenAtMaxAndProbabilisticDisabled_expectDecrement() throws Exception {
    setPrivateBooleanFalse(subsystem, "decrementAtMax");
    when(node.maxHTL()).thenReturn((short) 10);
    when(node.isDisableProbabilisticHTLs()).thenReturn(true);

    short result = subsystem.decrementHTL(null, (short) 10);

    assertEquals(9, result);
  }

  @Test
  void decrementHTL_whenAtMinAndProbabilisticEnabled_expectNoDecrement() throws Exception {
    setPrivateBooleanFalse(subsystem, "decrementAtMin");
    when(node.maxHTL()).thenReturn((short) 10);
    when(node.isDisableProbabilisticHTLs()).thenReturn(false);

    short result = subsystem.decrementHTL(null, (short) 1);

    assertEquals(1, result);
  }

  @Test
  void decrementHTL_whenAtMinAndProbabilisticDisabled_expectDecrement() throws Exception {
    setPrivateBooleanFalse(subsystem, "decrementAtMin");
    when(node.maxHTL()).thenReturn((short) 10);
    when(node.isDisableProbabilisticHTLs()).thenReturn(true);

    short result = subsystem.decrementHTL(null, (short) 1);

    assertEquals(0, result);
  }

  @Test
  void decrementHTL_whenIntermediate_expectDecrement() throws Exception {
    setPrivateBooleanFalse(subsystem, "decrementAtMax");
    setPrivateBooleanFalse(subsystem, "decrementAtMin");
    when(node.maxHTL()).thenReturn((short) 10);

    short result = subsystem.decrementHTL(null, (short) 3);

    assertEquals(2, result);
  }

  @Test
  void decrementHTL_whenNegative_expectZero() {
    when(node.maxHTL()).thenReturn((short) 10);
    short result = subsystem.decrementHTL(null, (short) -1);

    assertEquals(0, result);
  }

  @Test
  void makeRequestSender_whenLocalStoreHit_returnsKeyBlock() {
    NodeCHK key = mock(NodeCHK.class);
    RequestTag tag = mock(RequestTag.class);
    CHKBlock block = mock(CHKBlock.class);
    when(node.storage()).thenReturn(storage);
    when(storage.fetch(eq(key), eq(true), eq(true), eq(false), eq(true), eq(false), isNull()))
        .thenReturn(block);
    lenient().when(node.network()).thenReturn(network);
    lenient().when(network.darknetPortNumber()).thenReturn(1234);
    when(node.maxHTL()).thenReturn((short) 10);

    NodeRoutingSubsystem.RequestSenderOptions opts =
        NodeRoutingSubsystem.RequestSenderOptions.of(false, false, false, true, false, false);

    Object result = subsystem.makeRequestSender(key, (short) 5, 10L, tag, null, opts);

    assertEquals(block, result);
    verifyNoInteractions(tag);
  }

  @Test
  void makeRequestSender_whenIgnoreStoreAndLocalOnly_returnsNull() {
    NodeSSK key = mock(NodeSSK.class);
    RequestTag tag = mock(RequestTag.class);
    lenient().when(node.network()).thenReturn(network);
    lenient().when(network.darknetPortNumber()).thenReturn(1234);
    when(node.maxHTL()).thenReturn((short) 10);
    NodeRoutingSubsystem.RequestSenderOptions opts =
        NodeRoutingSubsystem.RequestSenderOptions.of(true, true, false, false, false, false);

    Object result = subsystem.makeRequestSender(key, (short) 5, 10L, tag, null, opts);

    assertNull(result);
    verifyNoInteractions(storage);
    verifyNoInteractions(tag);
  }

  @Test
  void makeRequestSender_whenHtlZero_returnsNull() {
    NodeSSK key = mock(NodeSSK.class);
    RequestTag tag = mock(RequestTag.class);
    lenient().when(node.network()).thenReturn(network);
    lenient().when(network.darknetPortNumber()).thenReturn(1234);
    when(node.maxHTL()).thenReturn((short) 10);
    NodeRoutingSubsystem.RequestSenderOptions opts =
        NodeRoutingSubsystem.RequestSenderOptions.of(false, true, false, false, false, false);

    Object result = subsystem.makeRequestSender(key, (short) 0, 10L, tag, null, opts);

    assertNull(result);
    verifyNoInteractions(storage);
    verifyNoInteractions(tag);
  }

  @Test
  void makeInsertSender_whenSskMissingPubKey_throws() {
    NodeSSK key = mock(NodeSSK.class);
    when(key.getPubKey()).thenReturn(null);
    SSKBlock block = mock(SSKBlock.class);
    when(block.getKey()).thenReturn(key);
    InsertTag tag = mock(InsertTag.class);

    NodeRoutingSubsystem.SskInsertOptions opts = NodeRoutingSubsystem.SskInsertOptions.of();

    assertThrows(
        IllegalArgumentException.class,
        () -> subsystem.makeInsertSender(block, (short) 5, 10L, tag, null, opts));
  }

  @Test
  void requestSenderOptions_of_retainsValues() {
    NodeRoutingSubsystem.RequestSenderOptions opts =
        NodeRoutingSubsystem.RequestSenderOptions.of(true, true, true, true, false, true);

    assertTrue(opts.localOnly());
    assertTrue(opts.ignoreStore());
    assertTrue(opts.offersOnly());
    assertTrue(opts.canReadClientCache());
    assertFalse(opts.canWriteClientCache());
    assertTrue(opts.realTimeFlag());
  }

  @Test
  void chkInsertOptions_withFlags_returnsNewInstanceWithUpdates() {
    byte[] headers = new byte[] {1, 2, 3};
    NodeRoutingSubsystem.ChkInsertOptions base =
        NodeRoutingSubsystem.ChkInsertOptions.of(headers, null);

    NodeRoutingSubsystem.ChkInsertOptions updated =
        base.withFromStore(true).withCanWriteClientCache(true).withRealTimeFlag(true);

    assertFalse(base.fromStore);
    assertFalse(base.canWriteClientCache);
    assertFalse(base.realTimeFlag);
    assertTrue(updated.fromStore);
    assertTrue(updated.canWriteClientCache);
    assertTrue(updated.realTimeFlag);
  }

  @Test
  void sskInsertOptions_withFlags_returnsNewInstanceWithUpdates() {
    NodeRoutingSubsystem.SskInsertOptions base = NodeRoutingSubsystem.SskInsertOptions.of();

    NodeRoutingSubsystem.SskInsertOptions updated =
        base.withFromStore(true).withCanWriteDatastore(true).withRealTimeFlag(true);

    assertFalse(base.fromStore);
    assertFalse(base.canWriteDatastore);
    assertFalse(base.realTimeFlag);
    assertTrue(updated.fromStore);
    assertTrue(updated.canWriteDatastore);
    assertTrue(updated.realTimeFlag);
  }

  private static void setPrivateBooleanFalse(NodeRoutingSubsystem target, String fieldName)
      throws Exception {
    Field field = NodeRoutingSubsystem.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.setBoolean(target, false);
  }

  private static boolean getPrivateBoolean(NodeRoutingSubsystem target, String fieldName)
      throws Exception {
    Field field = NodeRoutingSubsystem.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.getBoolean(target);
  }
}
