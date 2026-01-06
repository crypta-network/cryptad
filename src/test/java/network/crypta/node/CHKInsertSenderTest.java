package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class CHKInsertSenderTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeStats nodeStats;
  @Mock private PeerNode sourcePeer;
  @Mock private InsertTag insertTag;
  @Mock private PartiallyReceivedBlock prb;

  private NodeCHK key;
  private long uid;
  private short htl;
  private byte[] headers;

  @BeforeEach
  void setUp() {
    // Stable CHK routing key (32 bytes) and algorithm
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    for (int i = 0; i < rk.length; i++) rk[i] = (byte) (i + 1);
    key = new NodeCHK(rk, Key.ALGO_AES_PCFB_256_SHA256);

    uid = 123456789L;
    htl = (short) 10;
    headers = new byte[] {1, 2, 3, 4};

    // Minimal Node stubbing used by BaseSender/CHKInsertSender
    when(node.network().enableNewLoadManagement(anyBoolean())).thenReturn(false);
    when(node.maxHTL()).thenReturn((short) 18);
    when(node.network().stats()).thenReturn(nodeStats);
  }

  private CHKInsertSender newSender(
      boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realtime) {
    return new CHKInsertSender(
        key,
        uid,
        insertTag,
        headers,
        htl,
        sourcePeer,
        node,
        prb,
        /* fromStore= */ false,
        forkOnCacheable,
        preferInsert,
        ignoreLowBackoff,
        realtime);
  }

  @Test
  @DisplayName("createDataRequest_whenFlagsDeviate_addsExpectedSubmessagesAndFields")
  void createDataRequest_whenFlagsDeviate_addsExpectedSubmessagesAndFields() {
    // Arrange: force all flags to deviate from Node defaults
    boolean forkOnCacheable = !Node.FORK_ON_CACHEABLE_DEFAULT; // false
    boolean preferInsert = !Node.PREFER_INSERT_DEFAULT; // true
    boolean ignoreLowBackoff = !Node.IGNORE_LOW_BACKOFF_DEFAULT; // true
    boolean realtime = true;
    CHKInsertSender sender = newSender(forkOnCacheable, preferInsert, ignoreLowBackoff, realtime);

    // Act
    Message m = sender.createDataRequest();

    // Assert: top-level type and core fields
    assertEquals(DMT.FNPInsertRequest, m.getSpec());
    assertEquals(uid, m.getLong(DMT.UID));
    assertEquals(htl, m.getShort(DMT.HTL));
    assertEquals(key, m.getFromPayload(DMT.FREENET_ROUTING_KEY));

    // RealTime flag is always present and mirrors the mode
    Message rt = m.getSubMessage(DMT.FNPRealTimeFlag);
    assertNotNull(rt);
    assertTrue(rt.getBoolean(DMT.REAL_TIME_FLAG));

    // When flags differ from defaults, corresponding submessages must be present
    assertNotNull(m.getSubMessage(DMT.FNPSubInsertForkControl));
    assertNotNull(m.getSubMessage(DMT.FNPSubInsertPreferInsert));
    assertNotNull(m.getSubMessage(DMT.FNPSubInsertIgnoreLowBackoff));
  }

  @Test
  @DisplayName("createDataRequest_whenDefaultsOnly_includesOnlyRealtimeSubmessage")
  void createDataRequest_whenDefaultsOnly_includesOnlyRealtimeSubmessage() {
    // Arrange: use Node defaults exactly
    CHKInsertSender sender =
        newSender(
            Node.FORK_ON_CACHEABLE_DEFAULT,
            Node.PREFER_INSERT_DEFAULT,
            Node.IGNORE_LOW_BACKOFF_DEFAULT,
            /* realtime= */ false);

    // Act
    Message m = sender.createDataRequest();

    // Assert
    assertEquals(DMT.FNPInsertRequest, m.getSpec());
    // Only realtime submessage expected
    assertNotNull(m.getSubMessage(DMT.FNPRealTimeFlag));
    assertFalse(m.getSubMessage(DMT.FNPRealTimeFlag).getBoolean(DMT.REAL_TIME_FLAG));
    assertNull(m.getSubMessage(DMT.FNPSubInsertForkControl));
    assertNull(m.getSubMessage(DMT.FNPSubInsertPreferInsert));
    assertNull(m.getSubMessage(DMT.FNPSubInsertIgnoreLowBackoff));
  }

  @Test
  @DisplayName("getAcceptedTimeout_returnsConfiguredConstant")
  void getAcceptedTimeout_returnsConfiguredConstant() {
    CHKInsertSender sender = newSender(true, false, false, true);
    assertEquals(CHKInsertSender.ACCEPTED_TIMEOUT, sender.getAcceptedTimeout());
  }

  @Test
  @DisplayName("ignoreLowBackoff_whenEnabled_returnsConfiguredThreshold")
  void ignoreLowBackoff_whenEnabled_returnsConfiguredThreshold() {
    CHKInsertSender enabled = newSender(true, false, true, false);
    assertEquals(Node.LOW_BACKOFF, enabled.ignoreLowBackoff());

    CHKInsertSender disabled = newSender(true, false, false, false);
    assertEquals(0L, disabled.ignoreLowBackoff());
  }

  @Test
  @DisplayName("isInsert_alwaysTrueForCHKInsertSender")
  void isInsert_alwaysTrueForCHKInsertSender() {
    CHKInsertSender sender = newSender(true, false, false, true);
    assertTrue(sender.isInsert());
  }

  @Test
  @DisplayName("priority_isHigh")
  void priority_isHigh() {
    CHKInsertSender sender = newSender(true, false, false, true);
    assertEquals(NativeThread.PriorityLevel.HIGH_PRIORITY.value, sender.getPriority());
  }

  @Test
  @DisplayName("headersAndUid_accessors_returnValuesProvidedToConstructor")
  void headersAndUid_accessors_returnValuesProvidedToConstructor() {
    CHKInsertSender sender = newSender(true, false, false, true);
    assertArrayEquals(headers, sender.getHeaders());
    assertArrayEquals(headers, sender.getPubkeyHash());
    assertEquals(uid, sender.getUID());
  }

  @Test
  @DisplayName("routedTo_initiallyEmpty")
  void routedTo_initiallyEmpty() {
    CHKInsertSender sender = newSender(true, false, false, true);
    assertEquals(0, sender.getRoutedTo().length);
  }

  @Test
  @DisplayName("byteCounters_updateTotals_and_delegateToNodeStats")
  void byteCounters_updateTotals_and_delegateToNodeStats() {
    CHKInsertSender sender = newSender(true, false, false, true);

    sender.sentBytes(100);
    sender.receivedBytes(50);
    sender.sentPayload(20);

    assertEquals(100, sender.getTotalSentBytes());
    assertEquals(50, sender.getTotalReceivedBytes());

    verify(nodeStats).insertSentBytes(false, 100);
    verify(nodeStats).insertReceivedBytes(false, 50);
    verify(nodeStats).insertSentBytes(false, -20);
    verify(node).sentPayload(20);
  }

  @Test
  @DisplayName("receiveFailed_flow_setsFlags_status_and_unblocksWaiters")
  void receiveFailed_flow_setsFlags_status_and_unblocksWaiters() {
    CHKInsertSender sender = newSender(true, false, false, true);

    // Before failure
    assertFalse(sender.failedReceive());
    assertFalse(sender.completed());
    assertFalse(sender.failIfReceiveFailed(null, null));
    verifyNoInteractions(sourcePeer); // no routing-unlock without args and before failure

    // Signal receive failure
    sender.onReceiveFailed();

    // After failure
    assertTrue(sender.failedReceive());
    assertTrue(sender.completed());
    assertTrue(sender.failIfReceiveFailed(insertTag, sourcePeer));
    // When tag and peer are supplied, we must unlock routing on the peer
    verify(sourcePeer).noLongerRoutingTo(insertTag, false);
    assertEquals(CHKInsertSender.RECEIVE_FAILED, sender.getStatus());
  }
}
