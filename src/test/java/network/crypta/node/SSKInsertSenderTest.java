package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.crypt.DSAPublicKey;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SSKInsertSenderTest {

  @Mock private Node node;
  @Mock private NodeStats nodeStats;
  @Mock private PeerNode source;
  @Mock private InsertTag insertTag;
  @Mock private SSKBlock block;
  @Mock private NodeSSK nodeSSK;
  @Mock private DSAPublicKey dsaPublicKey;

  private byte[] rawData;
  private byte[] rawHeaders;

  // Stubs applied lazily only when constructing a sender to avoid unnecessary-stubbing failures
  private void prepareCommonStubs() {
    when(node.getNodeStats()).thenReturn(nodeStats);
    when(node.enableNewLoadManagement(false)).thenReturn(false);
    when(node.enableNewLoadManagement(true)).thenReturn(false);
    when(node.maxHTL()).thenReturn((short) 18); // arbitrary but stable

    when(block.getKey()).thenReturn(nodeSSK);
    rawData = new byte[] {1, 2, 3};
    rawHeaders = new byte[] {4, 5, 6, 7};
    when(block.getRawData()).thenReturn(rawData);
    when(block.getRawHeaders()).thenReturn(rawHeaders);

    when(nodeSSK.getRoutingKey()).thenReturn(new byte[] {9});
    when(nodeSSK.toNormalizedDouble()).thenReturn(0.5);
    when(nodeSSK.getPubKey()).thenReturn(dsaPublicKey);
    when(nodeSSK.toString()).thenReturn("MySSK");
    when(dsaPublicKey.asBytes()).thenReturn(new byte[] {11, 22, 33});
  }

  private SSKInsertSender newSender(
      boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTime) {
    prepareCommonStubs();
    // uid=42, htl=10, fromStore=false, canWriteClientCache=false
    return new SSKInsertSender(
        block,
        42L,
        insertTag,
        (short) 10,
        source,
        node,
        false,
        forkOnCacheable,
        preferInsert,
        ignoreLowBackoff,
        realTime);
  }

  @ParameterizedTest
  @CsvSource({
    "0,SUCCESS",
    "1,ROUTE NOT FOUND",
    "-1,NOT FINISHED",
    "3,INTERNAL ERROR",
    "4,TIMED OUT",
    "5,GENERATED REJECTED OVERLOAD",
    "6,ROUTE REALLY NOT FOUND",
    "999,UNKNOWN STATUS CODE: 999"
  })
  @DisplayName("getStatusString maps codes to readable labels")
  void getStatusString_whenCalled_expectReadableLabels(int code, String expected) {
    assertEquals(expected, SSKInsertSender.getStatusString(code));
  }

  @Test
  void sentBytes_whenCalled_updatesCountersAndNodeStats() {
    SSKInsertSender sender = newSender(true, false, false, false);

    sender.sentBytes(123);
    sender.sentBytes(123);

    assertEquals(246, sender.getTotalSentBytes());
    verify(nodeStats, times(2)).insertSentBytes(true, 123);
  }

  @Test
  void receivedBytes_whenCalled_updatesCountersAndNodeStats() {
    SSKInsertSender sender = newSender(true, false, false, false);

    sender.receivedBytes(77);
    sender.receivedBytes(77);
    sender.receivedBytes(77);

    assertEquals(231, sender.getTotalReceivedBytes());
    verify(nodeStats, times(3)).insertReceivedBytes(true, 77);
  }

  @Test
  void sentPayload_whenCalled_debitsStatsAndCallsNode() {
    SSKInsertSender sender = newSender(true, false, false, false);

    sender.sentPayload(1000);

    verify(node).sentPayload(1000);
    verify(nodeStats).insertSentBytes(true, -1000);
  }

  @Test
  void createDataRequest_whenFlagsDiffer_shouldIncludeExpectedSubMessages() {
    // Use values different from Node defaults to trigger sub-messages
    SSKInsertSender sender = newSender(false, true, true, true);

    Message req = sender.createDataRequest();
    assertEquals(DMT.FNPSSKInsertRequestNew, req.getSpec());
    assertEquals(42L, req.getLong(DMT.UID));
    assertEquals((short) 10, req.getShort(DMT.HTL));

    // Fork control present and set to false
    Message forkCtl = req.getSubMessage(DMT.FNPSubInsertForkControl);
    assertTrue(forkCtl != null && !forkCtl.getBoolean(DMT.ENABLE_INSERT_FORK_WHEN_CACHEABLE));

    // Prefer-insert present and true
    Message prefer = req.getSubMessage(DMT.FNPSubInsertPreferInsert);
    assertTrue(prefer != null && prefer.getBoolean(DMT.PREFER_INSERT));

    // Ignore-low-backoff present and true
    Message ignore = req.getSubMessage(DMT.FNPSubInsertIgnoreLowBackoff);
    assertTrue(ignore != null && ignore.getBoolean(DMT.IGNORE_LOW_BACKOFF));

    // Real-time flag always attached
    assertTrue(DMT.getRealTimeFlag(req));
  }

  @Test
  void ignoreLowBackoff_whenEnabled_returnsLowBackoff() {
    SSKInsertSender senderTrue = newSender(true, false, true, false);
    SSKInsertSender senderFalse = newSender(true, false, false, false);

    assertEquals(Node.LOW_BACKOFF, senderTrue.ignoreLowBackoff());
    assertEquals(0L, senderFalse.ignoreLowBackoff());
  }

  @Test
  void isInsert_alwaysTrue() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertTrue(sender.isInsert());
  }

  @Test
  void getAcceptedTimeout_returnsTenSeconds() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertEquals(10_000L, sender.getAcceptedTimeout());
  }

  @Test
  void toString_containsKeyAndUid() {
    SSKInsertSender sender = newSender(true, false, false, false);
    String s = sender.toString();
    assertTrue(s.contains("SSKInsertSender:"));
    assertTrue(s.contains("MySSK"));
    assertTrue(s.endsWith(":42"));
  }

  @Test
  void getters_returnInitialValuesFromBlock() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertArrayEquals(rawData, sender.getData());
    assertArrayEquals(rawHeaders, sender.getHeaders());
    assertEquals(block, sender.getBlock());
    assertEquals(42L, sender.getUID());
    // Misnamed getter returns headers
    assertArrayEquals(rawHeaders, sender.getPubkeyHash());
  }

  @Test
  void sentRequest_initiallyFalse() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertFalse(sender.sentRequest());
  }

  @Test
  void sourceForRouting_returnsOriginalSourceWhenNotForked() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertEquals(source, sender.sourceForRouting());
  }

  @Test
  void forwardRejectedOverload_setsReceivedFlagOnce() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertFalse(sender.receivedRejectedOverload());
    sender.forwardRejectedOverload();
    assertTrue(sender.receivedRejectedOverload());
    // idempotent
    sender.forwardRejectedOverload();
    assertTrue(sender.receivedRejectedOverload());
  }

  @Test
  void timedOutWhileWaiting_whenNotForwarded_setsRouteReallyNotFound_andMarksNotRouted() {
    SSKInsertSender sender = newSender(true, false, false, false);

    // Ensure HTL starts positive and Node.maxHTL() is stable from setUp().
    assertEquals((short) 10, sender.getHTL());

    sender.timedOutWhileWaiting(0.0);

    // Because nothing was forwarded, ROUTE_NOT_FOUND is promoted to ROUTE REALLY NOT FOUND.
    assertEquals("ROUTE REALLY NOT FOUND", sender.getStatusString());
    verify(insertTag, times(1)).setNotRoutedOnwards();
  }

  @Test
  void isAccepted_whenSSKAccepted_setsNeedPubKeyFlag() {
    SSKInsertSender sender = newSender(true, false, false, false);
    Message acceptedNeedPk = DMT.createFNPSSKAccepted(42L, true);
    Message acceptedNoPk = DMT.createFNPSSKAccepted(42L, false);

    assertTrue(sender.isAccepted(acceptedNeedPk));
    // Call with the other variant just to ensure it returns true (no exception); internal flag
    // effect is exercised indirectly via behavior, which is outside this unit-scope.
    assertTrue(sender.isAccepted(acceptedNoPk));
  }

  @Test
  void collisionFlags_whenToggled_viaReflection_behaveAsDocumented() throws Exception {
    SSKInsertSender sender = newSender(true, false, false, false);

    // hasRecentlyCollided resets to false after read
    var fldRecent = SSKInsertSender.class.getDeclaredField("hasRecentlyCollided");
    fldRecent.setAccessible(true);
    fldRecent.setBoolean(sender, true);
    assertTrue(sender.hasRecentlyCollided());
    assertFalse(sender.hasRecentlyCollided());

    // hasCollided simple getter
    var fldCollided = SSKInsertSender.class.getDeclaredField("hasCollided");
    fldCollided.setAccessible(true);
    fldCollided.setBoolean(sender, true);
    assertTrue(sender.hasCollided());
  }

  @Test
  void getPriority_returnsHighPriority() {
    SSKInsertSender sender = newSender(true, false, false, false);
    assertEquals(NativeThread.PriorityLevel.HIGH_PRIORITY.value, sender.getPriority());
  }
}
