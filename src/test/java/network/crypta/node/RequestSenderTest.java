package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem.RequestSenderOptions;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming style: method_whenCondition_expectOutcome
class RequestSenderTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  private static byte[] bytes(int size, int seed) {
    byte[] b = new byte[size];
    for (int i = 0; i < size; i++) b[i] = (byte) ((i + seed) & 0xFF);
    return b;
  }

  private RequestSender newChkSender(boolean realtime, long uid, short htl) {
    // 32‑byte routing key; content doesn't matter for these tests
    NodeCHK key = new NodeCHK(bytes(NodeCHK.KEY_LENGTH, 1), (byte) 1);
    when(node.maxHTL()).thenReturn((short) 18);
    when(node.network().enableNewLoadManagement(realtime)).thenReturn(false);
    RequestSenderContext context =
        new RequestSenderContext(key, null, htl, uid, mock(RequestTag.class), node, null);
    RequestSenderOptions options =
        RequestSenderOptions.of(false, false, false, false, true, realtime);
    return new RequestSender(context, options, true);
  }

  private RequestSender newSskSender(boolean realtime, long uid, short htl, DSAPublicKey pubKey) {
    // 32‑byte E(H(docname)) and 32‑byte pubKeyHash
    byte[] ehd = bytes(NodeSSK.E_H_DOCNAME_SIZE, 2);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 3);
    NodeSSK key = new NodeSSK(pkh, ehd, (byte) 1);
    when(node.maxHTL()).thenReturn((short) 18);
    when(node.network().enableNewLoadManagement(realtime)).thenReturn(false);
    RequestSenderContext context =
        new RequestSenderContext(key, pubKey, htl, uid, mock(RequestTag.class), node, null);
    RequestSenderOptions options =
        RequestSenderOptions.of(false, false, false, false, true, realtime);
    return new RequestSender(context, options, true);
  }

  private void createSenderWithNullKey() {
    RequestSenderContext context =
        new RequestSenderContext(null, null, (short) 5, 99L, mock(RequestTag.class), node, null);
    RequestSenderOptions options = RequestSenderOptions.of(false, false, false, false, true, false);
    new RequestSender(context, options, true);
  }

  @ParameterizedTest
  @CsvSource({
    RequestSender.NOT_FINISHED + ",NOT FINISHED",
    RequestSender.SUCCESS + ",SUCCESS",
    RequestSender.ROUTE_NOT_FOUND + ",ROUTE NOT FOUND",
    RequestSender.DATA_NOT_FOUND + ",DATA NOT FOUND",
    RequestSender.TRANSFER_FAILED + ",TRANSFER FAILED",
    RequestSender.VERIFY_FAILURE + ",VERIFY FAILURE",
    RequestSender.TIMED_OUT + ",TIMED OUT",
    RequestSender.GENERATED_REJECTED_OVERLOAD + ",GENERATED REJECTED OVERLOAD",
    RequestSender.INTERNAL_ERROR + ",INTERNAL ERROR",
    RequestSender.RECENTLY_FAILED + ",RECENTLY FAILED",
    RequestSender.GET_OFFER_VERIFY_FAILURE + ",GET OFFER VERIFY FAILURE",
    RequestSender.GET_OFFER_TRANSFER_FAILED + ",GET OFFER TRANSFER FAILED"
  })
  void getStatusString_forKnownCodes_returnsLabel(int code, String expected) {
    assertEquals(expected, RequestSender.getStatusString(code));
  }

  @Test
  void getStatusString_whenUnknownCode_returnsFallback() {
    String s = RequestSender.getStatusString(9999);
    assertTrue(s.startsWith("UNKNOWN STATUS CODE: "));
    assertTrue(s.endsWith("9999"));
  }

  @Test
  @DisplayName("createDataRequest (CHK): type and realtime flag set")
  void createDataRequest_whenChk_setsTypeAndRealtimeFlag() {
    long uid = 42L;
    short htl = 10;
    boolean realtime = true;
    RequestSender sender = newChkSender(realtime, uid, htl);

    Message m = sender.createDataRequest();

    assertEquals(DMT.FNPCHKDataRequest, m.getSpec());
    assertTrue(DMT.getRealTimeFlag(m));
    assertEquals(uid, m.getLong(DMT.UID));
    assertEquals(htl, m.getShort(DMT.HTL));
  }

  @Test
  @DisplayName("createDataRequest (SSK, pubKey missing): NEED_PUB_KEY=true and realtime flag set")
  void createDataRequest_whenSskAndPubKeyMissing_setsNeedPubKeyTrue() {
    long uid = 77L;
    short htl = 7;
    boolean realtime = false; // bulk
    RequestSender sender = newSskSender(realtime, uid, htl, /*pubKey*/ null);

    Message m = sender.createDataRequest();

    assertEquals(DMT.FNPSSKDataRequest, m.getSpec());
    assertEquals(uid, m.getLong(DMT.UID));
    assertEquals(htl, m.getShort(DMT.HTL));
    // pubKey missing => request it
    assertTrue(m.getBoolean(DMT.NEED_PUB_KEY));
    // sub-message present, value reflects mode (bulk=false)
    assertFalse(DMT.getRealTimeFlag(m));
  }

  @Test
  @DisplayName("createDataRequest (SSK, pubKey present): NEED_PUB_KEY=false")
  void createDataRequest_whenSskAndPubKeyPresent_setsNeedPubKeyFalse() {
    DSAPublicKey pk = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.TWO);
    RequestSender sender = newSskSender(true, 5L, (short) 3, pk);

    Message m = sender.createDataRequest();
    assertEquals(DMT.FNPSSKDataRequest, m.getSpec());
    assertFalse(m.getBoolean(DMT.NEED_PUB_KEY));
    assertTrue(DMT.getRealTimeFlag(m));
  }

  @Test
  void start_enqueuesTaskWithDescriptiveLabel() {
    long uid = 1234L;
    short htl = 12;
    RequestSender sender = newChkSender(true, uid, htl);

    PriorityAwareExecutor exec = mock(PriorityAwareExecutor.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(exec);
    when(network.darknetPortNumber()).thenReturn(31337);

    sender.start();

    verify(exec, times(1)).execute(sender, "RequestSender for UID " + uid + " on 31337");
  }

  @Test
  void getPriority_returnsHighPriorityLevelValue() {
    RequestSender sender = newChkSender(true, 1L, (short) 5);
    assertEquals(
        network.crypta.support.io.NativeThread.PriorityLevel.HIGH_PRIORITY.value,
        sender.getPriority());
  }

  @Test
  void transferCoalesced_setterGetter_roundTrips() {
    RequestSender sender = newChkSender(false, 9L, (short) 6);
    assertFalse(sender.isTransferCoalesced());
    sender.setTransferCoalesced();
    assertTrue(sender.isTransferCoalesced());
  }

  @Test
  void fetchTimeout_matchesBaseSenderCalculation() {
    boolean realtime = true;
    short htl = 8;
    when(node.maxHTL()).thenReturn((short) 18);
    when(node.network().enableNewLoadManagement(realtime)).thenReturn(false);
    RequestSender sender = newChkSender(realtime, 11L, htl);

    int expected = BaseSender.calculateTimeout(realtime, htl, node);
    assertEquals(expected, sender.fetchTimeout());
  }

  @Test
  void getAcceptedTimeout_returnsConstantTenSeconds() {
    RequestSender sender = newChkSender(true, 2L, (short) 4);
    assertEquals(10_000L, sender.getAcceptedTimeout());
  }

  @Test
  void toString_appendsUidSuffix() {
    long uid = 4242L;
    RequestSender sender = newChkSender(false, uid, (short) 5);
    String s = sender.toString();
    assertNotNull(s);
    assertTrue(s.endsWith(" for " + uid));
  }

  @Test
  void constructor_whenKeyIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, this::createSenderWithNullKey);
  }
}
