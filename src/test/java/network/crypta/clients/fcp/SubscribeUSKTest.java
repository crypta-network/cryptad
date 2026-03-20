package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKFoundEditionPayload;
import network.crypta.client.async.USKFoundEditionProgress;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.USKSparseProxyCallback;
import network.crypta.keys.USK;
import network.crypta.node.RequestClient;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubscribeUSKTest {

  private static final String TEST_USK =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";

  @Mock private FcpInsertRuntimeSupport runtimeSupport;
  @Mock private USKManager uskManager;
  @Mock private FCPConnectionHandler handler;
  @Mock private PersistentRequestClient persistentRequestClient;
  @Mock private RequestClient requestClient;
  @Mock private USKSparseProxyCallback sparseProxyCallback;
  @Mock private ClientContext clientContext;

  @Test
  void constructor_whenSparsePollRequested_usesSubscribeSparseAndStoresProxyForUnsubscribe()
      throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-sparse", false, true, (short) 5, (short) 4, true, true);
    mockCommonBehavior();
    when(uskManager.subscribeSparse(eq(message.key), any(), eq(true), eq(requestClient)))
        .thenReturn(sparseProxyCallback);

    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    verify(handler).addUSKSubscription("id-sparse", subscription);
    verify(persistentRequestClient).lowLevelClient(true);
    verify(uskManager).subscribeSparse(message.key, subscription, true, requestClient);
    verify(uskManager, never()).subscribe(any(USK.class), any(), anyBoolean(), anyBoolean(), any());

    subscription.unsubscribe();

    verify(uskManager).unsubscribe(message.key, sparseProxyCallback);
  }

  @Test
  void constructor_whenBackgroundPollingEnabled_subscribesWithPollingAndUsesSelfForUnsubscribe()
      throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-poll", false, false, (short) 6, (short) 5, false, false);
    mockCommonBehavior();

    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    verify(handler).addUSKSubscription("id-poll", subscription);
    verify(persistentRequestClient).lowLevelClient(false);
    verify(uskManager).subscribe(message.key, subscription, true, false, requestClient);
    verify(uskManager, never())
        .subscribeSparse(eq(message.key), eq(subscription), anyBoolean(), eq(requestClient));

    subscription.unsubscribe();

    verify(uskManager).unsubscribe(message.key, subscription);
  }

  @Test
  void onFoundEdition_whenHandlerClosed_unsubscribesWithoutSending() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-closed", true, false, (short) 2, (short) 1, false, false);
    mockCommonBehavior();
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);
    when(handler.isClosed()).thenReturn(true);

    subscription.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(7L, message.key, false, (short) 1, new byte[0]),
            clientContext,
            new USKFoundEditionProgress(true, false)));

    verify(uskManager).unsubscribe(message.key, subscription);
    verify(handler, never()).send(any());
  }

  @Test
  void onFoundEdition_whenHandlerOpen_sendsSubscribedUSKUpdate() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-open", true, false, (short) 3, (short) 1, false, false);
    mockCommonBehavior();
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);
    when(handler.isClosed()).thenReturn(false);

    subscription.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(12L, message.key, false, (short) 1, null),
            clientContext,
            new USKFoundEditionProgress(true, false)));

    ArgumentCaptor<SubscribedUSKUpdate> captor = ArgumentCaptor.forClass(SubscribedUSKUpdate.class);
    verify(handler).send(captor.capture());

    SubscribedUSKUpdate update = captor.getValue();
    assertEquals("id-open", update.requestIdentifier);
    assertEquals(12L, update.edition);
    assertSame(message.key, update.key);
    assertTrue(update.newKnownGood);
    assertFalse(update.newSlotToo);

    verify(uskManager, never()).unsubscribe(any(), any());
  }

  @Test
  void getPollingPriorityMethods_whenCalled_returnValuesFromMessage() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-prio", true, false, (short) 9, (short) 2, false, false);
    mockCommonBehavior();

    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    assertEquals(9, subscription.getPollingPriorityNormal());
    assertEquals(2, subscription.getPollingPriorityProgress());
  }

  @Test
  void onSendingToNetwork_whenInvoked_sendsSendingToNetworkMessage() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-send", true, false, (short) 1, (short) 0, false, false);
    mockCommonBehavior();
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    subscription.onSendingToNetwork(clientContext);

    ArgumentCaptor<SubscribedUSKSendingToNetworkMessage> captor =
        ArgumentCaptor.forClass(SubscribedUSKSendingToNetworkMessage.class);
    verify(handler).send(captor.capture());

    SubscribedUSKSendingToNetworkMessage sending = captor.getValue();
    assertEquals("id-send", sending.messageIdentifier);
  }

  @Test
  void onRoundFinished_whenInvoked_sendsRoundFinishedMessage() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-round", true, false, (short) 1, (short) 0, false, false);
    mockCommonBehavior();
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    subscription.onRoundFinished(clientContext);

    ArgumentCaptor<SubscribedUSKRoundFinishedMessage> captor =
        ArgumentCaptor.forClass(SubscribedUSKRoundFinishedMessage.class);
    verify(handler).send(captor.capture());

    SubscribedUSKRoundFinishedMessage finished = captor.getValue();
    assertEquals("id-round", finished.getFieldSet().get("Identifier"));
  }

  private void mockCommonBehavior() {
    when(runtimeSupport.uskManager()).thenReturn(uskManager);
    when(handler.getRebootClient()).thenReturn(persistentRequestClient);
    when(persistentRequestClient.lowLevelClient(anyBoolean())).thenReturn(requestClient);
    lenient().when(requestClient.persistent()).thenReturn(false);
  }

  private SubscribeUSKMessage buildSubscribeUSKMessage(
      String identifier,
      boolean dontPoll,
      boolean sparsePoll,
      short prio,
      short prioProgress,
      boolean realTimeFlag,
      boolean ignoreUSKDatehints)
      throws MessageInvalidException {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", identifier);
    fieldSet.putSingle("URI", TEST_USK);
    fieldSet.put("DontPoll", dontPoll);
    if (!dontPoll) {
      fieldSet.put("SparsePoll", sparsePoll);
    }
    fieldSet.put("PriorityClass", prio);
    fieldSet.put("PriorityClassProgress", prioProgress);
    fieldSet.put("RealTimeFlag", realTimeFlag);
    fieldSet.put("IgnoreUSKDatehints", ignoreUSKDatehints);
    return new SubscribeUSKMessage(fieldSet);
  }
}
