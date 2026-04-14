package network.crypta.clients.fcp;

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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubscribeUSKTest {

  private static final String TEST_USK =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";

  @Mock private FcpInsertRuntimeSupport runtimeSupport;
  @Mock private FCPConnectionHandler handler;
  @Mock private UskSubscriptionHandle subscriptionHandle;

  @Test
  void constructor_whenCreated_registersWithHandlerAndRuntimeSupport() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-sparse", false, true, (short) 5, (short) 4, true, true);
    when(runtimeSupport.subscribeUSK(eq(message), any(SubscribeUSKCallbacks.class), eq(handler)))
        .thenReturn(subscriptionHandle);

    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    verify(handler).addUSKSubscription("id-sparse", subscription);
    verify(runtimeSupport).subscribeUSK(message, subscription, handler);

    subscription.unsubscribe();

    verify(subscriptionHandle).unsubscribe();
  }

  @Test
  void onFoundEdition_whenHandlerOpen_sendsSubscribedUSKUpdate() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-open", true, false, (short) 3, (short) 1, false, false);
    when(runtimeSupport.subscribeUSK(eq(message), any(SubscribeUSKCallbacks.class), eq(handler)))
        .thenReturn(subscriptionHandle);
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    subscription.onFoundEdition(12L, message.key, true, false);

    ArgumentCaptor<SubscribedUSKUpdate> captor = ArgumentCaptor.forClass(SubscribedUSKUpdate.class);
    verify(handler).send(captor.capture());

    SubscribedUSKUpdate update = captor.getValue();
    assertEquals("id-open", update.requestIdentifier);
    assertEquals(12L, update.edition);
    assertSame(message.key, update.key);
    assertTrue(update.newKnownGood);
    assertFalse(update.newSlotToo);
  }

  @Test
  void getPollingPriorityMethods_whenCalled_returnValuesFromMessage() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-prio", true, false, (short) 9, (short) 2, false, false);
    when(runtimeSupport.subscribeUSK(eq(message), any(SubscribeUSKCallbacks.class), eq(handler)))
        .thenReturn(subscriptionHandle);

    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    assertEquals(9, subscription.getPollingPriorityNormal());
    assertEquals(2, subscription.getPollingPriorityProgress());
    assertEquals(9, subscription.pollingPriorityNormal());
    assertEquals(2, subscription.pollingPriorityProgress());
  }

  @Test
  void onSendingToNetwork_whenInvoked_sendsSendingToNetworkMessage() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-send", true, false, (short) 1, (short) 0, false, false);
    when(runtimeSupport.subscribeUSK(eq(message), any(SubscribeUSKCallbacks.class), eq(handler)))
        .thenReturn(subscriptionHandle);
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    subscription.onSendingToNetwork();

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
    when(runtimeSupport.subscribeUSK(eq(message), any(SubscribeUSKCallbacks.class), eq(handler)))
        .thenReturn(subscriptionHandle);
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    subscription.onRoundFinished();

    ArgumentCaptor<SubscribedUSKRoundFinishedMessage> captor =
        ArgumentCaptor.forClass(SubscribedUSKRoundFinishedMessage.class);
    verify(handler).send(captor.capture());

    SubscribedUSKRoundFinishedMessage finished = captor.getValue();
    assertEquals("id-round", finished.getFieldSet().get("Identifier"));
  }

  @Test
  void callbackSurface_whenQueried_reflectsCurrentSubscriptionState() throws Exception {
    SubscribeUSKMessage message =
        buildSubscribeUSKMessage("id-state", true, false, (short) 7, (short) 6, false, false);
    when(runtimeSupport.subscribeUSK(eq(message), any(SubscribeUSKCallbacks.class), eq(handler)))
        .thenReturn(subscriptionHandle);
    when(handler.isClosed()).thenReturn(true);
    SubscribeUSK subscription = new SubscribeUSK(message, runtimeSupport, handler);

    assertTrue(subscription.isClosed());
    assertEquals("id-state", subscription.clientIdentifier());
    verify(handler, never()).send(any());
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
