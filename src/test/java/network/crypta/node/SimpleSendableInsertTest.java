package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ChosenBlockImpl;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.KeyAndClientKey;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.SSKBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SimpleSendableInsertTest {

  @Mock private RequestClient requestClient;
  @Mock private ClientRequestScheduler insertScheduler;
  @Mock private RequestScheduler requestScheduler;
  @Mock private ClientContext clientContext;

  private CHKBlock chkBlock;
  private SSKBlock sskBlock;

  @BeforeEach
  void setUp() {
    chkBlock = mock(CHKBlock.class);
    sskBlock = mock(SSKBlock.class);
  }

  @Test
  void getPriorityClass_whenConstructed_returnsProvidedPriority() {
    short prio = 3;
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, prio, requestClient, insertScheduler);

    assertEquals(prio, insert.getPriorityClass());
  }

  @Test
  void schedule_whenCalled_registersInsert_andResetsFinished() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 2, requestClient, insertScheduler);
    // Mark finished first via cancel(); no parent array is registered, so unregister is a no-op.
    insert.cancel(clientContext);
    assertTrue(insert.isCancelled());

    insert.schedule();

    verify(insertScheduler, times(1)).registerInsert(insert, false);
    assertFalse(insert.isCancelled());
  }

  @Test
  void getSender_send_whenSuccess_callsRealPut_onSuccess_andRemovesRunningInsert()
      throws Exception {
    // Arrange
    SimpleSendableInsert real =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    SimpleSendableInsert insert = spy(real);

    NodeClientCore core = mock(NodeClientCore.class);
    NodeClientCoreTransfers transfers = mock(NodeClientCoreTransfers.class);
    when(core.getTransfers()).thenReturn(transfers);
    // Make realPut succeed (do nothing)
    doNothing()
        .when(transfers)
        .realPut(
            chkBlock,
            true,
            Node.FORK_ON_CACHEABLE_DEFAULT,
            Node.PREFER_INSERT_DEFAULT,
            Node.IGNORE_LOW_BACKOFF_DEFAULT,
            false);

    // Build a token and chosen block
    SendableRequestItemKey tokenKey = new SendableRequestItemKey() {};
    SendableRequestItem token =
        new SendableRequestItem() {
          @Override
          public void dump() {
            // No-op: this test stub never calls dump().
          }

          @Override
          public SendableRequestItemKey getKey() {
            return tokenKey;
          }
        };

    var chosen =
        new ChosenBlockImpl(
            insert,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(
                false,
                false,
                true, // canWriteClientCache propagated into realPut
                Node.FORK_ON_CACHEABLE_DEFAULT,
                false),
            requestScheduler,
            false);

    // Act
    boolean sent =
        insert.getSender(clientContext).send(core, requestScheduler, clientContext, chosen);

    // Assert
    assertTrue(sent);
    verify(transfers, times(1))
        .realPut(
            chkBlock,
            true,
            Node.FORK_ON_CACHEABLE_DEFAULT,
            Node.PREFER_INSERT_DEFAULT,
            Node.IGNORE_LOW_BACKOFF_DEFAULT,
            false);
    verify(insert, times(1)).onSuccess(token, null, clientContext);
    verify(requestScheduler, times(1)).removeRunningInsert(insert, tokenKey);
    assertTrue(insert.isCancelled());
    assertTrue(insert.isEmpty());
    verifyNoMoreInteractions(requestScheduler);
  }

  @Test
  void getSender_send_whenRealPutThrows_callsOnFailure_setsFinished_andSkipsRemove()
      throws Exception {
    // Arrange
    SimpleSendableInsert real =
        new SimpleSendableInsert(sskBlock, (short) 2, requestClient, insertScheduler);
    SimpleSendableInsert insert = spy(real);

    NodeClientCore core = mock(NodeClientCore.class);
    NodeClientCoreTransfers transfers = mock(NodeClientCoreTransfers.class);
    when(core.getTransfers()).thenReturn(transfers);
    doThrow(new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD))
        .when(transfers)
        .realPut(
            eq(sskBlock),
            any(Boolean.class),
            eq(Node.FORK_ON_CACHEABLE_DEFAULT),
            eq(Node.PREFER_INSERT_DEFAULT),
            eq(Node.IGNORE_LOW_BACKOFF_DEFAULT),
            eq(false));

    SendableRequestItemKey tokenKey = new SendableRequestItemKey() {};
    SendableRequestItem token =
        new SendableRequestItem() {
          @Override
          public void dump() {
            // No-op: this test stub never calls dump().
          }

          @Override
          public SendableRequestItemKey getKey() {
            return tokenKey;
          }
        };

    var chosen =
        new ChosenBlockImpl(
            insert,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(false, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, false),
            requestScheduler,
            false);

    // Act
    boolean sent =
        insert.getSender(clientContext).send(core, requestScheduler, clientContext, chosen);

    // Assert
    assertTrue(sent);
    verify(insert, times(1))
        .onFailure(any(LowLevelPutException.class), eq(token), eq(clientContext));
    // removeRunningInsert() is not called on failure in this sender path
    verifyNoInteractions(insertScheduler);
    verifyNoMoreInteractions(requestScheduler);
    assertTrue(insert.isCancelled());
    assertTrue(insert.isEmpty());
  }

  @Test
  void chooseKey_whenAlreadyInFlight_returnsNull() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);

    KeysFetchingLocally keys = mock(KeysFetchingLocally.class);
    when(keys.hasInsert(any())).thenReturn(true);

    assertNull(insert.chooseKey(keys, clientContext));
  }

  @Test
  void chooseKey_whenFinished_returnsNull() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    insert.cancel(clientContext);

    KeysFetchingLocally keys = mock(KeysFetchingLocally.class);
    when(keys.hasInsert(any())).thenReturn(false);

    assertNull(insert.chooseKey(keys, clientContext));
  }

  @Test
  void chooseKey_whenEligible_returnsItemAndStableKey() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(sskBlock, (short) 5, requestClient, insertScheduler);

    KeysFetchingLocally keys = mock(KeysFetchingLocally.class);
    when(keys.hasInsert(any())).thenReturn(false);

    SendableRequestItem a = insert.chooseKey(keys, clientContext);
    SendableRequestItem b = insert.chooseKey(keys, clientContext);
    assertNotNull(a);
    assertNotNull(b);
    // Identity should differ, equality should be based on the parent; hashCode should match.
    assertNotSame(a, b);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertSame(a, a.getKey());
  }

  @Test
  void getWakeupTime_whenEmpty_returnsMinusOne() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    insert.cancel(clientContext);

    long wake = insert.getWakeupTime(clientContext, 0L);
    assertEquals(-1L, wake);
  }

  @Test
  void getWakeupTime_whenRunningSameToken_returnsLongMax() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    // Not finished

    KeysFetchingLocally keys = mock(KeysFetchingLocally.class);
    when(keys.hasInsert(any())).thenReturn(true);
    when(insertScheduler.fetchingKeys()).thenReturn(keys);

    long wake = insert.getWakeupTime(clientContext, 0L);
    assertEquals(Long.MAX_VALUE, wake);
  }

  @Test
  void getWakeupTime_whenReady_returnsZero() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(sskBlock, (short) 4, requestClient, insertScheduler);

    KeysFetchingLocally keys = mock(KeysFetchingLocally.class);
    when(keys.hasInsert(any())).thenReturn(false);
    when(insertScheduler.fetchingKeys()).thenReturn(keys);

    long wake = insert.getWakeupTime(clientContext, 0L);
    assertEquals(0L, wake);
  }

  @Test
  void isSSK_whenBlockTypeVaries_reportsAccurately() {
    SimpleSendableInsert chkInsert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    SimpleSendableInsert sskInsert =
        new SimpleSendableInsert(sskBlock, (short) 1, requestClient, insertScheduler);
    assertFalse(chkInsert.isSSK());
    assertTrue(sskInsert.isSSK());
  }

  @Test
  void cacheAndForkFlags_matchDefaults() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    assertFalse(insert.canWriteClientCache());
    assertFalse(insert.localRequestOnly());
    assertEquals(Node.FORK_ON_CACHEABLE_DEFAULT, insert.forkOnCacheable());
  }

  @Test
  void countKeys_whenFinishedAndNotFinished_reflectsState() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(sskBlock, (short) 1, requestClient, insertScheduler);
    assertEquals(1L, insert.countAllKeys(clientContext));
    assertEquals(1L, insert.countSendableKeys(clientContext));

    insert.cancel(clientContext);
    assertEquals(0L, insert.countAllKeys(clientContext));
    assertEquals(0L, insert.countSendableKeys(clientContext));
  }

  @Test
  void basicAccessors_returnExpectedValues() {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 7, requestClient, insertScheduler);
    assertEquals(requestClient, insert.getClient());
    assertNull(insert.getClientRequest());
    assertNull(insert.getSchedulerGroup());
  }

  @Test
  void ctor_withUnknownBlockType_throwsIllegalArgumentException() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(core.getNode()).thenReturn(node);
    when(node.getNonPersistentClientBulk()).thenReturn(requestClient);

    KeyBlock unknown = mock(KeyBlock.class); // not CHK or SSK

    assertThrows(
        IllegalArgumentException.class, () -> new SimpleSendableInsert(core, unknown, (short) 1));
  }

  @Test
  void innerOnResume_doesNothing_andDoesNotThrow() throws Exception {
    SimpleSendableInsert insert =
        new SimpleSendableInsert(chkBlock, (short) 1, requestClient, insertScheduler);
    // Do not expect any exception from innerOnResume via public onResume.
    insert.onResume(clientContext);
    assertEquals(1L, insert.countSendableKeys(clientContext));
  }
}
