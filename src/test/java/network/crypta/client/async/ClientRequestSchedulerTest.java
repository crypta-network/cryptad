package network.crypta.client.async;

import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.ClientContextResources;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.IdentityHashSet;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100") // Intentional method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class ClientRequestSchedulerTest {

  @Mock private RandomSource random;
  @Mock private RequestStarter starter;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private DatastoreChecker datastoreChecker;

  private ClientContext context;

  @BeforeEach
  void setUp() {
    // Minimal, real ClientContext with mostly dummies to satisfy field access
    PriorityAwareExecutor mainExecutor = mock(PriorityAwareExecutor.class);
    Ticker ticker = mock(Ticker.class);
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);

    context =
        new ClientContext(
            1L,
            new ClientContextRuntime(
                jobRunner, mainExecutor, null, ticker, random, new Random(0L), null),
            new ClientContextStorageFactories(null, null, null, null, null, null, null),
            new ClientContextRafFactories(null, null),
            new ClientContextServices(
                new ClientContextResources(null, null), null, null, datastoreChecker, null, null),
            new ClientContextDefaults(null, null, null));

    when(core.getStoreChecker()).thenReturn(datastoreChecker);
  }

  private ClientRequestScheduler newScheduler(boolean forInserts) {
    return new ClientRequestScheduler(
        new ClientRequestScheduler.SchedulerMode(
            forInserts, /* forSSKs */ false, /* forRT */ false),
        random,
        starter,
        node,
        core,
        "test",
        context);
  }

  private static void setFinalField(Object target, String fieldName, Object value)
      throws Exception {
    Field f = target.getClass().getDeclaredField(fieldName);
    f.setAccessible(true);
    f.set(target, value);
  }

  @Test
  void getChoosenPriorityScheduler_defaultsToHard() {
    ClientRequestScheduler sched = newScheduler(false);
    assertEquals(ClientRequestScheduler.PRIORITY_HARD, sched.getChoosenPriorityScheduler());
  }

  @Test
  void setPriorityScheduler_whenSoft_changesBehaviorInGrabRequest() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    ChosenBlock chosen = mock(ChosenBlock.class);
    when(selector.chooseRequest(
            anyInt(),
            same(random),
            any(OfferedKeysList.class),
            same(starter),
            eq(false),
            same(context)))
        .thenReturn(chosen);

    sched.setPriorityScheduler(ClientRequestScheduler.PRIORITY_SOFT);
    ChosenBlock ret = sched.grabRequest();

    assertSame(chosen, ret);
    ArgumentCaptor<Integer> fuzzCap = ArgumentCaptor.forClass(Integer.class);
    verify(selector)
        .chooseRequest(
            fuzzCap.capture(),
            same(random),
            any(OfferedKeysList.class),
            same(starter),
            eq(false),
            same(context));
    assertEquals(-1, fuzzCap.getValue().intValue());
  }

  @Test
  void grabRequest_whenHardPriority_usesZeroFuzz() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    when(selector.chooseRequest(anyInt(), any(), any(), any(), anyBoolean(), any()))
        .thenReturn(null);

    sched.setPriorityScheduler(ClientRequestScheduler.PRIORITY_HARD);
    sched.grabRequest();

    ArgumentCaptor<Integer> fuzzCap = ArgumentCaptor.forClass(Integer.class);
    verify(selector)
        .chooseRequest(
            fuzzCap.capture(),
            same(random),
            any(OfferedKeysList.class),
            same(starter),
            eq(false),
            same(context));
    assertEquals(0, fuzzCap.getValue().intValue());
  }

  @Test
  void registerInsert_whenNotInsertScheduler_throws() {
    ClientRequestScheduler sched = newScheduler(false);
    SendableRequest req = mock(SendableRequest.class);
    assertThrows(IllegalArgumentException.class, () -> sched.registerInsert(req, false));
  }

  @Test
  void registerInsert_whenInsertScheduler_registersAndWakesStarter() throws Exception {
    ClientRequestScheduler sched = newScheduler(true);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableRequest req = mock(SendableRequest.class);
    doNothing().when(selector).innerRegister(same(req), same(context));

    sched.registerInsert(req, false);

    verify(selector).innerRegister(same(req), same(context));
    verify(starter).wakeUp();
  }

  @Test
  void register_whenInsertScheduler_throws() {
    ClientRequestScheduler sched = newScheduler(true);
    assertThrows(
        IllegalStateException.class,
        () -> sched.register(null, new SendableGet[] {}, false, null, true));
  }

  @Test
  void register_whenNoCheckStore_immediateFinishRegisterAndWakeUp() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableGet g1 = mock(SendableGet.class);
    SendableGet g2 = mock(SendableGet.class);

    // Any-valid should be true due to g1
    when(g1.isCancelled()).thenReturn(false);
    when(g1.getWakeupTime(same(context), anyLong())).thenReturn(0L);
    when(g1.preRegister(same(context), eq(true))).thenReturn(false);

    // Cancelled path calls preRegister(..., false) and does not register
    when(g2.isCancelled()).thenReturn(true);

    sched.register(null, new SendableGet[] {g1, g2}, false, null, true);

    verify(g1).preRegister(same(context), eq(true));
    verify(g2).preRegister(same(context), eq(false));
    verify(selector).innerRegister(same(g1), same(context));
    verifyNoMoreInteractions(selector);
    verify(starter).wakeUp();
  }

  @Test
  void finishRegister_persistent_registersOnlyWhenPreRegisterReturnsFalse() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableGet g1 = mock(SendableGet.class);
    when(g1.isCancelled()).thenReturn(false);
    when(g1.preRegister(same(context), eq(true))).thenReturn(false); // should register

    SendableGet g2 = mock(SendableGet.class);
    when(g2.isCancelled()).thenReturn(false);
    when(g2.preRegister(same(context), eq(true))).thenReturn(true); // skip registration

    sched.finishRegister(new SendableGet[] {g1, g2}, true, true);

    verify(selector).innerRegister(same(g1), same(context));
    verifyNoMoreInteractions(selector);
  }

  @Test
  void finishRegister_onInsertScheduler_throwsAndReportsInternalError() {
    ClientRequestScheduler sched = newScheduler(true);
    SendableGet g1 = mock(SendableGet.class);
    SendableGet g2 = mock(SendableGet.class);

    IllegalStateException ex =
        assertThrows(
            IllegalStateException.class,
            () -> sched.finishRegister(new SendableGet[] {g1, g2}, true, true));
    assertNotNull(ex);
    verify(g1)
        .internalError(any(IllegalStateException.class), same(sched), same(context), eq(true));
    verify(g2)
        .internalError(any(IllegalStateException.class), same(sched), same(context), eq(true));
  }

  @Test
  void removeRunningRequest_removesRequestAndClearsWakeup() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);

    SendableRequest req = mock(SendableRequest.class);

    Field f = ClientRequestScheduler.class.getDeclaredField("runningPersistentRequests");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    IdentityHashSet<SendableRequest> set = (IdentityHashSet<SendableRequest>) f.get(sched);
    set.add(req);

    assertTrue(sched.isRunningOrQueuedPersistentRequest(req));

    sched.removeRunningRequest(req);

    assertFalse(sched.isRunningOrQueuedPersistentRequest(req));
    verify(req).clearWakeupTime(same(context));
  }

  @Test
  void queueOfferedKey_wakesStarter() {
    ClientRequestScheduler sched = newScheduler(false);
    Key key = mock(Key.class);
    sched.queueOfferedKey(key, false);
    verify(starter).wakeUp();
  }

  @Test
  void countQueuedRequests_delegatesToSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    when(selector.countQueuedRequests(same(context))).thenReturn(42L);
    assertEquals(42L, sched.countQueuedRequests());
    verify(selector).countQueuedRequests(same(context));
  }

  @Test
  void fetchingKeys_returnsSelector() {
    ClientRequestScheduler sched = newScheduler(false);
    assertSame(sched.getSelector(), sched.fetchingKeys());
  }

  @Test
  void removeFetchingKey_delegatesToSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    Key key = mock(Key.class);
    sched.removeFetchingKey(key);
    verify(selector).removeFetchingKey(same(key));
  }

  @Test
  void removeRunningInsert_delegatesAndClearsWakeup() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableInsert insert = mock(SendableInsert.class);
    SendableRequestItemKey token = mock(SendableRequestItemKey.class);

    sched.removeRunningInsert(insert, token);

    verify(selector).removeRunningInsert(same(token));
    verify(insert).clearWakeupTime(same(context));
  }

  @Test
  void callFailure_get_nonPersistent_callsOnFailureDirectly() {
    ClientRequestScheduler sched = newScheduler(false);
    SendableGet get = mock(SendableGet.class);
    LowLevelGetException e =
        new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, "x", null);
    sched.callFailure(get, e, 1, false);
    verify(get).onFailure(same(e), isNull(), same(context));
  }

  @Test
  void callFailure_get_persistent_queuesJobRunner() {
    ClientRequestScheduler sched = newScheduler(false);
    SendableGet get = mock(SendableGet.class);
    LowLevelGetException e =
        new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, "x", null);
    sched.callFailure(get, e, 7, true);
    // Queued via context.jobRunner (ClientLayerPersister mock in context)
    try {
      verify(((ClientLayerPersister) context.jobRunner)).queue(any(PersistentJob.class), eq(7));
    } catch (PersistenceDisabledException ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  void callFailure_insert_nonPersistent_callsOnFailureDirectly() {
    ClientRequestScheduler sched = newScheduler(true);
    SendableInsert insert = mock(SendableInsert.class);
    LowLevelPutException e =
        new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, "x", null);
    sched.callFailure(insert, e, 3, false);
    verify(insert).onFailure(same(e), isNull(), same(context));
  }

  @Test
  void callFailure_insert_persistent_queuesJobRunner() {
    ClientRequestScheduler sched = newScheduler(true);
    SendableInsert insert = mock(SendableInsert.class);
    LowLevelPutException e =
        new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, "x", null);
    sched.callFailure(insert, e, 5, true);
    try {
      verify(((ClientLayerPersister) context.jobRunner)).queue(any(PersistentJob.class), eq(5));
    } catch (PersistenceDisabledException ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  void addToFetching_delegatesToSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    Key key = mock(Key.class);
    when(selector.addToFetching(same(key))).thenReturn(true);
    assertTrue(sched.addToFetching(key));
    verify(selector).addToFetching(same(key));
  }

  @Test
  void addRunningInsert_delegatesToSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(true);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableInsert insert = mock(SendableInsert.class);
    SendableRequestItemKey token = mock(SendableRequestItemKey.class);
    when(selector.addRunningInsert(same(token))).thenReturn(true);

    assertTrue(sched.addRunningInsert(insert, token));
    verify(selector).addRunningInsert(same(token));
  }

  @Test
  void hasFetchingKey_delegatesToSelectorWithNullWaiter() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    Key key = mock(Key.class);
    BaseSendableGet waiter = mock(BaseSendableGet.class);

    when(selector.hasKey(same(key), isNull())).thenReturn(true);
    assertTrue(sched.hasFetchingKey(key, waiter, false));
    verify(selector).hasKey(same(key), isNull());
  }

  @Test
  void countPersistentWaitingKeys_returnsZeroWhenCoreMissing_orDelegatesWhenPresent()
      throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    assertEquals(0L, sched.countPersistentWaitingKeys());

    KeyListenerTracker coreTracker = mock(KeyListenerTracker.class);
    when(coreTracker.countWaitingKeys()).thenReturn(123L);
    setFinalField(sched, "schedCore", coreTracker);
    assertEquals(123L, sched.countPersistentWaitingKeys());
  }

  @Test
  void isInsertScheduler_reflectsConstructorArg() {
    assertFalse(newScheduler(false).isInsertScheduler());
    assertTrue(newScheduler(true).isInsertScheduler());
  }

  @Test
  void wakeStarter_callsStarterWakeUp() {
    ClientRequestScheduler sched = newScheduler(false);
    sched.wakeStarter();
    verify(starter).wakeUp();
  }

  @Test
  void saltKey_usesCorrectSalterForPersistentOrTransient() {
    ClientRequestScheduler sched = newScheduler(false);
    Key key = mock(Key.class);
    when(key.getRoutingKey()).thenReturn(new byte[] {1, 2, 3});

    byte[] transientSalted = sched.schedTransient.saltKey(key);
    assertArrayEquals(transientSalted, sched.saltKey(false, key));

    // persistent path
    sched.startCore(new byte[] {9, 9, 9});
    KeySalter coreSalter = sched.getGlobalKeySalter(true);
    byte[] persistentSalted = coreSalter.saltKey(key);
    assertArrayEquals(persistentSalted, sched.saltKey(true, key));
  }

  @Test
  void getNode_returnsConstructorNode() {
    ClientRequestScheduler sched = newScheduler(false);
    assertSame(node, sched.getNode());
  }

  @Test
  void getGlobalKeySalter_returnsExpectedTracker() {
    ClientRequestScheduler sched = newScheduler(false);
    assertSame(sched.schedTransient, sched.getGlobalKeySalter(false));
    assertNull(sched.getGlobalKeySalter(true));
    // After startCore -> core salter
    sched.startCore(new byte[] {1});
    assertNotNull(sched.getGlobalKeySalter(true));
  }

  @Test
  void getSelector_returnsInternalSelector() {
    ClientRequestScheduler sched = newScheduler(false);
    assertSame(sched.getSelector(), sched.selector);
  }
}
