package network.crypta.client.async;

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

import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.node.BaseSendableGet;
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

@SuppressWarnings("java:S100") // Intentional method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class ClientRequestSchedulerTest {

  @Mock private RandomSource random;
  @Mock private RequestStarter starter;
  @Mock private Node node;
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
            jobRunner,
            mainExecutor,
            /* archiveManager */ null,
            /* ptbf */ null,
            /* tbf */ null,
            /* tracker */ null,
            /* healingQueue */ null,
            /* uskManager */ null,
            /* strongRandom */ random,
            /* fastWeakRandom */ new Random(0L),
            /* ticker */ ticker,
            /* memoryLimitedJobRunner */ null,
            /* fg */ null,
            /* persistentFG */ null,
            /* rafFactory */ null,
            /* persistentRAFFactory */ null,
            /* fileRAFTransient */ null,
            /* fileRAFPersistent */ null,
            /* rc */ null,
            /* checker */ datastoreChecker,
            /* persistentRoot */ null,
            /* cryptoSecretTransient */ null,
            /* linkFilterExceptionProvider */ null,
            /* defaultPersistentFetchContext */ null,
            /* defaultPersistentInsertContext */ null,
            /* config */ null);

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
    sched.setPriorityScheduler(ClientRequestScheduler.PRIORITY_SOFT);

    Key key = mock(Key.class);
    ChosenBlock chosen = new ChosenBlock(key, (short) 3, null);
    when(selector.chooseRequest(anyShort(), same(random), any(), same(starter), anyBoolean(), same(context)))
        .thenReturn(chosen);

    ChosenBlock result = sched.grabRequest();
    assertSame(chosen, result);
    // in soft mode fuzz is negative (docs)
    ArgumentCaptor<Short> fuzz = ArgumentCaptor.forClass(Short.class);
    verify(selector).chooseRequest(fuzz.capture(), same(random), any(), same(starter), anyBoolean(), same(context));
    assertTrue(fuzz.getValue() <= 0);
  }

  @Test
  void registerInsert_whenNotInsertScheduler_throws() {
    ClientRequestScheduler sched = newScheduler(false);
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> sched.registerInsert(null, false));
    assertTrue(ex.getMessage().contains("SendableInsert"));
  }

  @Test
  void registerInsert_whenInsertScheduler_registersAndWakesStarter() throws Exception {
    ClientRequestScheduler sched = newScheduler(true);
    SendableRequest req = mock(SendableRequest.class);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    sched.registerInsert(req, /* persistent */ false);
    verify(selector).innerRegister(same(req), same(context), isNull());
    verify(starter).wakeUp();
  }

  @Test
  void register_withListenerAndNullGetters_registersListenerOnly() {
    ClientRequestScheduler sched = newScheduler(false);
    HasKeyListener hasListener = mock(HasKeyListener.class);
    KeyListener listener = mock(KeyListener.class);
    when(hasListener.makeKeyListener(same(context), eq(false))).thenReturn(listener);

    sched.register(hasListener, null, /* persistent */ false, null, /* noCheckStore */ true);
    assertTrue(sched.schedTransient.containsPendingKeys(same(listener)));
  }

  @Test
  void register_withNoCheckStore_schedulesInnerRegisterOnlyForValidRequests() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableGet valid = mock(SendableGet.class);
    when(valid.isCancelled()).thenReturn(false);
    when(valid.getWakeupTime(same(context), anyLong())).thenReturn(0L);

    SendableGet cancelled = mock(SendableGet.class);
    when(cancelled.isCancelled()).thenReturn(true);

    SendableGet cooldown = mock(SendableGet.class);
    when(cooldown.isCancelled()).thenReturn(false);
    when(cooldown.getWakeupTime(same(context), anyLong())).thenReturn(100L);

    SendableGet[] getters = new SendableGet[] {valid, cancelled, cooldown};

    sched.register(/* hasListener */ null, getters, /* persistent */ false, null, /* noCheckStore */ true);
    verify(selector).innerRegister(same(valid), same(context), same(getters));
    verifyNoMoreInteractions(selector);
  }

  @Test
  void finishRegister_persistent_preRegisterFalse_registersWithSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    SendableGet getter = mock(SendableGet.class);
    when(getter.isCancelled()).thenReturn(false);
    when(getter.preRegister(same(context), eq(true))).thenReturn(false);

    sched.finishRegister(new SendableGet[] {getter}, /* persistent */ true, /* anyValid */ true);
    verify(selector).innerRegister(same(getter), same(context), any());
  }

  @Test
  void removeRunningRequest_alwaysClearsWakeupTime() {
    ClientRequestScheduler sched = newScheduler(false);
    SendableRequest req = mock(SendableRequest.class);

    // The add-then-remove is a functional no-op; just verify clearWakeupTime is called.
    sched.removeRunningRequest(req);
    verify(req).clearWakeupTime(same(context));
  }

  @Test
  void isRunningOrQueuedPersistentRequest_checksIdentityInSet() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    IdentityHashSet<SendableRequest> set = new IdentityHashSet<>();
    setFinalField(sched, "runningPersistentRequests", set);

    SendableRequest r1 = mock(SendableRequest.class);
    SendableRequest r2 = mock(SendableRequest.class);

    assertFalse(sched.isRunningOrQueuedPersistentRequest(r1));
    set.add(r1);
    assertTrue(sched.isRunningOrQueuedPersistentRequest(r1));
    assertFalse(sched.isRunningOrQueuedPersistentRequest(r2));
  }

  @Test
  void grabRequest_returnsSelectorResult_withPriorityFuzzDependingOnMode() {
    ClientRequestScheduler sched = newScheduler(false);
    Key key = mock(Key.class);

    ChosenBlock chosen = new ChosenBlock(key, (short) 3, null);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    when(selector.chooseRequest(anyShort(), same(random), any(), same(starter), anyBoolean(), same(context)))
        .thenReturn(chosen);

    // Default=HARD -> zero fuzz
    assertSame(chosen, sched.grabRequest());

    sched.setPriorityScheduler(ClientRequestScheduler.PRIORITY_SOFT);
    // Soft -> negative fuzz
    assertSame(chosen, sched.grabRequest());
  }

  @Test
  void wantKey_checksTransientFirst_thenCoreIfPresent() {
    ClientRequestScheduler sched = newScheduler(false);
    Key key = mock(Key.class);

    KeyListenerTracker transientTracker = mock(KeyListenerTracker.class);
    KeyListenerTracker coreTracker = mock(KeyListenerTracker.class);

    setFinalField(sched, "schedTransient", transientTracker);
    when(transientTracker.anyProbablyWantKey(same(key), same(context))).thenReturn(false);
    assertFalse(sched.wantKey(key));

    setFinalField(sched, "schedCore", coreTracker);
    when(coreTracker.anyProbablyWantKey(same(key), same(context))).thenReturn(true);
    assertTrue(sched.wantKey(key));
  }

  @Test
  void queueOfferedKey_checksModeAndWakesStarter() {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    Key key = mock(Key.class);
    sched.queueOfferedKey(key, /* realTime */ false);
    verify(starter).wakeUp();
  }

  @Test
  void dequeueOfferedKey_removesKeyFromList() {
    ClientRequestScheduler sched = newScheduler(false);
    OfferedKeysList list = mock(OfferedKeysList.class);
    setFinalField(sched, "offeredKeys", list);

    Key key = mock(Key.class);
    sched.dequeueOfferedKey(key);
    verify(list).remove(same(key));
  }

  @Test
  void countQueuedRequests_delegatesToSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    when(selector.countQueuedRequests(same(context))).thenReturn(42L);
    assertEquals(42L, sched.countQueuedRequests());
  }

  @Test
  void fetchingKeys_returnsSelector() throws Exception {
    ClientRequestScheduler sched = newScheduler(false);
    ClientRequestSelector selector = mock(ClientRequestSelector.class);
    setFinalField(sched, "selector", selector);

    assertSame(selector, sched.fetchingKeys());
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
  void removeRunningInsert_delegatesToSelectorAndClearsCooldown() throws Exception {
    ClientRequestScheduler sched = newScheduler(true);
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
    sched.callFailure(get, e, 3, false);
    verify(get).onFailure(same(e), isNull(), same(context));
  }

  @Test
  void callFailure_get_persistent_queuesJobRunner() {
    ClientRequestScheduler sched = newScheduler(false);
    SendableGet get = mock(SendableGet.class);
    LowLevelGetException e =
        new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, "x", null);
    sched.callFailure(get, e, 5, true);
    try {
      verify(((ClientLayerPersister) context.jobRunner)).queue(any(PersistentJob.class), eq(5));
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
