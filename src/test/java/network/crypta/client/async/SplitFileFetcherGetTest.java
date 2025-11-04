package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.client.FetchContext;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableGet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SplitFileFetcherGetTest {

  @Mock private ClientContext clientContext;
  @Mock private ClientRequestScheduler scheduler;

  private SplitFileFetcher fetcher;
  private SplitFileFetcher storageOwnerFetcher; // alias to clarify role in a few tests
  private SplitFileFetcherGet getter;
  private SplitFileFetcherStorage storage;

  private TestRequester requester;
  private RequestClient requestClient;

  private FetchContext blockFetchContext;
  private BlockSet blockSet;

  @BeforeEach
  void setup() {
    // Minimal RequestClient used by ClientRequester to provide persistence/RT flags
    requestClient =
        new RequestClient() {
          @Override
          public boolean persistent() {
            return true;
          }

          @Override
          public boolean realTimeFlag() {
            return false;
          }
        };

    requester = new TestRequester((short) 42, requestClient);

    // Build a basic FetchContext and then a masked copy that carries a BlockSet
    FetchContext base =
        new FetchContext(
            1024L,
            1024L,
            1024,
            1,
            0,
            0,
            true,
            1,
            1,
            1,
            false,
            false,
            false,
            false,
            0,
            0,
            null,
            new SimpleEventProducer(),
            false,
            true,
            null,
            null,
            null);
    blockSet = new SimpleBlockSet();
    blockFetchContext =
        new FetchContext(base, FetchContext.SPLITFILE_DEFAULT_BLOCK_MASK, false, blockSet);

    // Real SplitFileFetcher instance via serialization-only ctor; then wire required finals
    fetcher = new SplitFileFetcher();
    storageOwnerFetcher = fetcher;
    setField(fetcher, "parent", requester);
    setField(fetcher, "realTimeFlag", false);
    setField(fetcher, "blockFetchContext", blockFetchContext);

    storage = mock(SplitFileFetcherStorage.class);

    // Do not stub context here; stub per-test to avoid strict stubbing failures

    getter = new SplitFileFetcherGet(fetcher, storage);
  }

  @Test
  void getKey_withMatchingStorage_delegatesToStorage() {
    ClientKey expected = mock(ClientKey.class);
    SplitFileFetcherStorage.SplitFileFetcherStorageKey token = newKey(storage, 1, 0);
    when(storage.getKey(token)).thenReturn(expected);

    ClientKey got = getter.getKey(token);

    assertEquals(expected, got);
    verify(storage, times(1)).getKey(token);
  }

  @Test
  void getKey_withMismatchedStorage_throwsIllegalArgumentException() {
    SplitFileFetcherStorage other = mock(SplitFileFetcherStorage.class);
    SplitFileFetcherStorage.SplitFileFetcherStorageKey token = newKey(other, 2, 1);
    assertThrows(IllegalArgumentException.class, () -> getter.getKey(token));
  }

  @Test
  void listKeys_delegatesToStorage() {
    Key k1 = mock(Key.class);
    Key k2 = mock(Key.class);
    when(storage.listUnfetchedKeys()).thenReturn(new Key[] {k1, k2});
    assertArrayEquals(new Key[] {k1, k2}, getter.listKeys());
  }

  @Test
  void getContext_returnsParentsBlockFetchContext() {
    assertEquals(blockFetchContext, getter.getContext());
  }

  @Test
  void onFailure_whenNonFatal_delegatesToStorageOnFailure() {
    SplitFileFetcherStorage.SplitFileFetcherStorageKey token = newKey(storage, 3, 0);
    LowLevelGetException e = new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND, "dnf");

    getter.onFailure(e, token, clientContext);

    // Non-fatal → storage handles it; parent.fail() is not called
    verify(storage, times(1)).onFailure(eq(token), any(network.crypta.client.FetchException.class));
  }

  @Test
  void onFailure_whenFatal_callsParentFail() {
    // Spy the fetcher to intercept fail() without executing its heavy logic
    SplitFileFetcher spyFetcher = org.mockito.Mockito.spy(storageOwnerFetcher);
    setField(spyFetcher, "parent", requester); // ensure wiring survives spy
    setField(spyFetcher, "realTimeFlag", false);
    setField(spyFetcher, "blockFetchContext", blockFetchContext);
    SplitFileFetcherGet localGetter = new SplitFileFetcherGet(spyFetcher, storage);

    SplitFileFetcherStorage.SplitFileFetcherStorageKey token = newKey(storage, 4, 0);
    LowLevelGetException e = new LowLevelGetException(LowLevelGetException.DECODE_FAILED, "decode");

    // Do not run the real fail() internals
    doNothing().when(spyFetcher).fail(any(network.crypta.client.FetchException.class));

    localGetter.onFailure(e, token, clientContext);

    verify(spyFetcher, times(1)).fail(any(network.crypta.client.FetchException.class));
    // Storage.onFailure should not be called on fatal errors
    verify(storage, never()).onFailure(eq(token), any());
  }

  @Test
  void getWakeupTime_delegatesToStorage() {
    when(storage.getCooldownWakeupTime(anyLong())).thenReturn(1234L);
    assertEquals(1234L, getter.getWakeupTime(clientContext, 111L));
  }

  @Test
  void getCooldownWakeup_readsFromSegmentCooldown() {
    // Prepare segments array with a mocked segment that returns a fixed cooldown time
    SplitFileFetcherSegmentStorage seg0 = mock(SplitFileFetcherSegmentStorage.class);
    when(seg0.getCooldownTime(7)).thenReturn(555L);
    setStorageSegments(storage, new SplitFileFetcherSegmentStorage[] {seg0});

    SplitFileFetcherStorage.SplitFileFetcherStorageKey token = newKey(storage, 7, 0);
    long t = getter.getCooldownWakeup(token, clientContext);
    assertEquals(555L, t);
  }

  @Test
  void preRegister_whenLocalOnly_finishesCheckingAndReturnsTrue() {
    blockFetchContext.localRequestOnly = true;
    boolean cancelled = getter.preRegister(clientContext, true);
    assertTrue(cancelled);
    verify(storage, times(1)).finishedCheckingDatastoreOnLocalRequest();
  }

  @Test
  void preRegister_whenNetwork_setsHasCheckedStoreNotifiesAndReturnsFalse() {
    blockFetchContext.localRequestOnly = false;
    PersistentJobRunner runner = mock(PersistentJobRunner.class);
    when(clientContext.getJobRunner(true)).thenReturn(runner);

    boolean cancelled = getter.preRegister(clientContext, true);

    assertFalse(cancelled);
    verify(storage, times(1)).setHasCheckedStore(clientContext);
    // The requester notifies via the job runner; ensure a job was queued
    verify(clientContext.getJobRunner(true), times(1)).queueNormalOrDrop(any(PersistentJob.class));
  }

  @Test
  void getPriorityClass_delegatesToParent() {
    assertEquals(42, getter.getPriorityClass());
  }

  @Test
  void chooseKey_delegatesToStorage() {
    SplitFileFetcherStorage.SplitFileFetcherStorageKey token = newKey(storage, 1, 0);
    when(storage.chooseRandomKey()).thenReturn(token);
    assertEquals(token, getter.chooseKey(null, clientContext));
  }

  @Test
  void countMethods_delegateToStorage() {
    when(storage.countUnfetchedKeys()).thenReturn(10L);
    when(storage.countSendableKeys()).thenReturn(4L);
    assertEquals(10L, getter.countAllKeys(clientContext));
    assertEquals(4L, getter.countSendableKeys(clientContext));
  }

  @Test
  void isCancelled_reflectsParentFinishedState() {
    // Default false
    assertFalse(getter.isCancelled());
    // Flip via fetcher.hasFinished(); easiest is to set succeeded flag via reflection
    setField(fetcher, "succeeded", true);
    assertTrue(getter.isCancelled());
  }

  @Test
  void getClientAndRequest_returnValuesFromParentRequester() {
    assertEquals(requestClient, getter.getClient());
    assertEquals(requester, getter.getClientRequest());
  }

  @Test
  void isSSK_returnsFalse() {
    assertFalse(getter.isSSK());
  }

  @Test
  void schedule_registersWithSchedulerUsingBlocksAndFlag() {
    when(clientContext.getChkFetchScheduler(false)).thenReturn(scheduler);

    getter.schedule(clientContext, true);

    ArgumentCaptor<SendableGet[]> arrCap = ArgumentCaptor.forClass(SendableGet[].class);
    verify(scheduler, times(1))
        .register(eq(getter), arrCap.capture(), eq(true), eq(blockSet), eq(true));
    SendableGet[] passed = arrCap.getValue();
    assertNotNull(passed);
    assertEquals(1, passed.length);
    assertEquals(getter, passed[0]);
  }

  @Test
  void makeKeyListener_whenNoListener_returnsNull() {
    // By default, a Mockito mock has null fields; ensure we get null back
    assertNull(getter.makeKeyListener(clientContext, false));
  }

  @Test
  void hasQueued_reflectsStorageFlag() {
    when(storage.hasCheckedStore()).thenReturn(true).thenReturn(false);
    assertTrue(getter.hasQueued());
    assertFalse(getter.hasQueued());
  }

  @Test
  void getWantedKey_returnsNull() {
    assertNull(getter.getWantedKey());
  }

  // --- helpers ---

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field f = target.getClass().getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (NoSuchFieldException e) {
      // Try superclass for protected fields
      try {
        Field f = target.getClass().getSuperclass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
      } catch (ReflectiveOperationException ex) {
        throw new RuntimeException(ex);
      }
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException(e);
    }
  }

  private static SplitFileFetcherStorage.SplitFileFetcherStorageKey newKey(
      SplitFileFetcherStorage owner, int block, int seg) {
    return owner.new SplitFileFetcherStorageKey(block, seg, owner);
  }

  private static void setStorageSegments(
      SplitFileFetcherStorage s, SplitFileFetcherSegmentStorage[] segments) {
    try {
      Field f = SplitFileFetcherStorage.class.getDeclaredField("segments");
      f.setAccessible(true);
      f.set(s, segments);
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException(e);
    }
  }

  // Minimal concrete ClientRequester used by tests
  private static final class TestRequester extends ClientRequester {
    TestRequester(short prio, RequestClient client) {
      super(prio, client);
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Intentional no-op: unit tests do not need transition notifications
    }

    @Override
    public void cancel(ClientContext context) {
      // Intentional no-op: cancellation behavior is not under test here
    }

    @Override
    public network.crypta.keys.FreenetURI getURI() {
      return null;
    }

    @Override
    public boolean isFinished() {
      return false;
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      // Intentional no-op: network notifications are exercised via scheduler mocks
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      // Intentional no-op: progress notification side effects are not required in tests
    }

    @Override
    protected ClientBaseCallback getCallback() {
      // Minimal callback that just exposes the existing RequestClient; no resume work needed
      return new ClientBaseCallback() {
        @Override
        public void onResume(ClientContext context) {
          // no-op for tests
        }

        @Override
        public RequestClient getRequestClient() {
          return getClient();
        }
      };
    }
  }
}
