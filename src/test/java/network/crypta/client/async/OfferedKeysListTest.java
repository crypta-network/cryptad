package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeClientCoreTransfers;
import network.crypta.node.RequestCompletionListener;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestSender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class OfferedKeysListTest {

  private static final short PRIO = 7;

  private NodeClientCore core;
  private NodeClientCoreTransfers transfers;
  private KeysFetchingLocally fetching;
  private RequestScheduler scheduler;

  @BeforeEach
  void setUp() {
    core = mock(NodeClientCore.class);
    transfers = mock(NodeClientCoreTransfers.class);
    lenient().when(core.getTransfers()).thenReturn(transfers);
    fetching = mock(KeysFetchingLocally.class);
    scheduler = mock(RequestScheduler.class);
  }

  @Test
  void isEmpty_and_queueKey_and_remove_behaveAsExpected() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(1), PRIO, false, false);

    assertTrue(list.isEmpty());

    Key k = keyWithByte((byte) 0x11);
    list.queueKey(k);
    assertFalse(list.isEmpty());

    list.remove(k);
    assertTrue(list.isEmpty());
  }

  @Test
  void chooseKey_whenEmpty_returnsNull() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(2), PRIO, false, false);
    assertNull(list.chooseKey(fetching, null));
  }

  @Test
  void chooseKey_whenSingleKeyAndNotFetching_returnsTokenAndRemoves() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(3), PRIO, false, false);
    Key k = keyWithByte((byte) 0x22);
    list.queueKey(k);

    when(fetching.hasKey(k, null)).thenReturn(false);

    var item = list.chooseKey(fetching, null);
    assertNotNull(item);
    assertEquals(k, list.getNodeKey(item));
    assertTrue(list.isEmpty(), "Key should be removed after chooseKey");
  }

  @Test
  void chooseKey_whenSingleKeyButAlreadyFetching_returnsNullAndKeepsKey() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(4), PRIO, false, false);
    Key k = keyWithByte((byte) 0x33);
    list.queueKey(k);

    when(fetching.hasKey(k, null)).thenReturn(true);

    assertNull(list.chooseKey(fetching, null));
    assertFalse(list.isEmpty(), "Key must remain queued when already fetching");

    // Now make it available and ensure we can pick it up.
    when(fetching.hasKey(k, null)).thenReturn(false);
    SendableRequestItem item = list.chooseKey(fetching, null);
    assertNotNull(item);
    assertEquals(k, list.getNodeKey(item));
    assertTrue(list.isEmpty());
  }

  @Test
  void chooseKey_whenMultipleKeys_skipsFetchingOnes_andReturnsAnother() {
    // Deterministic random that first returns index 0, then 1.
    RandomSource rnd = new SeqRandomSource(0, 1);
    OfferedKeysList list = new OfferedKeysList(rnd, PRIO, false, false);
    Key a = keyWithByte((byte) 0x44);
    Key b = keyWithByte((byte) 0x55);
    list.queueKey(a);
    list.queueKey(b);

    when(fetching.hasKey(a, null)).thenReturn(true);
    when(fetching.hasKey(b, null)).thenReturn(false);

    SendableRequestItem item = list.chooseKey(fetching, null);
    assertNotNull(item);
    assertEquals(b, list.getNodeKey(item), "Should select non-fetching key");
    assertFalse(list.isEmpty());
  }

  @Test
  void chooseKey_whenAllCandidatesFetching_returnsNullAfterAttempts() {
    // Always return index 0 to keep picking the same fetching key until loop limit.
    RandomSource rnd = new SeqRandomSource(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    OfferedKeysList list = new OfferedKeysList(rnd, PRIO, false, false);
    Key a = keyWithByte((byte) 0x66);
    Key b = keyWithByte((byte) 0x77);
    list.queueKey(a);
    list.queueKey(b);

    when(fetching.hasKey(a, null)).thenReturn(true);

    assertNull(list.chooseKey(fetching, null));
    // Nothing should have been removed.
    assertFalse(list.isEmpty());
  }

  @Test
  void queueKey_whenDuplicateOffered_deduplicates() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(5), PRIO, false, false);
    Key k = keyWithByte((byte) 0x7A);
    list.queueKey(k);
    list.queueKey(k); // duplicate

    when(fetching.hasKey(k, null)).thenReturn(false);

    // Only one should be returned, and then the list is empty.
    assertNotNull(list.chooseKey(fetching, null));
    assertTrue(list.isEmpty());
  }

  @Test
  void getSender_send_invokesAsyncGet_andSchedulerCallbacksOnCompletion() {
    boolean realTime = true;
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(6), PRIO, false, realTime);
    Key k = keyWithByte((byte) 0x01);
    list.queueKey(k);
    when(fetching.hasKey(k, null)).thenReturn(false);
    SendableRequestItem token = list.chooseKey(fetching, null);
    assertNotNull(token);

    // Capture the RequestCompletionListener passed to asyncGet
    ArgumentCaptor<RequestCompletionListener> captor =
        ArgumentCaptor.forClass(RequestCompletionListener.class);
    doAnswer(
            invocation -> {
              // No-op stub: we drive completion via captured listener after verification.
              return null;
            })
        .when(transfers)
        .asyncGet(
            any(Key.class),
            any(Boolean.class),
            any(RequestCompletionListener.class),
            any(Boolean.class),
            any(Boolean.class),
            any(Boolean.class),
            any(Boolean.class),
            any(Boolean.class));

    // Use sender directly with a minimal ChosenBlock carrying the token
    var sender = list.getSender(null);
    TestChosenBlock req = new TestChosenBlock(token);
    assertTrue(sender.send(core, scheduler, null, req));
    assertFalse(sender.sendIsBlocking());

    // Verify asyncGet was invoked and capture arguments to assert values without eq(...)
    ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);
    ArgumentCaptor<Boolean> offersOnlyCap = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<Boolean> canReadCap = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<Boolean> canWriteCap = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<Boolean> rtCap = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<Boolean> localOnlyCap = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<Boolean> ignoreStoreCap = ArgumentCaptor.forClass(Boolean.class);
    verify(transfers, times(1))
        .asyncGet(
            keyCaptor.capture(),
            offersOnlyCap.capture(),
            captor.capture(),
            canReadCap.capture(),
            canWriteCap.capture(),
            rtCap.capture(),
            localOnlyCap.capture(),
            ignoreStoreCap.capture());

    assertSame(k, keyCaptor.getValue());
    assertTrue(offersOnlyCap.getValue());
    assertTrue(canReadCap.getValue());
    assertFalse(canWriteCap.getValue());
    assertEquals(realTime, rtCap.getValue());
    assertFalse(localOnlyCap.getValue());
    assertFalse(ignoreStoreCap.getValue());

    // Simulate success callback
    RequestCompletionListener listener = captor.getValue();
    assertNotNull(listener);
    listener.onSucceeded();
    verify(scheduler, times(1)).removeFetchingKey(k);
    verify(scheduler, times(1)).wakeStarter();

    // Simulate failure callback
    listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
    verify(scheduler, times(2)).removeFetchingKey(k);
    verify(scheduler, times(2)).wakeStarter();
  }

  @Test
  void getters_and_basicFlags_returnConfiguredValues() {
    OfferedKeysList listSSKRT = new OfferedKeysList(new DummyRandomSource(7), PRIO, true, true);
    OfferedKeysList listCHKBulk = new OfferedKeysList(new DummyRandomSource(8), PRIO, false, false);

    assertSame(listSSKRT, listSSKRT.getClient());
    assertNull(listSSKRT.getClientRequest());
    assertEquals(PRIO, listSSKRT.getPriorityClass());
    assertTrue(listSSKRT.isSSK());
    assertFalse(listSSKRT.isInsert());
    assertFalse(listSSKRT.isCancelled());

    assertFalse(listCHKBulk.isSSK());
  }

  @Test
  void getScheduler_returnsCorrectSchedulerForFlags() {
    OfferedKeysList listSSKRT = new OfferedKeysList(new DummyRandomSource(9), PRIO, true, true);
    OfferedKeysList listCHKBulk =
        new OfferedKeysList(new DummyRandomSource(10), PRIO, false, false);

    ClientContext context = mock(ClientContext.class);
    ClientRequestScheduler sskRT = mock(ClientRequestScheduler.class);
    ClientRequestScheduler chkBulk = mock(ClientRequestScheduler.class);

    when(context.getSskFetchScheduler(true)).thenReturn(sskRT);
    when(context.getChkFetchScheduler(false)).thenReturn(chkBulk);

    assertSame(sskRT, listSSKRT.getScheduler(context));
    assertSame(chkBulk, listCHKBulk.getScheduler(context));
  }

  @Test
  void preRegister_returnsFalse_and_getWakeupTime_respectsEmptyState() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(11), PRIO, false, false);
    assertFalse(list.preRegister(null, false));
    assertEquals(Long.MAX_VALUE, list.getWakeupTime(null, 0));

    Key k = keyWithByte((byte) 0x5A);
    list.queueKey(k);
    assertEquals(0, list.getWakeupTime(null, 0));
  }

  @Test
  void countMethods_throwUnsupportedOperation() {
    OfferedKeysList list = new OfferedKeysList(new DummyRandomSource(12), PRIO, false, false);
    assertThrows(UnsupportedOperationException.class, () -> list.countAllKeys(null));
    assertThrows(UnsupportedOperationException.class, () -> list.countSendableKeys(null));
  }

  // --- Helpers ---

  private static Key keyWithByte(byte val) {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    Arrays.fill(rk, val);
    return new NodeCHK(rk, Key.ALGO_AES_CTR_256_SHA256);
  }

  /**
   * Deterministic RandomSource that returns a fixed sequence from nextInt(bound). Values are taken
   * modulo bound to satisfy API contract.
   */
  private static final class SeqRandomSource extends DummyRandomSource {
    private final int[] seq;
    private int idx;

    SeqRandomSource(int... seq) {
      super(0);
      this.seq = seq.clone();
      this.idx = 0;
    }

    @Override
    public synchronized int nextInt(int bound) {
      if (seq.length == 0) return 0;
      int v = seq[idx % seq.length];
      idx++;
      if (bound <= 0) return v; // Defensive; Random would throw, but not used in this test
      v %= bound;
      if (v < 0) v += bound;
      return v;
    }
  }

  /** Minimal ChosenBlock carrying only a token for sender tests. */
  private static final class TestChosenBlock extends ChosenBlock {
    TestChosenBlock(SendableRequestItem token) {
      super(token, null, null, new Options(false, false, false, false, false));
    }

    @Override
    public boolean isPersistent() {
      return false;
    }

    @Override
    public boolean isCancelled() {
      return false;
    }

    @Override
    public void onFailure(LowLevelPutException e, ClientContext context) {
      // Intentionally empty: this test stub never exercises insert failure callbacks.
      // Provided only to satisfy the abstract contract of ChosenBlock.
    }

    @Override
    public void onInsertSuccess(network.crypta.keys.ClientKey key, ClientContext context) {
      // Intentionally empty: insert success is not relevant for OfferedKeysList sender tests.
    }

    @Override
    public void onFailure(LowLevelGetException e, ClientContext context) {
      // Intentionally empty: callbacks are tested indirectly via scheduler interactions above.
    }

    @Override
    public void onFetchSuccess(ClientContext context) {
      // Intentionally empty: fetch success triggers are not invoked by these unit tests.
    }

    @Override
    public short getPriority() {
      return 0;
    }

    @Override
    public SendableRequestSender getSender(ClientContext context) {
      throw new UnsupportedOperationException("Not used in this test");
    }
  }
}
