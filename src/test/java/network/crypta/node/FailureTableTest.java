package network.crypta.node;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.PeerContext;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FailureTableTest {

  @Mock private NodeClientCore core;

  private static final byte CRYPTO_ALGO = Key.ALGO_AES_PCFB_256_SHA256;

  private static final class InlineExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NonNull Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      job.run();
    }

    @Override
    public int[] waitingThreads() {
      return new int[0];
    }

    @Override
    public int[] runningThreads() {
      return new int[0];
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  private static final class NoopTicker implements Ticker {
    private final PriorityAwareExecutor exec = new InlineExecutor();

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      // Intentionally a no-op in tests: we avoid real scheduling to keep tests deterministic.
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      // Intentionally a no-op in tests: duplicate suppression/ticker semantics are irrelevant here.
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return exec;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // Intentionally a no-op in tests: nothing is ever queued in this NoopTicker.
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      // Intentionally a no-op in tests: absolute scheduling is not exercised.
    }
  }

  private static final class FixedRandomSource extends RandomSource {
    private final Random rnd;

    FixedRandomSource(long seed) {
      this.rnd = new Random(seed);
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // Nothing to release: this RandomSource delegates to a local java.util.Random.
    }

    @Override
    protected synchronized int next(int bits) {
      return rnd.nextInt() >>> (32 - bits);
    }
  }

  private static Node newNodeMock(boolean ulpr, boolean perNode, NodeClientCore core) {
    Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    Mockito.when(node.isEnableULPRDataPropagation()).thenReturn(ulpr);
    Mockito.when(node.isEnablePerNodeFailureTables()).thenReturn(perNode);
    Mockito.when(node.getRandom()).thenReturn(new FixedRandomSource(123456789L));
    Mockito.when(node.network().ticker()).thenReturn(new NoopTicker());
    Mockito.when(node.services().clientCore()).thenReturn(core);
    Mockito.when(node.storage().hasKey(Mockito.any(), Mockito.anyBoolean(), Mockito.anyBoolean()))
        .thenReturn(false);
    Mockito.when(node.network().darknetPortNumber()).thenReturn(9481);
    return node;
  }

  private static NodeCHK newKey(byte fill) {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    for (int i = 0; i < rk.length; i++) rk[i] = (byte) (fill + i);
    return new NodeCHK(rk, CRYPTO_ALGO);
  }

  @BeforeEach
  void resetCore() {
    Mockito.reset(core);
  }

  @Test
  @DisplayName("onFailed clamps timeouts and updates entry")
  void onFailed_whenInvalidTimeouts_expectClampedAndRecorded() {
    Node node = newNodeMock(true, true, core);
    FailureTable ft = new FailureTable(node);
    NodeCHK key = newKey((byte) 1);

    PeerNode routedTo = Mockito.mock(PeerNode.class);
    Mockito.when(routedTo.getBootID()).thenReturn(100L);
    Mockito.when(routedTo.getLocation()).thenReturn(0.42);
    Mockito.when(routedTo.getWeakRef()).thenReturn(new WeakReference<PeerContext>(routedTo));
    Mockito.when(routedTo.isConnected()).thenReturn(true);

    long nowBefore = System.currentTimeMillis();

    // rfTimeout beyond limit, ftTimeout negative -> rf is clamped to RECENTLY_FAILED_TIME, ft to 0
    ft.onFailed(key, routedTo, (short) 3, FailureTable.RECENTLY_FAILED_TIME + 10_000, -5L);

    TimedOutNodesList list = ft.getTimedOutNodesList(key);
    assertNotNull(list, "Entry should exist when per-node tables are enabled");

    long rfDeadline = list.getTimeoutTime(routedTo, (short) 3, System.currentTimeMillis(), false);
    long ftDeadline = list.getTimeoutTime(routedTo, (short) 3, System.currentTimeMillis(), true);

    long expectedRfMin = nowBefore + FailureTable.RECENTLY_FAILED_TIME;
    assertTrue(rfDeadline >= expectedRfMin, "RF timeout should be in the future and clamped");
    assertEquals(-1L, ftDeadline, "FT timeout should be unset when clamped to 0");
  }

  @Test
  @DisplayName("onFinalFailure records requestor and minOfferedHTL computes minimum")
  void onFinalFailure_whenRequestorRecorded_expectPeersWantAndMinHTL() {
    Node node = newNodeMock(true, true, core);
    FailureTable ft = new FailureTable(node);
    NodeCHK key = newKey((byte) 2);

    PeerNode routedTo = Mockito.mock(PeerNode.class);
    Mockito.when(routedTo.getBootID()).thenReturn(200L);
    Mockito.when(routedTo.getLocation()).thenReturn(0.7);
    Mockito.when(routedTo.getWeakRef()).thenReturn(new WeakReference<PeerContext>(routedTo));
    Mockito.when(routedTo.isConnected()).thenReturn(true);

    PeerNode requestor = Mockito.mock(PeerNode.class);
    Mockito.when(requestor.getBootID()).thenReturn(300L);
    Mockito.when(requestor.getLocation()).thenReturn(0.1);
    Mockito.when(requestor.getWeakRef()).thenReturn(new WeakReference<PeerContext>(requestor));
    Mockito.when(requestor.isConnected()).thenReturn(true);

    ft.onFinalFailure(key, routedTo, (short) 5, (short) 7, 1_000L, 1_000L, requestor);

    assertTrue(ft.peersWantKey(key, Mockito.mock(PeerNode.class)), "Some peer should want the key");
    assertEquals(7, ft.minOfferedHTL(key, (short) 10), "Minimum HTL should reflect requestor");
  }

  @Test
  @DisplayName("onFound offers key to recorded requestors and removes entry")
  void onFound_whenEntryExists_expectOfferAndRemoval() {
    Node node = newNodeMock(true, true, core);
    FailureTable ft = new FailureTable(node);
    NodeCHK key = newKey((byte) 3);

    PeerNode requestor = Mockito.mock(PeerNode.class);
    Mockito.when(requestor.getBootID()).thenReturn(111L);
    Mockito.when(requestor.getLocation()).thenReturn(0.33);
    Mockito.when(requestor.getWeakRef()).thenReturn(new WeakReference<PeerContext>(requestor));
    Mockito.when(requestor.isConnected()).thenReturn(true);

    // Record a requestor so offer() has a target
    ft.onFinalFailure(key, null, (short) 0, (short) 4, 0L, 0L, requestor);

    // Prepare a KeyBlock that resolves to our key
    KeyBlock block = Mockito.mock(KeyBlock.class);
    Mockito.when(block.getKey()).thenReturn(key);

    ft.onFound(block);

    Mockito.verify(requestor, Mockito.times(1)).offer(key);
    assertFalse(ft.peersWantKey(key, null), "Entry should be removed after offering");
  }

  @Test
  @DisplayName("innerOnOffer accepts when we asked that peer and queues offered key")
  void innerOnOffer_whenWeAsked_expectOfferQueued() {
    Node node = newNodeMock(true, true, core);
    FailureTable ft = new FailureTable(node);
    NodeCHK key = newKey((byte) 4);

    PeerNode offeredBy = Mockito.mock(PeerNode.class);
    Mockito.when(offeredBy.getBootID()).thenReturn(55L);
    Mockito.when(offeredBy.getLocation()).thenReturn(0.21);
    Mockito.when(offeredBy.getWeakRef()).thenReturn(new WeakReference<PeerContext>(offeredBy));
    Mockito.when(offeredBy.isConnected()).thenReturn(true);

    // We "asked from" this peer earlier by recording a failure on it.
    ft.onFailed(key, offeredBy, (short) 3, 500L, 500L);

    // Reflectively set myRef so BlockOffer.isExpired() is safe if getOffers() is called.
    setPeerMyRef(offeredBy);

    ft.innerOnOffer(key, offeredBy, new byte[] {1, 2, 3});

    Mockito.verify(core, Mockito.times(1)).queueOfferedKey(key, false);
    assertTrue(ft.hadAnyOffers(key), "Offers map should contain the key");

    // getOffers() is the happy path API; ensure it is non-null when ULPR is enabled.
    assertNotNull(ft.getOffers(key));
  }

  @Test
  @DisplayName("innerOnOffer ignored when neither asked-by nor asked-from holds")
  void innerOnOffer_whenNotAsked_expectIgnored() {
    Node node = newNodeMock(true, true, core);
    FailureTable ft = new FailureTable(node);
    NodeCHK key = newKey((byte) 5);

    PeerNode routedElsewhere = Mockito.mock(PeerNode.class);
    Mockito.when(routedElsewhere.getBootID()).thenReturn(777L);
    Mockito.when(routedElsewhere.getLocation()).thenReturn(0.9);
    Mockito.when(routedElsewhere.getWeakRef())
        .thenReturn(new WeakReference<PeerContext>(routedElsewhere));
    Mockito.when(routedElsewhere.isConnected()).thenReturn(true);

    // We previously interacted with a different peer.
    ft.onFailed(key, routedElsewhere, (short) 1, 500L, 500L);

    PeerNode otherPeer = Mockito.mock(PeerNode.class);
    Mockito.when(otherPeer.getBootID()).thenReturn(888L);
    Mockito.when(otherPeer.getLocation()).thenReturn(0.1);
    Mockito.when(otherPeer.getWeakRef()).thenReturn(new WeakReference<PeerContext>(otherPeer));
    Mockito.when(otherPeer.isConnected()).thenReturn(true);

    ft.innerOnOffer(key, otherPeer, new byte[] {9});

    Mockito.verify(core, Mockito.never()).queueOfferedKey(Mockito.any(), Mockito.anyBoolean());
    assertFalse(ft.hadAnyOffers(key), "No offers should be recorded for unrelated peer");
  }

  @Test
  @DisplayName("getOffers returns null when ULPR is disabled")
  void getOffers_whenUlprDisabled_expectNull() {
    Node node = newNodeMock(false, true, core);
    FailureTable ft = new FailureTable(node);
    assertNull(ft.getOffers(newKey((byte) 9)));
  }

  @Test
  @DisplayName("getTimedOutNodesList returns null when per-node failure tables disabled")
  void getTimedOutNodesList_whenDisabled_expectNull() {
    Node node = newNodeMock(true, false, core);
    FailureTable ft = new FailureTable(node);
    assertNull(ft.getTimedOutNodesList(newKey((byte) 7)));
  }

  @Test
  @DisplayName("minOfferedHTL returns input when no entry exists")
  void minOfferedHTL_whenNoEntry_expectIdentity() {
    Node node = newNodeMock(true, true, core);
    FailureTable ft = new FailureTable(node);
    short h = 12;
    assertEquals(h, ft.minOfferedHTL(newKey((byte) 42), h));
  }

  private static void setPeerMyRef(PeerNode peer) {
    try {
      Field f = PeerNode.class.getDeclaredField("myRef");
      f.setAccessible(true);
      f.set(peer, new WeakReference<PeerContext>(peer));
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set PeerNode.myRef reflectively", e);
    }
  }
}
