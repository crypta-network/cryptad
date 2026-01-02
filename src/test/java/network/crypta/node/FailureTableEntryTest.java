package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.ref.WeakReference;
import network.crypta.io.comm.PeerContext;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FailureTableEntryTest {

  private static final short HTL_3 = 3;
  private static final short HTL_5 = 5;

  private Key key;
  private FailureTableEntry entry;

  @Mock private PeerNode peer1;
  @Mock private PeerNode peer2;

  @BeforeEach
  void setUp() {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    for (int i = 0; i < rk.length; i++) rk[i] = (byte) (i + 1);
    key = new NodeCHK(rk, Key.ALGO_AES_PCFB_256_SHA256);
    entry = new FailureTableEntry(key);

    // Default stubs for peers
    setPeerDefaults(peer1, 1L, 0.42);
    setPeerDefaults(peer2, 2L, 0.99);
  }

  private static void setPeerDefaults(PeerNode peer, long bootId, double loc) {
    when(peer.getBootID()).thenReturn(bootId);
    when(peer.getLocation()).thenReturn(loc);
    when(peer.isConnected()).thenReturn(true);
    when(peer.shortToString()).thenReturn("peer-" + bootId);
    when(peer.getWeakRef()).thenAnswer(inv -> new WeakReference<PeerContext>(peer));
  }

  @Test
  @DisplayName("constructor_initialState_expectEmptyAndNoTimeouts")
  void constructor_initialState_expectEmptyAndNoTimeouts() {
    long now = System.currentTimeMillis();

    assertTrue(entry.isEmpty());
    assertTrue(entry.isEmpty());

    assertFalse(entry.askedByPeer(peer1, now));
    assertFalse(entry.askedFromPeer(peer1, now));

    assertEquals(-1, entry.getTimeoutTime(peer1, HTL_3, now, false));
    assertEquals(-1, entry.getTimeoutTime(peer1, HTL_3, now, true));
  }

  @Test
  @DisplayName("failedTo_setsTimeoutsAndGetTimeoutTimeHonorsHtl")
  void failedTo_setsTimeoutsAndGetTimeoutTimeHonorsHtl() {
    long base = 10_000L;
    long rf = 5_000L;
    long ft = 10_000L;

    entry.failedTo(peer1, rf, ft, base, HTL_5);

    assertTrue(entry.askedFromPeer(peer1, base + 1));

    assertEquals(base + rf, entry.getTimeoutTime(peer1, HTL_5, base + 1, false));
    assertEquals(base + ft, entry.getTimeoutTime(peer1, HTL_5, base + 1, true));

    // Higher HTL should ignore the timeout stored at a lower HTL
    assertEquals(-1, entry.getTimeoutTime(peer1, (short) (HTL_5 + 1), base + 1, false));
  }

  @Test
  @DisplayName("failedTo_secondCallDoesNotDecreaseTimeouts")
  void failedTo_secondCallDoesNotDecreaseTimeouts() {
    long base = 50_000L;
    entry.failedTo(peer1, 5_000L, 10_000L, base, HTL_3);
    // Attempt to lower the timeouts: should not shorten
    entry.failedTo(peer1, 100L, 100L, base + 1, HTL_3);

    assertEquals(base + 5_000L, entry.getTimeoutTime(peer1, HTL_3, base + 2, false));
    assertEquals(base + 10_000L, entry.getTimeoutTime(peer1, HTL_3, base + 2, true));
  }

  @Test
  @DisplayName("failedTo_samePeerDifferentHtl_keepsSeparateTimeoutsAndSelection")
  void failedTo_samePeerDifferentHtl_keepsSeparateTimeoutsAndSelection() {
    long base = 100_000L;
    entry.failedTo(peer1, 100L, 0L, base, HTL_3); // RF=base+100 @ HTL_3
    entry.failedTo(peer1, 500L, 0L, base, HTL_5); // RF=base+500 @ HTL_5

    // At HTL 5: should see the entry with HTL 5
    assertEquals(base + 500L, entry.getTimeoutTime(peer1, HTL_5, base + 1, false));
    // At HTL 3: both entries are eligible; max wins
    assertEquals(base + 500L, entry.getTimeoutTime(peer1, HTL_3, base + 1, false));
  }

  @Test
  @DisplayName("othersWantAndAskedByPeer_withinAndAfterExpiry")
  void othersWantAndAskedByPeer_withinAndAfterExpiry() {
    long now = 200_000L;
    short reqHtl = 7;

    // Populate requestor list directly via package-private helper
    entry.addRequestor(peer1, now, reqHtl);

    assertTrue(entry.othersWant());
    assertTrue(entry.askedByPeer(peer1, now + 1));
    assertFalse(entry.askedByPeer(peer2, now + 1));

    long afterExpiry = now + FailureTableEntry.MAX_TIME_BETWEEN_REQUEST_AND_OFFER + 1;
    assertFalse(entry.askedByPeer(peer1, afterExpiry));
    // askedByPeer() clears empty/expired requestors eagerly
    assertFalse(entry.othersWant());
  }

  @Test
  @DisplayName("offer_sendsToBothRequestedAndRequestor_onceEachAndSkipsDuplicates")
  void offer_sendsToBothRequestedAndRequestor_onceEachAndSkipsDuplicates() {
    long now = 300_000L;
    short reqHtl = 9;

    // Add one as requestor and the same also as requested-from to ensure uniqueness
    entry.addRequestor(peer1, now, reqHtl);
    entry.failedTo(peer1, 1000L, 1000L, now, HTL_3);
    // And add another peer through the requested-from path
    entry.failedTo(peer2, 1000L, 1000L, now, HTL_3);

    entry.offer();

    // Each peer gets exactly one offer with the entry's key
    verify(peer1, times(1)).offer(entry.key);
    verify(peer2, times(1)).offer(entry.key);
  }

  @Test
  @DisplayName("askedFromPeer_expiredEntries_returnFalseUntilCleanup")
  void askedFromPeer_expiredEntries_returnFalseUntilCleanup() {
    long now = 400_000L;
    entry.failedTo(peer1, 1000L, 1000L, now, HTL_3);

    long max = FailureTableEntry.MAX_TIME_BETWEEN_REQUEST_AND_OFFER;
    long afterExpiry = now + max + 1;
    // Sanity: verify our computed timestamp is beyond expiry window relative to stored value
    // (package-private array access used for determinism only)
    assertTrue(afterExpiry - entry.requestedTimes[0] > max);
    assertFalse(entry.askedFromPeer(peer1, afterExpiry));

    // Not yet cleaned from arrays
    assertFalse(entry.isEmpty());

    // cleanup() uses wall clock. Use entries that are already far in the past to be pruned now.
    FailureTableEntry e2 = new FailureTableEntry(key);
    e2.failedTo(peer1, 0L, 0L, 1L, HTL_3);
    assertTrue(e2.cleanup()); // everything pruned, empty
    assertTrue(e2.isEmpty());
  }

  @Test
  @DisplayName("minRequestorHTL_returnsMinimumAmongRecent_andKeepsInitialWhenAllExpired")
  void minRequestorHTL_returnsMinimumAmongRecent_andKeepsInitialWhenAllExpired() {
    long nowWall = System.currentTimeMillis();
    entry.addRequestor(peer1, nowWall, (short) 8);
    entry.addRequestor(peer2, nowWall, (short) 3);

    assertEquals(3, entry.minRequestorHTL((short) 10));

    // Expire both and verify initial HTL is returned
    long past =
        System.currentTimeMillis() - (FailureTableEntry.MAX_TIME_BETWEEN_REQUEST_AND_OFFER + 10);
    FailureTableEntry e2 = new FailureTableEntry(key);
    e2.addRequestor(peer1, past, (short) 8);
    e2.addRequestor(peer2, past, (short) 3);
    assertEquals(10, e2.minRequestorHTL((short) 10));
  }

  @Test
  @DisplayName("cleanup_prunesDisconnectedOrExpired_andReportsEmptyState")
  void cleanup_prunesDisconnectedOrExpired_andReportsEmptyState() {
    long nowWall = System.currentTimeMillis();
    entry.addRequestor(peer1, nowWall, (short) 6);
    entry.failedTo(peer2, 1000L, 1000L, nowWall, HTL_3);

    // First cleanup with everything connected and recent -> not empty
    boolean emptyAfterFirst = entry.cleanup();
    assertFalse(emptyAfterFirst);

    // Mark peers disconnected; cleanup should now prune everything
    when(peer1.isConnected()).thenReturn(false);
    when(peer2.isConnected()).thenReturn(false);

    // Simulate time after expiry window to ensure pruning
    // With peers disconnected, cleanup should prune regardless of timing.
    boolean emptyAfterSecond = entry.cleanup();
    assertTrue(emptyAfterSecond);
    assertTrue(entry.isEmpty());
  }

  @Test
  @DisplayName("cleanupRequested_compaction_preservesLiveTimeouts")
  void cleanupRequested_compaction_preservesLiveTimeouts() {
    long wall = System.currentTimeMillis();
    long base = wall - 1_000L; // ensure within validity window

    // Index 0: will be pruned due to disconnection
    entry.failedTo(peer1, 100_000L, 200_000L, base, HTL_3);
    // Index 1: stays valid and should be compacted to index 0 with timeouts preserved
    entry.failedTo(peer2, 120_000L, 250_000L, base, HTL_3);

    // Make the first peer invalid so cleanup compacts the arrays
    when(peer1.isConnected()).thenReturn(false);

    // Trigger compaction; method computes 'now' internally
    entry.cleanup();

    // Peer2 must still be considered recently asked-from
    assertTrue(entry.askedFromPeer(peer2, wall + 10));

    // RF and FT timeouts must be preserved after compaction
    assertEquals(base + 120_000L, entry.getTimeoutTime(peer2, HTL_3, wall + 20, false));
    assertEquals(base + 250_000L, entry.getTimeoutTime(peer2, HTL_3, wall + 20, true));
  }
}
