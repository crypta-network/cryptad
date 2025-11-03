package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
// No argument matchers required here; use direct values for clarity.
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.MessageDigest;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class KeyListenerTrackerTest {

  private static final byte[] GLOBAL_SALT = new byte[32];

  static {
    // Stable salt for deterministic hashing
    for (int i = 0; i < GLOBAL_SALT.length; i++) GLOBAL_SALT[i] = (byte) (i + 1);
  }

  // Use a deterministic dummy RNG for reproducibility in tests.

  @Mock private RequestStarter starter;
  @Mock private Node node;
  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;

  private DummyRandomSource random;

  @BeforeEach
  void setUp() {
    random = new DummyRandomSource(42L);
    when(core.getStoreChecker()).thenReturn(mock(DatastoreChecker.class));
  }

  private ClientRequestScheduler newScheduler(boolean forInserts, boolean forSSKs) {
    ClientRequestScheduler.SchedulerMode mode =
        new ClientRequestScheduler.SchedulerMode(forInserts, forSSKs, false);
    return new ClientRequestScheduler(mode, random, starter, node, core, "test", clientContext);
  }

  private static byte[] bytes(int value) {
    byte[] b = new byte[32];
    for (int i = 0; i < b.length; i++) b[i] = (byte) (value + i);
    return b;
  }

  private static NodeCHK newCHK(byte[] routingKey) {
    return new NodeCHK(routingKey, (byte) 2);
  }

  private static NodeSSK newSSK(byte[] pkh, byte[] ehd) {
    return new NodeSSK(pkh, ehd, (byte) 2);
  }

  @Test
  void fixRetryCount_whenBelowThreshold_returnsZero() {
    assertEquals(0, KeyListenerTracker.fixRetryCount(0));
    assertEquals(0, KeyListenerTracker.fixRetryCount(1));
    assertEquals(0, KeyListenerTracker.fixRetryCount(2));
    // threshold itself
    assertEquals(0, KeyListenerTracker.fixRetryCount(3));
  }

  @Test
  void fixRetryCount_whenAboveThreshold_returnsOffset() {
    assertEquals(1, KeyListenerTracker.fixRetryCount(4));
    assertEquals(7, KeyListenerTracker.fixRetryCount(10));
  }

  @Test
  void saltKey_chkScheduler_hashesWithGlobalSalt() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    byte[] rk = bytes(10);
    NodeCHK key = newCHK(rk);

    byte[] salted = tracker.saltKey(key);

    MessageDigest md = SHA256.getMessageDigest();
    md.update(rk);
    md.update(GLOBAL_SALT);
    byte[] expected = md.digest();
    assertArrayEquals(expected, salted);
  }

  @Test
  void saltKey_sskScheduler_returnsPubKeyHash() {
    ClientRequestScheduler sched = newScheduler(false, true);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, true, false, random, sched, GLOBAL_SALT, false);

    byte[] pkh = bytes(20);
    byte[] ehd = bytes(70);
    NodeSSK key = newSSK(pkh, ehd);

    byte[] salted = tracker.saltKey(key);
    assertArrayEquals(pkh, salted);
  }

  @Test
  void addPendingKeys_nullListener_throws() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);
    assertThrows(NullPointerException.class, () -> tracker.addPendingKeys(null));
  }

  @Test
  void addRemove_singleKeyListener_roundtripAndOnRemoveCalledTwice() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    HasKeyListener owner = mock(HasKeyListener.class);
    byte[] wanted = bytes(1);
    when(owner.getWantedKey()).thenReturn(wanted);

    KeyListener listener = mock(KeyListener.class);
    when(listener.getHasKeyListener()).thenReturn(owner);
    when(listener.getWantedKey()).thenReturn(wanted);

    // Register and verify lookup
    tracker.addPendingKeys(listener);
    NodeCHK key = newCHK(wanted);
    byte[] salted = tracker.saltKey(key);
    when(listener.probablyWantKey(key, salted)).thenReturn(true);
    assertTrue(tracker.anyProbablyWantKey(key, clientContext));

    // Remove and verify double onRemove and absence
    assertTrue(tracker.removePendingKeys(listener));
    verify(listener, times(2)).onRemove();
    assertFalse(tracker.anyProbablyWantKey(key, clientContext));
  }

  @Test
  void addRemove_twoListenersSameKey_keepsOtherUntilRemoved() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    HasKeyListener owner = mock(HasKeyListener.class);
    byte[] wanted = bytes(2);
    when(owner.getWantedKey()).thenReturn(wanted);

    KeyListener l1 = mock(KeyListener.class);
    when(l1.getHasKeyListener()).thenReturn(owner);
    when(l1.getWantedKey()).thenReturn(wanted);

    KeyListener l2 = mock(KeyListener.class);
    when(l2.getHasKeyListener()).thenReturn(owner);
    when(l2.getWantedKey()).thenReturn(wanted);

    tracker.addPendingKeys(l1);
    tracker.addPendingKeys(l2);
    NodeCHK key = newCHK(wanted);
    byte[] salted = tracker.saltKey(key);
    when(l1.probablyWantKey(key, salted)).thenReturn(true);
    when(l2.probablyWantKey(key, salted)).thenReturn(true);
    assertTrue(tracker.anyProbablyWantKey(key, clientContext));

    // Remove first; second remains
    assertTrue(tracker.removePendingKeys(l1));
    verify(l1, times(2)).onRemove();
    assertTrue(tracker.anyProbablyWantKey(key, clientContext));

    // Remove second; none remains
    assertTrue(tracker.removePendingKeys(l2));
    verify(l2, times(2)).onRemove();
    assertFalse(tracker.anyProbablyWantKey(key, clientContext));
  }

  @Test
  void removeByOwner_removesAllAndCallsOnRemoveOnceEach() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    HasKeyListener owner = mock(HasKeyListener.class);
    byte[] wanted = bytes(3);
    when(owner.getWantedKey()).thenReturn(wanted);

    KeyListener l1 = mock(KeyListener.class);
    when(l1.getHasKeyListener()).thenReturn(owner);
    when(l1.getWantedKey()).thenReturn(wanted);

    KeyListener l2 = mock(KeyListener.class);
    when(l2.getHasKeyListener()).thenReturn(owner);
    when(l2.getWantedKey()).thenReturn(wanted);

    tracker.addPendingKeys(l1);
    tracker.addPendingKeys(l2);
    NodeCHK key = newCHK(wanted);
    byte[] salted = tracker.saltKey(key);
    when(l1.probablyWantKey(key, salted)).thenReturn(true);
    when(l2.probablyWantKey(key, salted)).thenReturn(true);
    assertTrue(tracker.anyProbablyWantKey(key, clientContext));

    assertTrue(tracker.removePendingKeys(owner));
    verify(l1, times(1)).onRemove();
    verify(l2, times(1)).onRemove();
    assertFalse(tracker.anyProbablyWantKey(key, clientContext));
  }

  @Test
  void getKeyPrio_whenMatches_minPriorityReturned() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    byte[] rk = bytes(4);
    NodeCHK key = newCHK(rk);
    byte[] salted = tracker.saltKey(key);

    // List listener (wantedKey == null)
    KeyListener l1 = mock(KeyListener.class);
    when(l1.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(l1.getWantedKey()).thenReturn(null);
    when(l1.probablyWantKey(key, salted)).thenReturn(true);
    when(l1.definitelyWantKey(key, salted, clientContext)).thenReturn((short) 8);
    tracker.addPendingKeys(l1);

    // Single-key listener
    HasKeyListener owner2 = mock(HasKeyListener.class);
    when(owner2.getWantedKey()).thenReturn(rk);
    KeyListener l2 = mock(KeyListener.class);
    when(l2.getHasKeyListener()).thenReturn(owner2);
    when(l2.getWantedKey()).thenReturn(rk);
    when(l2.probablyWantKey(key, salted)).thenReturn(true);
    when(l2.definitelyWantKey(key, salted, clientContext)).thenReturn((short) 5);
    tracker.addPendingKeys(l2);

    short result = tracker.getKeyPrio(key, (short) 10, clientContext);
    assertEquals(5, result);
  }

  @Test
  void anyWantKey_whenDefiniteNegative_returnsFalse() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    byte[] rk = bytes(5);
    NodeCHK key = newCHK(rk);
    byte[] salted = tracker.saltKey(key);

    KeyListener l = mock(KeyListener.class);
    when(l.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(l.getWantedKey()).thenReturn(null);
    when(l.probablyWantKey(key, salted)).thenReturn(true);
    when(l.definitelyWantKey(key, salted, clientContext)).thenReturn((short) -1);

    tracker.addPendingKeys(l);
    assertFalse(tracker.anyWantKey(key, clientContext));
  }

  @Test
  void anyProbablyWantKey_checksBothCollections() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    byte[] rk = bytes(6);
    NodeCHK key = newCHK(rk);
    byte[] salted = tracker.saltKey(key);

    // Single-key listener path
    HasKeyListener owner = mock(HasKeyListener.class);
    when(owner.getWantedKey()).thenReturn(rk);
    KeyListener l1 = mock(KeyListener.class);
    when(l1.getHasKeyListener()).thenReturn(owner);
    when(l1.getWantedKey()).thenReturn(rk);
    when(l1.probablyWantKey(key, salted)).thenReturn(true);

    // List listener path
    KeyListener l2 = mock(KeyListener.class);
    when(l2.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(l2.getWantedKey()).thenReturn(null);
    when(l2.probablyWantKey(key, salted)).thenReturn(false);

    tracker.addPendingKeys(l1);
    tracker.addPendingKeys(l2);
    assertTrue(tracker.anyProbablyWantKey(key, clientContext));
  }

  @Test
  void requestsForKey_aggregatesAndSkipsNulls() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    byte[] rk = bytes(7);
    NodeCHK key = newCHK(rk);
    byte[] salted = tracker.saltKey(key);

    // Matches and returns two requests
    KeyListener l1 = mock(KeyListener.class);
    when(l1.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(l1.getWantedKey()).thenReturn(null);
    when(l1.probablyWantKey(key, salted)).thenReturn(true);
    SendableGet r1 = mock(SendableGet.class);
    SendableGet r2 = mock(SendableGet.class);
    when(l1.getRequestsForKey(key, salted, clientContext)).thenReturn(new SendableGet[] {r1, r2});

    // Matches but returns null
    KeyListener l2 = mock(KeyListener.class);
    when(l2.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(l2.getWantedKey()).thenReturn(null);
    when(l2.probablyWantKey(key, salted)).thenReturn(true);
    when(l2.getRequestsForKey(key, salted, clientContext)).thenReturn(null);

    tracker.addPendingKeys(l1);
    tracker.addPendingKeys(l2);

    SendableGet[] out = tracker.requestsForKey(key, clientContext);
    assertNotNull(out);
    assertEquals(2, out.length);
  }

  @Test
  void requestsForKey_noMatches_returnsNull() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    NodeCHK key = newCHK(bytes(8));
    assertNull(tracker.requestsForKey(key, clientContext));
  }

  @Test
  void tripPendingKey_typeMismatch_returnsFalse() {
    ClientRequestScheduler sched = newScheduler(false, false); // CHK scheduler
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    NodeSSK key = newSSK(bytes(9), bytes(10));
    assertFalse(tracker.tripPendingKey(key, mock(KeyBlock.class), clientContext));
  }

  @Test
  void tripPendingKey_handlesMatches_andRemovesEmptyListeners() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    byte[] rk = bytes(11);
    NodeCHK key = newCHK(rk);
    byte[] salted = tracker.saltKey(key);

    // Single-key listener that handles and becomes empty
    HasKeyListener owner1 = mock(HasKeyListener.class);
    when(owner1.getWantedKey()).thenReturn(rk);
    KeyListener l1 = mock(KeyListener.class);
    when(l1.getHasKeyListener()).thenReturn(owner1);
    when(l1.getWantedKey()).thenReturn(rk);
    when(l1.probablyWantKey(key, salted)).thenReturn(true);
    KeyBlock block = mock(KeyBlock.class);
    when(l1.handleBlock(key, salted, block, clientContext)).thenReturn(true);
    when(l1.isEmpty()).thenReturn(true);

    // List listener that does not handle and stays
    KeyListener l2 = mock(KeyListener.class);
    when(l2.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(l2.getWantedKey()).thenReturn(null);
    when(l2.probablyWantKey(key, salted)).thenReturn(true);
    when(l2.handleBlock(key, salted, block, clientContext)).thenReturn(false);
    when(l2.isEmpty()).thenReturn(false);

    tracker.addPendingKeys(l1);
    tracker.addPendingKeys(l2);

    boolean handled = tracker.tripPendingKey(key, block, clientContext);
    assertTrue(handled, "At least one listener handled the block");

    // l1 should have been removed due to isEmpty()
    verify(l1, times(2)).onRemove();
    assertTrue(tracker.anyProbablyWantKey(key, clientContext)); // l2 still present
  }

  @Test
  void countWaitingKeys_sumsBothCollections() {
    ClientRequestScheduler sched = newScheduler(false, false);
    KeyListenerTracker tracker =
        new KeyListenerTracker(false, false, false, random, sched, GLOBAL_SALT, false);

    // Single-key mapping with one listener
    HasKeyListener owner1 = mock(HasKeyListener.class);
    byte[] k1 = bytes(12);
    when(owner1.getWantedKey()).thenReturn(k1);
    KeyListener a = mock(KeyListener.class);
    when(a.getHasKeyListener()).thenReturn(owner1);
    when(a.getWantedKey()).thenReturn(k1);
    when(a.countKeys()).thenReturn(5L);
    tracker.addPendingKeys(a);

    // Single-key mapping with two listeners
    HasKeyListener owner2 = mock(HasKeyListener.class);
    byte[] k2 = bytes(13);
    when(owner2.getWantedKey()).thenReturn(k2);
    KeyListener b = mock(KeyListener.class);
    when(b.getHasKeyListener()).thenReturn(owner2);
    when(b.getWantedKey()).thenReturn(k2);
    when(b.countKeys()).thenReturn(7L);
    tracker.addPendingKeys(b);
    KeyListener c = mock(KeyListener.class);
    when(c.getHasKeyListener()).thenReturn(owner2);
    when(c.getWantedKey()).thenReturn(k2);
    when(c.countKeys()).thenReturn(3L);
    tracker.addPendingKeys(c);

    // List listener
    KeyListener d = mock(KeyListener.class);
    when(d.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
    when(d.getWantedKey()).thenReturn(null);
    when(d.countKeys()).thenReturn(9L);
    tracker.addPendingKeys(d);

    assertEquals(24L, tracker.countWaitingKeys());
  }

  @Test
  void toString_containsTypeHints_andPersistentFlag() {
    ClientRequestScheduler sched1 = newScheduler(true, false);
    KeyListenerTracker insertChk =
        new KeyListenerTracker(true, false, false, random, sched1, GLOBAL_SALT, true);
    String s1 = insertChk.toString();
    assertTrue(s1.contains("insert:"));
    assertTrue(s1.contains("CHK"));

    ClientRequestScheduler sched2 = newScheduler(false, true);
    KeyListenerTracker getSsk =
        new KeyListenerTracker(false, true, false, random, sched2, GLOBAL_SALT, false);
    String s2 = getSsk.toString();
    assertFalse(s2.contains("insert:"));
    assertTrue(s2.contains("SSK"));

    assertTrue(insertChk.persistent());
    assertFalse(getSsk.persistent());
  }
}
