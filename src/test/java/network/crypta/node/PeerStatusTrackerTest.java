package network.crypta.node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link PeerStatusTracker}.
 *
 * <p>Note: {@code PeerStatusTracker} is package-private, so this test lives in the same package.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class PeerStatusTrackerTest {

  private static PeerNode mockPeer(String id) {
    PeerNode n = Mockito.mock(PeerNode.class, Mockito.withSettings().verboseLogging());
    Mockito.when(n.getIdentityString()).thenReturn(id);
    Mockito.when(n.shortToString()).thenReturn("peer-" + id);
    return n;
  }

  @Test
  void statusSize_whenUnknownStatus_returnsZero() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();

    int size = tracker.statusSize("S-unknown");

    assertEquals(0, size);
  }

  @Test
  void addStatus_whenNewStatus_addsPeerAndKeyPresent() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");

    tracker.addStatus("S1", a, true);

    assertEquals(1, tracker.statusSize("S1"));
    List<String> keys = new ArrayList<>();
    tracker.addStatusList(keys);
    assertTrue(keys.contains("S1"));
  }

  @Test
  void addStatus_whenDuplicatePeerSameStatus_noChangeAndNoDuplicate() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    tracker.addStatus("S1", a, true);

    tracker.addStatus("S1", a, false); // duplicate; should be ignored

    assertEquals(1, tracker.statusSize("S1"));
    List<String> keys = new ArrayList<>();
    tracker.addStatusList(keys);
    assertIterableEquals(List.of("S1"), keys);
  }

  @Test
  void addStatus_whenAddingDifferentPeerToExistingStatus_appendsToExistingSet() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    PeerNode b = mockPeer("B");
    tracker.addStatus("S1", a, true);

    tracker.addStatus("S1", b, true); // implementation appends into the existing set

    assertEquals(2, tracker.statusSize("S1"));
    // Remove one peer; key should still exist with the other one
    tracker.removeStatus("S1", b, true);
    assertEquals(1, tracker.statusSize("S1"));
  }

  @Test
  void removeStatus_whenPeerPresent_removesAndDeletesKeyWhenEmpty() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    tracker.addStatus("S1", a, true);

    tracker.removeStatus("S1", a, true);

    assertEquals(0, tracker.statusSize("S1"));
    List<String> keys = new ArrayList<>();
    tracker.addStatusList(keys);
    assertTrue(keys.isEmpty());
  }

  @Test
  void removeStatus_whenPeerNotPresent_keepsSetUnchanged() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    PeerNode b = mockPeer("B");
    tracker.addStatus("S1", a, true);

    tracker.removeStatus("S1", b, false); // not present; ignored

    assertEquals(1, tracker.statusSize("S1"));
    List<String> keys = new ArrayList<>();
    tracker.addStatusList(keys);
    assertIterableEquals(List.of("S1"), keys);
  }

  @Test
  void changePeerNodeStatus_whenMovingSolePeer_movesFromOldToNew() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    tracker.addStatus("OLD", a, true);

    tracker.changePeerNodeStatus(a, "OLD", "NEW", true);

    assertEquals(0, tracker.statusSize("OLD"));
    assertEquals(1, tracker.statusSize("NEW"));
    List<String> keys = new ArrayList<>();
    tracker.addStatusList(keys);
    assertIterableEquals(List.of("NEW"), keys);
  }

  @Test
  void changePeerNodeStatus_whenNewStatusHasOtherPeers_preservesExistingPeers() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    PeerNode x = mockPeer("X");
    PeerNode y = mockPeer("Y");

    tracker.addStatus("A", a, true);
    tracker.addStatus("A", x, true);
    tracker.addStatus("B", y, true);

    tracker.changePeerNodeStatus(a, "A", "B", true);

    // After change: A retains x; B contains both y and a
    assertEquals(1, tracker.statusSize("A"));
    assertEquals(2, tracker.statusSize("B"));

    // Remove 'a' and ensure 'y' remains tracked under B
    tracker.removeStatus("B", a, true);
    assertEquals(1, tracker.statusSize("B"));
  }

  @Test
  void addStatusList_whenExistingListHasElements_appendsKeys() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");
    PeerNode b = mockPeer("B");
    tracker.addStatus("S1", a, true);
    tracker.addStatus("S2", b, true);

    List<String> target = new ArrayList<>(List.of("seed"));
    tracker.addStatusList(target);

    assertTrue(target.containsAll(Arrays.asList("seed", "S1", "S2")));
    assertEquals(3, target.size());
  }

  @Test
  void addStatus_withNullStatusKey_allowedAndTracked() {
    PeerStatusTracker<String> tracker = new PeerStatusTracker<>();
    PeerNode a = mockPeer("A");

    tracker.addStatus(null, a, true);

    assertEquals(1, tracker.statusSize(null));
    List<String> keys = new ArrayList<>();
    tracker.addStatusList(keys);
    // List will contain a null entry for the status key
    assertTrue(keys.contains(null));
  }
}
