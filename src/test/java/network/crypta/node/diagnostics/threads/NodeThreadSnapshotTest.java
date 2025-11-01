package network.crypta.node.diagnostics.threads;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // test naming style
class NodeThreadSnapshotTest {

  private static NodeThreadInfo info(long id, String name) {
    return new NodeThreadInfo(id, id, 123L, name, 5, "main", "RUNNABLE");
  }

  @Test
  void constructor_whenThreadsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new NodeThreadSnapshot(null, 100));
  }

  @Test
  void constructor_whenThreadsContainsNull_throwsNullPointerException() {
    List<NodeThreadInfo> listWithNull = new ArrayList<>();
    listWithNull.add(info(1, "t1"));
    listWithNull.add(null);

    assertThrows(NullPointerException.class, () -> new NodeThreadSnapshot(listWithNull, 100));
  }

  @Test
  void getInterval_whenCalled_returnsGivenInterval() {
    NodeThreadSnapshot snap = new NodeThreadSnapshot(List.of(info(1, "t1")), 321);
    assertEquals(321, snap.getInterval());
  }

  @Test
  void getThreads_whenCalled_returnsDefensiveCopy() {
    NodeThreadSnapshot snap = new NodeThreadSnapshot(List.of(info(1, "a"), info(2, "b")), 10);

    List<NodeThreadInfo> first = snap.getThreads();
    List<NodeThreadInfo> second = snap.getThreads();

    assertNotNull(first);
    assertNotNull(second);
    assertEquals(2, first.size());
    assertEquals(2, second.size());
    assertNotSame(first, second, "Should return a new list each call");

    // Mutate the returned list and ensure it doesn't affect the snapshot
    first.add(info(3, "c"));
    assertEquals(3, first.size());
    assertEquals(2, snap.getThreads().size(), "Snapshot should remain unaffected by mutations");
  }

  @Test
  void constructor_whenOriginalListModified_snapshotUnaffected() {
    List<NodeThreadInfo> input = new ArrayList<>();
    input.add(info(1, "x"));

    NodeThreadSnapshot snap = new NodeThreadSnapshot(input, 42);
    assertEquals(1, snap.getThreads().size());

    // Mutate the original list after construction
    input.add(info(2, "y"));
    assertEquals(2, input.size());

    // Snapshot is backed by an immutable copy
    assertEquals(1, snap.getThreads().size());
  }

  @Test
  void threadsAccessor_whenModified_throwsUnsupportedOperationException() {
    NodeThreadSnapshot snap = new NodeThreadSnapshot(List.of(info(1, "a")), 7);

    List<NodeThreadInfo> unmodifiable = snap.threads();
    NodeThreadInfo elem = info(2, "b");
    assertThrows(UnsupportedOperationException.class, () -> unmodifiable.add(elem));
  }

  @Test
  void equalsAndHashCode_whenSameContent_consideredEqual() {
    List<NodeThreadInfo> l1 = List.of(info(1, "a"), info(2, "b"));
    List<NodeThreadInfo> l2 = List.of(info(1, "a"), info(2, "b"));

    NodeThreadSnapshot s1 = new NodeThreadSnapshot(l1, 100);
    NodeThreadSnapshot s2 = new NodeThreadSnapshot(l2, 100);
    NodeThreadSnapshot s3 = new NodeThreadSnapshot(List.of(info(3, "c")), 100);
    NodeThreadSnapshot s4 = new NodeThreadSnapshot(l1, 200);

    assertEquals(s1, s2);
    assertEquals(s1.hashCode(), s2.hashCode());
    assertNotEquals(s1, s3);
    assertNotEquals(s1, s4);

    String str = s1.toString();
    assertTrue(str.contains("NodeThreadSnapshot"));
    assertTrue(str.contains("interval=100"));
  }
}
