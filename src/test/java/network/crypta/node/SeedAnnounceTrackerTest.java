package network.crypta.node;

import java.net.InetAddress;
import java.util.List;
import java.util.Random;
import network.crypta.io.comm.Peer;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Tests for {@link SeedAnnounceTracker}. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // method naming per instructions
class SeedAnnounceTrackerTest {

  private SeedAnnounceTracker tracker;

  @Mock private SeedClientPeerNode peerNode;

  @BeforeEach
  void setUp() throws Exception {
    tracker = new SeedAnnounceTracker();
    // Default peer with stable IP/port and fresh version; specific tests may override.
    InetAddress ip = InetAddress.getAllByName("203.0.113.1")[0]; // TEST-NET-3 address
    Peer peer = new Peer(ip, 12345);
    lenient().when(peerNode.getPeer()).thenReturn(peer);
    lenient().when(peerNode.getBuildNumber()).thenReturn(100);
    lenient().when(peerNode.isUnroutableOlderVersion()).thenReturn(false);
  }

  @Test
  void acceptAnnounce_whenNewIP_expectAcceptedAndCountsAndVersion() {
    // Arrange
    Random rng = new Random(42); // not used for first-time IP

    // Act
    boolean accepted = tracker.acceptAnnounce(peerNode, rng);

    // Assert
    assertTrue(accepted, "First announce from new IP should be accepted");
    Table table = renderStats();
    assertEquals(1, table.rows());
    assertEquals("0", table.cell(0, Col.CONNECTS));
    assertEquals("1", table.cell(0, Col.ANNOUNCE));
    assertEquals("1", table.cell(0, Col.ACCEPTED));
    assertEquals("0", table.cell(0, Col.COMPLETED));
    assertEquals("0", table.cell(0, Col.FORWARDED));
    assertEquals("100", table.cell(0, Col.VERSION));
  }

  @Test
  void rejectedAnnounce_whenVerZero_expectAnnounceIncrementAndVersionUnchanged() {
    // Arrange
    tracker.acceptAnnounce(peerNode, new Random(1));
    when(peerNode.getBuildNumber()).thenReturn(0); // ignored by setVersion()

    // Act
    tracker.rejectedAnnounce(peerNode);

    // Assert
    Table table = renderStats();
    assertEquals("0", table.cell(0, Col.CONNECTS));
    assertEquals("2", table.cell(0, Col.ANNOUNCE));
    assertEquals("1", table.cell(0, Col.ACCEPTED));
    assertEquals("0", table.cell(0, Col.COMPLETED));
    assertEquals("0", table.cell(0, Col.FORWARDED));
    assertEquals(
        "100", table.cell(0, Col.VERSION), "version should remain at first positive value");
  }

  @Test
  void onConnectSeed_whenCalled_expectConnectionsIncremented() {
    // Arrange
    when(peerNode.getBuildNumber()).thenReturn(321);

    // Act
    tracker.onConnectSeed(peerNode);

    // Assert
    Table table = renderStats();
    assertEquals(1, table.rows());
    assertEquals("1", table.cell(0, Col.CONNECTS));
    assertEquals("0", table.cell(0, Col.ANNOUNCE));
    assertEquals("0", table.cell(0, Col.ACCEPTED));
    assertEquals("0", table.cell(0, Col.COMPLETED));
    assertEquals("0", table.cell(0, Col.FORWARDED));
    assertEquals("321", table.cell(0, Col.VERSION));
  }

  @Test
  void completedAnnounce_whenForwarded_expectCompletedAndForwardedIncremented() {
    // Arrange
    tracker.acceptAnnounce(peerNode, new Random(2));

    // Act
    tracker.completedAnnounce(peerNode, 7);

    // Assert
    Table table = renderStats();
    assertEquals("1", table.cell(0, Col.ACCEPTED));
    assertEquals("1", table.cell(0, Col.COMPLETED));
    assertEquals("7", table.cell(0, Col.FORWARDED));
  }

  @Test
  void acceptAnnounce_whenOldVersionAndRefsGt5_andRngReject_expectRejectedAndNoCountersChanged() {
    // Arrange: build up forwarded refs > 5
    for (int i = 0; i < 6; i++) tracker.completedAnnounce(peerNode, 1);
    when(peerNode.isUnroutableOlderVersion()).thenReturn(true);
    Random rng = mock(Random.class);
    when(rng.nextInt(5)).thenReturn(1); // non-zero -> reject

    // Act
    boolean accepted = tracker.acceptAnnounce(peerNode, rng);

    // Assert
    assertFalse(accepted);
    Table table = renderStats();
    assertEquals("0", table.cell(0, Col.ANNOUNCE));
    assertEquals("0", table.cell(0, Col.ACCEPTED));
    assertEquals("6", table.cell(0, Col.COMPLETED));
    assertEquals("6", table.cell(0, Col.FORWARDED));
  }

  @Test
  void acceptAnnounce_whenOldVersionAndRefsGt5_andRngZero_expectAccepted() {
    // Arrange: forwarded refs > 5
    for (int i = 0; i < 6; i++) tracker.completedAnnounce(peerNode, 1);
    when(peerNode.isUnroutableOlderVersion()).thenReturn(true);
    Random rng = mock(Random.class);
    when(rng.nextInt(5)).thenReturn(0); // zero -> accept

    // Act
    boolean accepted = tracker.acceptAnnounce(peerNode, rng);

    // Assert
    assertTrue(accepted);
    Table table = renderStats();
    assertEquals("1", table.cell(0, Col.ANNOUNCE));
    assertEquals("1", table.cell(0, Col.ACCEPTED));
  }

  @Test
  void acceptAnnounce_whenRefsGt10NotOld_andRngReject_expectRejected() {
    // Arrange: forwarded refs > 10 and not old version
    for (int i = 0; i < 11; i++) tracker.completedAnnounce(peerNode, 1);
    when(peerNode.isUnroutableOlderVersion()).thenReturn(false);
    Random rng = mock(Random.class);
    when(rng.nextInt(4)).thenReturn(3); // non-zero -> reject

    // Act
    boolean accepted = tracker.acceptAnnounce(peerNode, rng);

    // Assert
    assertFalse(accepted);
    Table table = renderStats();
    assertEquals("0", table.cell(0, Col.ANNOUNCE));
    assertEquals("0", table.cell(0, Col.ACCEPTED));
  }

  @Test
  void acceptAnnounce_whenRefsGt10NotOld_andRngZero_expectAccepted() {
    // Arrange
    for (int i = 0; i < 11; i++) tracker.completedAnnounce(peerNode, 1);
    when(peerNode.isUnroutableOlderVersion()).thenReturn(false);
    Random rng = mock(Random.class);
    when(rng.nextInt(4)).thenReturn(0); // zero -> accept

    // Act
    boolean accepted = tracker.acceptAnnounce(peerNode, rng);

    // Assert
    assertTrue(accepted);
    Table table = renderStats();
    assertEquals("1", table.cell(0, Col.ANNOUNCE));
    assertEquals("1", table.cell(0, Col.ACCEPTED));
  }

  @Test
  @DisplayName("drawSeedStats with no items creates no table")
  void drawSeedStats_whenEmpty_expectNoTable() {
    HTMLNode root = new HTMLNode("div");
    tracker.drawSeedStats(root);
    assertEquals(0, elementChildren(root).size());
  }

  @Test
  void drawSeedStats_whenMultipleIPs_expectTopSortedRowsPresent() throws Exception {
    // Arrange: three different IPs with varying counts
    SeedClientPeerNode p1 = mockPeer("198.51.100.1", 10); // TEST-NET-2
    SeedClientPeerNode p2 = mockPeer("198.51.100.2", 11);
    SeedClientPeerNode p3 = mockPeer("198.51.100.3", 12);

    // p1: 5 connects
    for (int i = 0; i < 5; i++) tracker.onConnectSeed(p1);
    // p2: 3 announces (accepted)
    for (int i = 0; i < 3; i++) assertTrue(tracker.acceptAnnounce(p2, new Random(3)));
    // p3: 4 announces (accepted)
    for (int i = 0; i < 4; i++) assertTrue(tracker.acceptAnnounce(p3, new Random(4)));

    // Act
    Table table = renderStats();

    // Assert: three rows present; a = max(announce, connect) should be non-decreasing
    assertEquals(3, table.rows());
    int a0 =
        Math.max(
            Integer.parseInt(table.cell(0, Col.ANNOUNCE)),
            Integer.parseInt(table.cell(0, Col.CONNECTS)));
    int a1 =
        Math.max(
            Integer.parseInt(table.cell(1, Col.ANNOUNCE)),
            Integer.parseInt(table.cell(1, Col.CONNECTS)));
    int a2 =
        Math.max(
            Integer.parseInt(table.cell(2, Col.ANNOUNCE)),
            Integer.parseInt(table.cell(2, Col.CONNECTS)));
    assertTrue(
        a0 <= a1 && a1 <= a2, "rows should be sorted by activity ascending within top slice");
  }

  // -- Helpers -------------------------------------------------------------------------------

  private SeedClientPeerNode mockPeer(String ip, int build) throws Exception {
    SeedClientPeerNode pn = mock(SeedClientPeerNode.class);
    Peer peer = new Peer(InetAddress.getAllByName(ip)[0], 4242);
    lenient().when(pn.getPeer()).thenReturn(peer);
    lenient().when(pn.getBuildNumber()).thenReturn(build);
    lenient().when(pn.isUnroutableOlderVersion()).thenReturn(false);
    return pn;
  }

  private enum Col {
    IP(0),
    CONNECTS(1),
    ANNOUNCE(2),
    ACCEPTED(3),
    COMPLETED(4),
    FORWARDED(5),
    VERSION(6);

    final int index;

    Col(int index) {
      this.index = index;
    }
  }

  private Table renderStats() {
    HTMLNode root = new HTMLNode("div");
    tracker.drawSeedStats(root);
    List<HTMLNode> children = elementChildren(root);
    // Expect a single table with one header row followed by data rows.
    HTMLNode table = children.getFirst();
    List<HTMLNode> rows = elementChildren(table);
    // drop header row
    rows.removeFirst();
    return new Table(rows);
  }

  private static List<HTMLNode> elementChildren(HTMLNode node) {
    return node.getChildren();
  }

  private static String cellText(HTMLNode cell) {
    // <td> stores text as a single text child
    List<HTMLNode> children = cell.getChildren();
    if (!children.isEmpty() && "#".equals(children.getFirst().getName())) {
      return children.getFirst().getContent();
    }
    return cell.generateChildren();
  }

  /** Lightweight view over a rendered table. */
  private static final class Table {
    private final List<HTMLNode> rows; // each is a <tr>

    Table(List<HTMLNode> rows) {
      this.rows = rows;
    }

    int rows() {
      return rows.size();
    }

    String cell(int row, Col col) {
      HTMLNode tr = rows.get(row);
      List<HTMLNode> cells = tr.getChildren();
      return cellText(cells.get(col.index));
    }
  }
}
