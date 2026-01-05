package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LocationManagerTest {

  private static LocationManager newLM(RandomSource r, Node node) {
    return new LocationManager(r, node);
  }

  @Test
  @DisplayName("setLocation_whenValid_updates_and_getLocation_returns_value")
  void setLocation_whenValid_updates_and_getLocation_returns_value() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);

    // Act
    lm.setLocation(0.0);

    // Assert
    assertEquals(0.0, lm.getLocation());

    // Act 2: boundary 1.0 is valid
    lm.setLocation(1.0);
    assertEquals(1.0, lm.getLocation());
  }

  @Test
  @DisplayName("setLocation_whenInvalid_doesNotChange_location")
  void setLocation_whenInvalid_doesNotChange_location() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);
    lm.setLocation(0.5);

    // Act
    lm.setLocation(-0.1); // invalid

    // Assert
    assertEquals(0.5, lm.getLocation());
  }

  @Test
  @DisplayName("updateLocationChangeSession_whenCrossingZero_wraps_and_accumulates")
  void updateLocationChangeSession_whenCrossingZero_wraps_and_accumulates() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);
    lm.setLocation(0.95);

    // Act: 0.95 -> 0.05 is +0.10 in circular space
    lm.updateLocationChangeSession(0.05);

    // Assert
    assertEquals(0.10, lm.getLocChangeSession(), 1e-9);

    // Act 2: from old 0.95 -> 0.25 is +0.30; total now +0.40
    lm.updateLocationChangeSession(0.25);
    assertEquals(0.40, lm.getLocChangeSession(), 1e-9);
  }

  @Test
  @DisplayName("getSendSwapInterval_defaults_to_bootstrap_interval_within_bounds")
  void getSendSwapInterval_defaults_to_bootstrap_interval_within_bounds() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);

    // Act
    long interval = lm.getSendSwapInterval();

    // Assert
    assertEquals(LocationManager.SEND_SWAP_INTERVAL, interval);
    assertTrue(interval >= LocationManager.MIN_SWAP_TIME);
    assertTrue(interval <= LocationManager.MAX_SWAP_TIME);
  }

  @Test
  @DisplayName("swappingDisabled_reflects_opennet_state_from_Node")
  void swappingDisabled_reflects_opennet_state_from_Node() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    // opennet enabled -> swapping disabled
    when(node.network()).thenReturn(network);
    doReturn(true).when(network).isOpennetEnabled();
    LocationManager lm = newLM(r, node);

    // Act & Assert
    assertTrue(lm.swappingDisabled());

    // Arrange 2: opennet disabled -> swapping allowed
    doReturn(false).when(network).isOpennetEnabled();
    assertFalse(lm.swappingDisabled());
  }

  @Test
  @DisplayName("getPitchBlackPrefix_returns_expected_prefix")
  void getPitchBlackPrefix_returns_expected_prefix() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);

    // Act
    String s = lm.getPitchBlackPrefix("abc");

    // Assert
    assertEquals(LocationManager.FOIL_PITCH_BLACK_ATTACK_PREFIX + "abc", s);
  }

  @Test
  @DisplayName("extractLocs_whenIndicateBackoff_false_returns_raw_locations")
  void extractLocs_whenIndicateBackoff_false_returns_raw_locations() {
    // Arrange
    PeerNode p1 = mock(PeerNode.class);
    PeerNode p2 = mock(PeerNode.class);
    doReturn(0.2).when(p1).getLocation();
    doReturn(0.8).when(p2).getLocation();

    // Act
    double[] out = LocationManager.extractLocs(new PeerNode[] {p1, p2}, false);

    // Assert
    assertArrayEquals(new double[] {0.2, 0.8}, out, 1e-12);
  }

  @Test
  @DisplayName("extractLocs_whenIndicateBackoff_true_applies_encoding")
  void extractLocs_whenIndicateBackoff_true_applies_encoding() {
    // Arrange
    PeerNode p1 = mock(PeerNode.class);
    PeerNode p2 = mock(PeerNode.class);
    doReturn(0.2).when(p1).getLocation();
    doReturn(0.8).when(p2).getLocation();
    doReturn(true).when(p1).isRoutingBackedOffEither();
    doReturn(false).when(p2).isRoutingBackedOffEither();

    // Act
    double[] out = LocationManager.extractLocs(new PeerNode[] {p1, p2}, true);

    // Assert: backed off -> +1; not backed off -> -1 - loc
    assertArrayEquals(new double[] {1.2, -1.8}, out, 1e-12);
  }

  @Test
  @DisplayName("extractUIDs_returns_array_with_values (mocks default to 0)")
  void extractUIDs_returns_array_with_values_mocks_default_zero() {
    // Arrange
    PeerNode p1 = mock(PeerNode.class);
    PeerNode p2 = mock(PeerNode.class);

    // Act
    long[] uids = LocationManager.extractUIDs(new PeerNode[] {p1, p2});

    // Assert: length matches; mocked abstract class yields default zero field values
    assertArrayEquals(new long[] {0L, 0L}, uids);
  }

  @Test
  @DisplayName("clearOldSwapChains_removes_items_older_than_timeout")
  void clearOldSwapChains_removes_items_older_than_timeout() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);

    // Prepare an old RecentlyForwardedItem
    PeerNode from = mock(PeerNode.class);
    PeerNode to = mock(PeerNode.class);
    LocationManager.RecentlyForwardedItem item =
        new LocationManager.RecentlyForwardedItem(1L, 2L, from, to);

    // Force age beyond threshold
    item.lastMessageTime = System.currentTimeMillis() - (LocationManager.TIMEOUT * 2) - 1;

    // Insert into the map under both keys (mirrors addForwardedItem behavior)
    lm.recentlyForwardedIDs.put(1L, item);
    lm.recentlyForwardedIDs.put(2L, item);

    // Act
    lm.clearOldSwapChains();

    // Assert
    assertTrue(lm.recentlyForwardedIDs.isEmpty());
  }

  @Test
  @DisplayName("lostOrRestartedNode_removes_matching_items_and_sends_reject_to_sender")
  void lostOrRestartedNode_removes_matching_items_and_sends_reject_to_sender()
      throws NotConnectedException {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);

    PeerNode sender = mock(PeerNode.class);
    PeerNode routedTo = mock(PeerNode.class);
    PeerNode otherRoute = mock(PeerNode.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(sender.transport()).thenReturn(transport);

    LocationManager.RecentlyForwardedItem itemKept =
        new LocationManager.RecentlyForwardedItem(10L, 11L, sender, otherRoute);
    itemKept.successfullyForwarded = true;

    LocationManager.RecentlyForwardedItem itemRemoved =
        new LocationManager.RecentlyForwardedItem(20L, 21L, sender, routedTo);
    itemRemoved.successfullyForwarded = true;

    // Populate table under both keys for each item
    lm.recentlyForwardedIDs.put(10L, itemKept);
    lm.recentlyForwardedIDs.put(11L, itemKept);
    lm.recentlyForwardedIDs.put(20L, itemRemoved);
    lm.recentlyForwardedIDs.put(21L, itemRemoved);

    // Stub sender.sendAsync to succeed and return null
    doReturn(null).when(transport).sendAsync(any(Message.class), any(), any());

    // Act
    lm.lostOrRestartedNode(routedTo);

    // Assert: only the matching item was removed; kept item remains
    Map<Long, LocationManager.RecentlyForwardedItem> table = lm.recentlyForwardedIDs;
    assertTrue(table.containsValue(itemKept));
    assertFalse(table.containsValue(itemRemoved));

    // And two rejections were sent back (duplicate map entries for the same item)
    verify(transport, times(2)).sendAsync(any(Message.class), any(), any());
  }

  @Test
  @DisplayName("knownLocations_register_and_query_by_timestamp")
  void knownLocations_register_and_query_by_timestamp() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager lm = newLM(r, node);

    long before = System.currentTimeMillis();
    long ts = before - 1; // strictly before any registration below

    // Act: register unique locations
    lm.registerKnownLocation(0.25);
    lm.registerKnownLocation(0.75);

    // Assert: count and pairs after timestamp
    int estimate = lm.getNetworkSizeEstimate(ts);
    assertEquals(2, estimate);

    Object[] pairs = lm.getKnownLocations(ts);
    assertNotNull(pairs);

    Double[] locs = (Double[]) pairs[0];
    Long[] times = (Long[]) pairs[1];
    assertEquals(2, locs.length);
    assertEquals(2, times.length);

    // Ensure values are present (order is by time; we ignore exact ordering here)
    boolean hasFirst = (Double.compare(locs[0], 0.25) == 0) || (Double.compare(locs[1], 0.25) == 0);
    boolean hasSecond =
        (Double.compare(locs[0], 0.75) == 0) || (Double.compare(locs[1], 0.75) == 0);
    assertTrue(hasFirst && hasSecond);

    // And timestamps are greater than our lower bound
    assertTrue(times[0] > ts);
    assertTrue(times[1] > ts);
  }

  @Test
  @DisplayName("byteCounters_delegate_to_NodeStats")
  void byteCounters_delegate_to_NodeStats() {
    // Arrange
    RandomSource r = mock(RandomSource.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeStats stats = mock(NodeStats.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(stats).when(network).stats();
    LocationManager lm = newLM(r, node);

    // Act
    lm.receivedBytes(7);
    lm.sentBytes(11);

    // Assert
    verify(stats).swappingReceivedBytes(7);
    verify(stats).swappingSentBytes(11);
  }

  @Test
  @DisplayName("clock_set_and_get_for_testing_roundtrip")
  void clock_set_and_get_for_testing_roundtrip() {
    // Arrange
    Clock original = LocationManager.getClockForTesting();
    try {
      Clock fixed = Clock.fixed(Instant.parse("2024-01-01T00:00:00Z"), ZoneOffset.UTC);

      // Act
      LocationManager.setClockForTesting(fixed);

      // Assert
      assertEquals(fixed, LocationManager.getClockForTesting());
    } finally {
      // Restore the global static to avoid side effects on other tests
      LocationManager.setClockForTesting(original);
    }
  }

  // --- no helpers needed ---
}
