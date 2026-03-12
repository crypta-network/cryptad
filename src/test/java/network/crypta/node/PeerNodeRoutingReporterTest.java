package network.crypta.node;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;
import network.crypta.support.math.RunningAverage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeRoutingReporterTest {

  @Test
  void reportRoutedTo_whenNodeStatsNull_doesNotThrow() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerNode peerNode = mock(PeerNode.class);
    when(node.network().stats()).thenReturn(null);
    when(peerNode.getLocation()).thenReturn(0.7);

    assertDoesNotThrow(
        () ->
            PeerNodeRoutingReporter.reportRoutedTo(
                node,
                peerNode,
                new PeerNodeRoutingReportParams(0.1, true, true, null, Set.of(), 1)));
  }

  @ParameterizedTest
  @CsvSource({"true,true", "true,false", "false,true", "false,false"})
  void reportRoutedTo_whenNoPeerLocationsPublished_reportsOriginalDistance(
      boolean isLocal, boolean realTime) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerNode peerNode = mock(PeerNode.class);
    RunningAverage overall = mock(RunningAverage.class);
    RunningAverage local = mock(RunningAverage.class);
    RunningAverage remote = mock(RunningAverage.class);
    RunningAverage rt = mock(RunningAverage.class);
    RunningAverage bulk = mock(RunningAverage.class);
    NodeStats stats = mockStats(overall, local, remote, rt, bulk);

    double target = 0.25;
    double peerLocation = 0.85;
    double expectedDistance = Location.distance(target, peerLocation);

    when(node.network().location()).thenReturn(0.4);
    when(node.network().stats()).thenReturn(stats);
    when(peerNode.getLocation()).thenReturn(peerLocation);
    when(peerNode.shallWeRouteAccordingToOurPeersLocation(2)).thenReturn(false);

    PeerNodeRoutingReporter.reportRoutedTo(
        node,
        peerNode,
        new PeerNodeRoutingReportParams(target, isLocal, realTime, null, Set.of(), 2));

    verify(overall).report(expectedDistance);
    if (isLocal) {
      verify(local).report(expectedDistance);
      verifyNoInteractions(remote);
    } else {
      verify(remote).report(expectedDistance);
      verifyNoInteractions(local);
    }
    if (realTime) {
      verify(rt).report(expectedDistance);
      verifyNoInteractions(bulk);
    } else {
      verify(bulk).report(expectedDistance);
      verifyNoInteractions(rt);
    }
  }

  @Test
  void reportRoutedTo_whenPeerPublishesCloserLocation_reportsCloserDistance() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerNode peerNode = mock(PeerNode.class);
    RunningAverage overall = mock(RunningAverage.class);
    RunningAverage local = mock(RunningAverage.class);
    RunningAverage remote = mock(RunningAverage.class);
    RunningAverage rt = mock(RunningAverage.class);
    RunningAverage bulk = mock(RunningAverage.class);
    NodeStats stats = mockStats(overall, local, remote, rt, bulk);

    double target = 0.2;
    double peerLocation = 0.9;
    double closestLocation = 0.25;
    double expectedDistance = Location.distance(target, closestLocation);

    when(node.network().location()).thenReturn(0.1);
    when(node.network().stats()).thenReturn(stats);
    when(peerNode.getLocation()).thenReturn(peerLocation);
    when(peerNode.shallWeRouteAccordingToOurPeersLocation(3)).thenReturn(true);
    when(peerNode.getClosestPeerLocation(eq(target), anySet())).thenReturn(closestLocation);

    PeerNodeRoutingReporter.reportRoutedTo(
        node, peerNode, new PeerNodeRoutingReportParams(target, true, true, null, Set.of(), 3));

    verify(overall).report(expectedDistance);
    verify(local).report(expectedDistance);
    verify(rt).report(expectedDistance);
    verifyNoInteractions(remote);
    verifyNoInteractions(bulk);
  }

  @ParameterizedTest
  @CsvSource({"NaN", "0.6"})
  void reportRoutedTo_whenClosestLocationMissingOrWorse_keepsOriginalDistance(
      double closestLocation) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerNode peerNode = mock(PeerNode.class);
    RunningAverage overall = mock(RunningAverage.class);
    RunningAverage local = mock(RunningAverage.class);
    RunningAverage remote = mock(RunningAverage.class);
    RunningAverage rt = mock(RunningAverage.class);
    RunningAverage bulk = mock(RunningAverage.class);
    NodeStats stats = mockStats(overall, local, remote, rt, bulk);

    double target = 0.2;
    double peerLocation = 0.9;
    double expectedDistance = Location.distance(target, peerLocation);

    when(node.network().location()).thenReturn(0.1);
    when(node.network().stats()).thenReturn(stats);
    when(peerNode.getLocation()).thenReturn(peerLocation);
    when(peerNode.shallWeRouteAccordingToOurPeersLocation(4)).thenReturn(true);
    when(peerNode.getClosestPeerLocation(eq(target), anySet())).thenReturn(closestLocation);

    PeerNodeRoutingReporter.reportRoutedTo(
        node, peerNode, new PeerNodeRoutingReportParams(target, true, false, null, Set.of(), 4));

    verify(overall).report(expectedDistance);
    verify(local).report(expectedDistance);
    verify(bulk).report(expectedDistance);
    verifyNoInteractions(remote);
    verifyNoInteractions(rt);
  }

  @Test
  void reportRoutedTo_whenPeerLocationInvalid_throwsIllegalArgumentException() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerNode peerNode = mock(PeerNode.class);
    RunningAverage overall = mock(RunningAverage.class);
    RunningAverage local = mock(RunningAverage.class);
    RunningAverage remote = mock(RunningAverage.class);
    RunningAverage rt = mock(RunningAverage.class);
    RunningAverage bulk = mock(RunningAverage.class);
    Set<PeerNode> routedTo = Set.of();
    double target = 0.1;
    PeerNodeRoutingReportParams params =
        new PeerNodeRoutingReportParams(target, true, true, null, routedTo, 5);
    when(peerNode.getLocation()).thenReturn(-0.5);

    assertThrows(
        IllegalArgumentException.class,
        () -> PeerNodeRoutingReporter.reportRoutedTo(node, peerNode, params));

    verifyNoInteractions(overall, local, remote, rt, bulk);
  }

  @Test
  void reportRoutedTo_whenPeerPublishesLocations_passesExcludeSetWithSelfPrevAndRoutedTo() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerNode peerNode = mock(PeerNode.class);
    PeerNode prev = mock(PeerNode.class);
    PeerNode routedToA = mock(PeerNode.class);
    PeerNode routedToB = mock(PeerNode.class);
    RunningAverage overall = mock(RunningAverage.class);
    RunningAverage local = mock(RunningAverage.class);
    RunningAverage remote = mock(RunningAverage.class);
    RunningAverage rt = mock(RunningAverage.class);
    RunningAverage bulk = mock(RunningAverage.class);
    NodeStats stats = mockStats(overall, local, remote, rt, bulk);

    double myLocation = 0.12;
    double prevLocation = 0.33;
    double routedToLocationA = 0.55;
    double routedToLocationB = 0.77;
    double target = 0.2;

    when(node.network().location()).thenReturn(myLocation);
    when(node.network().stats()).thenReturn(stats);
    when(peerNode.getLocation()).thenReturn(0.9);
    when(peerNode.shallWeRouteAccordingToOurPeersLocation(6)).thenReturn(true);
    when(prev.getLocation()).thenReturn(prevLocation);
    when(routedToA.getLocation()).thenReturn(routedToLocationA);
    when(routedToB.getLocation()).thenReturn(routedToLocationB);
    when(peerNode.getClosestPeerLocation(eq(target), anySet())).thenReturn(Double.NaN);

    Set<PeerNode> routedTo = new HashSet<>();
    routedTo.add(routedToA);
    routedTo.add(routedToB);

    PeerNodeRoutingReporter.reportRoutedTo(
        node, peerNode, new PeerNodeRoutingReportParams(target, false, true, prev, routedTo, 6));

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Set<Double>> captor =
        ArgumentCaptor.forClass((Class<Set<Double>>) (Class<?>) Set.class);
    verify(peerNode).getClosestPeerLocation(eq(target), captor.capture());
    Set<Double> excludeLocations = captor.getValue();

    assertEquals(4, excludeLocations.size());
    assertTrue(excludeLocations.contains(myLocation));
    assertTrue(excludeLocations.contains(prevLocation));
    assertTrue(excludeLocations.contains(routedToLocationA));
    assertTrue(excludeLocations.contains(routedToLocationB));

    verify(overall).report(Location.distance(target, 0.9));
    verify(remote).report(Location.distance(target, 0.9));
    verify(rt).report(Location.distance(target, 0.9));
    verifyNoInteractions(local);
    verifyNoInteractions(bulk);
  }

  private static NodeStats mockStats(
      RunningAverage overall,
      RunningAverage local,
      RunningAverage remote,
      RunningAverage rt,
      RunningAverage bulk) {
    NodeStats stats = mock(NodeStats.class);
    setField(stats, "routingMissDistanceOverall", overall);
    setField(stats, "routingMissDistanceLocal", local);
    setField(stats, "routingMissDistanceRemote", remote);
    setField(stats, "routingMissDistanceRT", rt);
    setField(stats, "routingMissDistanceBulk", bulk);
    return stats;
  }

  private static void setField(NodeStats stats, String fieldName, Object value) {
    try {
      Field field = NodeStats.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(stats, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed setting " + fieldName, e);
    }
  }
}
