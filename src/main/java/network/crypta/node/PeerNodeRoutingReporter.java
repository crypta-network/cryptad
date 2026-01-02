package network.crypta.node;

import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Routing-distance reporting helper for {@link PeerNode}. */
final class PeerNodeRoutingReporter {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeRoutingReporter.class);

  private PeerNodeRoutingReporter() {}

  static void reportRoutedTo(
      Node node,
      PeerNode peerNode,
      double target,
      boolean isLocal,
      boolean realTime,
      PeerNode prev,
      Set<PeerNode> routedTo,
      int htl) {
    double distance = Location.distance(target, peerNode.getLocation());

    double myLoc = node.getLocation();
    double prevLoc = prev != null ? prev.getLocation() : -1.0;

    Set<Double> excludeLocations = new HashSet<>();
    excludeLocations.add(myLoc);
    excludeLocations.add(prevLoc);
    for (PeerNode routedToNode : routedTo) {
      excludeLocations.add(routedToNode.getLocation());
    }

    if (peerNode.shallWeRouteAccordingToOurPeersLocation(htl)) {
      double l = peerNode.getClosestPeerLocation(target, excludeLocations);
      if (!Double.isNaN(l)) {
        double newDiff = Location.distance(l, target);
        if (newDiff < distance) {
          distance = newDiff;
        }
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "The peer {} has published his peer's locations and the closest we have found to the"
                + " target is {} away.",
            peerNode,
            distance);
    }

    var stats = node.getNodeStats();
    if (stats == null) return;

    if (stats.routingMissDistanceOverall != null) {
      stats.routingMissDistanceOverall.report(distance);
    }
    var localRemote = isLocal ? stats.routingMissDistanceLocal : stats.routingMissDistanceRemote;
    if (localRemote != null) {
      localRemote.report(distance);
    }
    var rtBulk = realTime ? stats.routingMissDistanceRT : stats.routingMissDistanceBulk;
    if (rtBulk != null) {
      rtBulk.report(distance);
    }
  }
}
