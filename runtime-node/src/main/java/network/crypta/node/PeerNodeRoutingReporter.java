package network.crypta.node;

import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reporting utility that records routing miss distances for peer forwarding decisions.
 *
 * <p>This helper centralizes the calculation and reporting of routing miss distances when a node
 * forwards traffic to a peer. Callers supply the local node, the candidate peer, and context such
 * as HTL, local/remote scope, and realtime/bulk mode; the helper derives a distance in the unit
 * keyspace and reports it into the node's routing statistics. When the peer publishes additional
 * peer locations, the helper optionally adjusts the distance to the closest published location so
 * that the statistics better reflect what the peer claims about its neighborhood. The computation
 * avoids reusing locations already visited on the route by excluding the local node, the previous
 * hop, and any nodes already routed to in this attempt.
 *
 * <p>Thread-safety: this class is stateless; it relies on the thread-safety of {@link NodeStats}
 * and {@link PeerNode} implementations. The only mutable state touched is owned by the passed
 * {@link NodeStats} instance. The method is side-effecting via stats reporting but does not mutate
 * routing or peer state.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Compute baseline routing distance for a candidate peer.
 *   <li>Adjust distance when a peer provides closer published locations.
 *   <li>Report distances into overall, local/remote, and RT/bulk aggregates.
 * </ul>
 *
 * @see PeerNode
 * @see NodeStats
 * @see Location
 */
final class PeerNodeRoutingReporter {
  /**
   * Logger for routing-distance reporting diagnostics.
   *
   * <p>This logger is used only for debug-level visibility into peer-published locations and does
   * not affect routing behavior.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeRoutingReporter.class);

  /** Hidden constructor to enforce non-instantiability. */
  private PeerNodeRoutingReporter() {}

  /**
   * Record a routing miss distance for a routing decision that targets a peer.
   *
   * <p>The method computes the circular distance between the target keyspace location and the
   * peer's location. If the peer publishes additional peer locations, the distance may be reduced
   * when a closer published location is available and not excluded. The resulting distance is then
   * reported into the node's routing statistics across overall, local/remote, and realtime/bulk
   * categories. The method is not idempotent: each call records a new observation. A {@code null}
   * {@link NodeStats} short-circuits the reporting path and leaves no side effects.
   *
   * <p>Preconditions: {@code target} and all locations consulted by {@link Location#distance} must
   * be valid keyspace locations in {@code [0.0, 1.0]}. The {@code routedTo} set should contain only
   * peers with valid locations when peer-published routing is enabled.
   *
   * @param node the local node providing location and stats; must be non-null
   * @param peerNode the candidate peer whose location is evaluated; must be non-null
   * @param routingParams routing context including target, policy flags, and peer history
   * @throws IllegalArgumentException if any required location is outside {@code [0.0, 1.0]}
   */
  static void reportRoutedTo(
      Node node, PeerNode peerNode, PeerNodeRoutingReportParams routingParams) {
    double distance = Location.distance(routingParams.target(), peerNode.getLocation());

    var stats = node.network().stats();
    if (stats == null) return;

    Set<Double> excludeLocations =
        buildExcludeLocations(node, routingParams.prev(), routingParams.routedTo());
    double adjustedDistance =
        adjustDistanceForPublishedPeers(
            peerNode, routingParams.target(), routingParams.htl(), excludeLocations, distance);
    reportToStats(stats, adjustedDistance, routingParams.isLocal(), routingParams.realTime());
  }

  /**
   * Build the set of locations that should be excluded from published-peer routing.
   *
   * @param node the local node contributing its own location to exclude
   * @param prev the previous hop, or {@code null} when no previous hop exists
   * @param routedTo peers already routed to and therefore excluded
   * @return a new set containing the local, previous, and routed-to locations
   */
  private static Set<Double> buildExcludeLocations(
      Node node, PeerNode prev, Set<PeerNode> routedTo) {
    double myLoc = node.network().location();
    double prevLoc = prev != null ? prev.getLocation() : -1.0;

    Set<Double> excludeLocations = new HashSet<>();
    excludeLocations.add(myLoc);
    excludeLocations.add(prevLoc);
    for (PeerNode routedToNode : routedTo) {
      excludeLocations.add(routedToNode.getLocation());
    }
    return excludeLocations;
  }

  /**
   * Adjust the routing distance when a peer publishes locations for its neighbors.
   *
   * @param peerNode the peer providing published locations for consideration
   * @param target the target keyspace location, in the range {@code [0.0, 1.0]}
   * @param htl hop-to-live value that gates peer-published routing behavior
   * @param excludeLocations locations that must be ignored when searching for published peers
   * @param distance the current best distance before considering published locations
   * @return the adjusted distance, possibly unchanged if no closer location is found
   * @throws IllegalArgumentException if a published location is invalid for {@link
   *     Location#distance}
   */
  private static double adjustDistanceForPublishedPeers(
      PeerNode peerNode, double target, int htl, Set<Double> excludeLocations, double distance) {
    if (!peerNode.shallWeRouteAccordingToOurPeersLocation(htl)) {
      return distance;
    }
    double closest = peerNode.getClosestPeerLocation(target, excludeLocations);
    if (!Double.isNaN(closest)) {
      double newDiff = Location.distance(closest, target);
      if (newDiff < distance) {
        distance = newDiff;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "The peer {} has published his peer's locations and the closest we have found to the"
              + " target is {} away.",
          peerNode,
          distance);
    }
    return distance;
  }

  /**
   * Report a computed routing distance into the appropriate NodeStats aggregates.
   *
   * @param stats the stats instance to update; must be non-null
   * @param distance the routing miss distance to report
   * @param isLocal whether the decision is categorized as local routing
   * @param realTime whether the decision is categorized as realtime routing
   */
  private static void reportToStats(
      NodeStats stats, double distance, boolean isLocal, boolean realTime) {
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
