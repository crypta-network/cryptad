package network.crypta.node;

import java.util.Set;

/**
 * Immutable parameter bundle for peer-routing miss distance reporting.
 *
 * <p>This record groups the routing-decision context used by {@link
 * PeerNodeRoutingReporter#reportRoutedTo(Node, PeerNode, PeerNodeRoutingReportParams)} so callers
 * can pass a single value instead of a long argument list. The record performs no validation or
 * defensive copies; callers must ensure locations are valid keyspace coordinates and the routed-to
 * set is treated as read-only for the reporting operation.
 *
 * @param target target keyspace location for the routing decision
 * @param isLocal whether this decision is classified as local routing
 * @param realTime whether this decision is classified as realtime routing
 * @param prev the previous hop peer, or {@code null} when no prior hop exists
 * @param routedTo peers already tried for this route; never {@code null}
 * @param htl hop-to-live value used to decide peer-published routing behavior
 * @see PeerNodeRoutingReporter#reportRoutedTo(Node, PeerNode, PeerNodeRoutingReportParams)
 */
public record PeerNodeRoutingReportParams(
    double target,
    boolean isLocal,
    boolean realTime,
    PeerNode prev,
    Set<PeerNode> routedTo,
    int htl) {}
