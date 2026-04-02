package network.crypta.node;

import java.util.List;
import java.util.Set;
import network.crypta.keys.Key;

/**
 * Immutable parameter bundle for peer-routing selection decisions.
 *
 * <p>This record centralizes the inputs required by the routing selector so call sites can pass a
 * single, self-describing value instead of long argument lists. Callers populate the request
 * origin, the set of already routed peers, and policy flags that control distance checks, backoff
 * behavior, and timeout handling. The record performs no validation or defensive copying; it simply
 * captures the values supplied at construction. Treat the referenced collections as read-only for
 * the life of a selection and keep the time-based values consistent with the selector's clock.
 *
 * <p>Because instances are immutable, they are safe to share across threads as long as the
 * contained collections are not mutated concurrently. Typical usage is to construct a new instance
 * per routing decision, then pass it to {@link
 * PeerRoutingSelector#closerPeer(PeerRoutingSelectionParams)}.
 *
 * <ul>
 *   <li>Bundles request context, routing limits, and policy flags in one value.
 *   <li>Maintains selection timing inputs without imposing defaults.
 *   <li>Supports optional reporting of recently failed outcomes.
 * </ul>
 *
 * <pre>{@code
 * PeerRoutingSelectionParams params =
 *     new PeerRoutingSelectionParams(origin, routedTo, target, true, false, -1,
 *         null, 2.0, key, htl, 0L, isLocal, realTime, null, false, now, false);
 * PeerNode nextHop = selector.closerPeer(params);
 * }</pre>
 *
 * @param origin origin peer for this routing decision, or {@code null} for local originators
 * @param routedTo peers already routed to for this request, used to avoid loops
 * @param target target location on the ring, expressed in normalized location units
 * @param ignoreSelf whether to ignore the local node when comparing distance to target
 * @param calculateMisrouting whether to report misrouting statistics during selection
 * @param minVersion minimum acceptable peer build version, inclusive; non-positive disables checks
 * @param addUnpickedLocsTo optional list to collect unpicked candidate locations, or {@code null}
 * @param maxDistance maximum allowable distance from {@code target}, in normalized units
 * @param key failure-table key used for timeout tracking, or {@code null} when disabled
 * @param outgoingHTL hop-to-live value for the outgoing request, in hops
 * @param ignoreBackoffUnder backoff window to ignore, in milliseconds from the current time
 * @param isLocal whether the request originated locally, affecting policy choices
 * @param realTime whether to enforce real-time routing constraints and backoff rules
 * @param recentlyFailed optional holder for recently failed timing feedback, or {@code null}
 * @param ignoreTimeout whether to bypass timeout-based exclusion checks for candidates
 * @param now current time in milliseconds used for timeout comparisons and scheduling
 * @param newLoadManagement whether to apply new load-management heuristics to candidates
 * @see PeerRoutingSelector#closerPeer(PeerRoutingSelectionParams)
 */
public record PeerRoutingSelectionParams(
    PeerNode origin,
    Set<PeerNode> routedTo,
    double target,
    boolean ignoreSelf,
    boolean calculateMisrouting,
    int minVersion,
    List<Double> addUnpickedLocsTo,
    double maxDistance,
    Key key,
    short outgoingHTL,
    long ignoreBackoffUnder,
    boolean isLocal,
    boolean realTime,
    RecentlyFailedReturn recentlyFailed,
    boolean ignoreTimeout,
    long now,
    boolean newLoadManagement) {}
