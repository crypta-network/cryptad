package network.crypta.node;

/**
 * Shared context for insert handlers derived from the original request.
 *
 * @param node node owning the handler
 * @param source upstream peer that initiated the insert
 * @param uid unique insert identifier
 * @param startTime timestamp in milliseconds when the handler was scheduled
 * @param tag insert tag guarding UID lifecycle for this request
 * @param routingOptions routing option snapshot for the insert
 * @param realTimeFlag whether the request should be treated as real-time traffic
 */
public record InsertHandlerContext(
    Node node,
    PeerNode source,
    long uid,
    long startTime,
    InsertTag tag,
    InsertRoutingOptions routingOptions,
    boolean realTimeFlag) {}
