package network.crypta.node;

import network.crypta.keys.Key;

/**
 * Shared context for inbound request handlers.
 *
 * @param node node coordinating the request
 * @param source upstream peer that sent the request to this node
 * @param uid unique request identifier (UID) assigned by the sender
 * @param htl hop-to-live value for the request (routing depth remaining)
 * @param key the {@link Key} being requested (CHK or SSK)
 * @param tag tracking tag used for accounting, slot management, and completion callbacks
 * @param realTimeFlag whether this request should use real-time prioritization
 */
public record RequestHandlerContext(
    Node node,
    PeerNode source,
    long uid,
    short htl,
    Key key,
    RequestTag tag,
    boolean realTimeFlag) {

  /**
   * Creates a handler context from the request metadata.
   *
   * @param node node coordinating the request
   * @param source upstream peer that sent the request to this node
   * @param uid unique request identifier (UID) assigned by the sender
   * @param htl hop-to-live value for the request (routing depth remaining)
   * @param key the {@link Key} being requested (CHK or SSK)
   * @param tag tracking tag used for accounting, slot management, and completion callbacks
   * @param realTimeFlag whether this request should use real-time prioritization
   * @return new immutable {@link RequestHandlerContext} instance
   */
  public static RequestHandlerContext of(
      Node node,
      PeerNode source,
      long uid,
      short htl,
      Key key,
      RequestTag tag,
      boolean realTimeFlag) {
    return new RequestHandlerContext(node, source, uid, htl, key, tag, realTimeFlag);
  }
}
