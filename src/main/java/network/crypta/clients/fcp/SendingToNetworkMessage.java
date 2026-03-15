package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Represents the FCP {@code SendingToNetwork} progress notification emitted to clients.
 *
 * <p>This message marks the moment a client request leaves local queues and begins traversing the
 * Crypta network. Instances are immutable once built; the identifier and global flag are captured
 * in the constructor and serialized via {@link #getFieldSet()} so connected clients can mirror
 * progress consistently, including after reconnections. The message is replayed for persistent
 * requests to keep late subscribers in sync with the original delivery order.
 *
 * <p>Typical flow: fetch or put components raise a {@link
 * network.crypta.client.events.SendingToNetworkEvent}, translate it into this message, and queue it
 * on an {@link FCPConnectionHandler}. Clients use the identifier to align UI or bookkeeping with
 * their pending request before subsequent progress events arrive. Because the notification is
 * informational only, {@link #run(FCPConnectionHandler)} intentionally performs no action on
 * inbound paths.
 *
 * <ul>
 *   <li>Immutable carrier for the request identifier and global visibility flag.
 *   <li>Serialized with {@code Identifier} and {@code Global} fields for protocol replay.
 *   <li>Used by reconnection logic to preserve original progress ordering.
 * </ul>
 *
 * @see FCPMessage
 * @see network.crypta.client.events.SendingToNetworkEvent
 * @see SubscribedUSKSendingToNetworkMessage
 */
public class SendingToNetworkMessage extends FCPMessage {
  /**
   * Canonical protocol token emitted on the wire for this message type.
   *
   * <p>Handlers and tests rely on this constant to route {@code SendingToNetwork} notifications
   * without allocating new strings, keeping persisted queues and client dispatch tables in sync
   * with the protocol expectation.
   */
  public static final String NAME = "SendingToNetwork";

  final String messageIdentifier;
  final boolean global;

  /**
   * Creates an immutable {@code SendingToNetwork} notification for the given request.
   *
   * <p>Invoke this when a fetch or put transitions from local preparation to outbound transmission.
   * The caller supplies the client-visible identifier so downstream listeners can correlate
   * subsequent progress updates. The {@code global} flag preserves whether the request belongs to
   * the global queue, which matters when replaying events to reconnecting clients or to multiple
   * connections sharing the same identifier. Instances carry no mutable state and can be safely
   * reused across threads that merely serialize the fields.
   *
   * @param id Request identifier echoed back to the FCP client for correlation.
   * @param global True when the request should be visible on the global client queue.
   */
  public SendingToNetworkMessage(String id, boolean global) {
    this.messageIdentifier = id;
    this.global = global;
  }

  /**
   * Builds the field set representing this message for transmission.
   *
   * <p>Each invocation creates a fresh {@link SimpleFieldSet} with {@code Identifier} and {@code
   * Global} entries, matching the names expected by FCP peers. The returned structure remains
   * mutable to allow callers to attach list request identifiers, but the values copied from this
   * instance are stable. Repeated calls are cheap and free of shared state, making the method safe
   * to use from multiple threads when serializing the same message for different connections.
   *
   * @return New field set containing {@code Identifier} and {@code Global} entries for
   *     serialization.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", messageIdentifier);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Returns the protocol-level name for this message type.
   *
   * <p>The method simply yields {@link #NAME}, allowing dispatchers to decide how to encode or
   * replay the notification. Because the name is constant and allocation-free, callers can invoke
   * it liberally when logging, building list request identifiers, or comparing message types during
   * reconnection flows. It remains stable across versions so persisted queues and client
   * expectations stay aligned.
   *
   * @return Canonical message name used when emitting the FCP frame.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * No-op because {@code SendingToNetwork} is outbound-only and never executed inbound.
   *
   * <p>The base {@link FCPMessage} contract requires an execution hook for inbound messages, but
   * protocol peers should never send this notification back to the node. Should it arrive due to
   * misuse or testing, the method simply returns without touching the handler or node, preserving
   * side effect freedom. The declared {@link MessageInvalidException} remains for compatibility
   * with the abstract signature, yet no exception is thrown here.
   *
   * @param handler Connection context invoking execution, ignored for this outbound message.
   * @throws MessageInvalidException Retained for interface compliance; not thrown by this
   *     implementation.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    // Not possible
  }
}
