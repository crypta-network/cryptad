package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message informing an FCP client that a request has entered a finite cooldown interval.
 *
 * <p>{@code EnterFiniteCooldown} is emitted by the node when a client-submitted request has been
 * throttled in a way that guarantees a bounded delay before processing resumes. The message acts as
 * a heartbeat for long-running fetch or insert operations, letting the remote UI or automation know
 * the request still exists but is paused. Callers typically enqueue the message, inspect the
 * identifier field to match local state, and adjust progress indicators or retry timers
 * accordingly. Implementations keep the payload deliberately small so it can travel even when
 * resources are scarce.
 *
 * <p>The instance is immutable after construction: all protocol fields are final and exposed only
 * through {@link #getFieldSet()}. The message object is safe to share across threads provided the
 * surrounding code does not mutate the returned {@link SimpleFieldSet}. Since this type only wraps
 * precomputed values, it contains no blocking logic, I/O, or node callbacks. The {@link #run}
 * method intentionally does nothing because cooldown updates are destined for clients rather than
 * interpreted locally.
 *
 * <ul>
 *   <li>Represents the "EnterFiniteCooldown" wire-level event.
 *   <li>Embeds the client-specified identifier plus global flag and wake-up timestamp.
 *   <li>Serializes to a minimal {@link SimpleFieldSet} suitable for network transport.
 * </ul>
 */
public class EnterFiniteCooldown extends FCPMessage {

  final String requestIdentifier;
  final boolean global;
  final long wakeupTime;

  /**
   * Creates a new immutable message instance that mirrors the provided request metadata.
   *
   * @param identifier unique client-assigned token identifying the original request instance. Must
   *     be non-null and match the value supplied in the corresponding FCP operation.
   * @param global whether the cooldown originates from a node-wide limiter ({@code true}) or from a
   *     request-specific throttle ({@code false}); informs the UI which subsystem is slowing the
   *     work.
   * @param wakeupTime wall-clock timestamp, expressed in Java milliseconds since the epoch,
   *     representing when processing is expected to resume if nothing else changes.
   */
  EnterFiniteCooldown(String identifier, boolean global, long wakeupTime) {
    this.requestIdentifier = identifier;
    this.global = global;
    this.wakeupTime = wakeupTime;
  }

  /**
   * Builds the protocol field set sent on the wire for this cooldown notification.
   *
   * <p>The returned {@link SimpleFieldSet} contains three scalar entries: {@code Identifier} echoes
   * the client-supplied token, {@code Global} reports the throttling scope as a boolean, and {@code
   * WakeupTime} exposes the millisecond timestamp when processing should resume. Callers may reuse
   * the structure for serialization immediately; it is not defensive-copied, so mutating it after
   * sending can lead to inconsistent retransmissions.
   *
   * @return mutable field set populated with the identifier, scope flag, and wake-up timestamp in
   *     UTC milliseconds, ready for encoding by {@link FCPMessage#send(java.io.OutputStream)}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putOverwrite("Identifier", requestIdentifier);
    fs.put("Global", global);
    fs.put("WakeupTime", wakeupTime);
    return fs;
  }

  /**
   * Returns the canonical wire name for this message type.
   *
   * <p>The value is stable across releases so that external clients can route the message to the
   * correct handler. Although trivial, an explicit override avoids string concatenations elsewhere
   * in the hierarchy and documents the role this type plays within the FCP message catalogue.
   *
   * @return literal string {@code "EnterFiniteCooldown"}, matching the protocol specification.
   */
  @Override
  public String getName() {
    return "EnterFiniteCooldown";
  }

  /**
   * {@inheritDoc}
   *
   * <p>The server does not execute any action when receiving this message because cooldown updates
   * flow from the node to the client only. The override exists purely to acknowledge the message
   * type and make the intentional no-op explicit for maintainers.
   *
   * @throws MessageInvalidException never thrown; retained for signature compatibility with the
   *     base class contract.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    // Not supported
  }
}
