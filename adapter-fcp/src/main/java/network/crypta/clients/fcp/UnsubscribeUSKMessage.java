package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * FCP message instructing the node to stop sending updates for a previously subscribed USK.
 *
 * <p>This inbound-only message is emitted by a client after it no longer wishes to receive
 * notifications for a {@code SubscribeUSK} request. The message body carries only the stable
 * subscription identifier so the server can cancel the corresponding watcher and release any
 * resources associated with queued updates. Typical usage pairs the identifier supplied in {@link
 * SubscribeUSKMessage} with this class and is handled synchronously by the {@link
 * FCPConnectionHandler} that accepted the original subscription.
 *
 * <p>Instances are immutable and represent a single unsubscribe request. The lifecycle is short:
 * the message is parsed from the incoming field set, validated for the presence of the identifier,
 * and then executed once via {@link #run(FCPConnectionHandler)}. Thread-safety is provided by the
 * caller; this class maintains no shared state. Use this type when tearing down long-lived USK
 * feeds to avoid unnecessary bandwidth and server-side cache usage.
 *
 * <ul>
 *   <li>Responsibility: convey which subscription to cancel.
 *   <li>Notable behavior: rejects requests missing the {@code Identifier} field.
 *   <li>Serialization: not emitted to peers; {@link #getFieldSet()} is unsupported.
 * </ul>
 *
 * @see SubscribeUSKMessage
 * @see FCPConnectionHandler#unsubscribeUSK(String)
 */
public final class UnsubscribeUSKMessage extends FCPMessage {

  /** Canonical message name advertised to FCP handlers for unsubscribe operations. */
  public static final String NAME = "UnsubscribeUSK";

  private final String subscriptionIdentifier;

  /**
   * Constructs an unsubscribe request from a parsed field set and validates required data.
   *
   * <p>The constructor reads the {@code Identifier} field supplied by the client. If the field is
   * missing or empty, it raises a {@link MessageInvalidException} to signal malformed input to the
   * caller. Successful construction guarantees that {@link #run(FCPConnectionHandler)} can
   * reference a non-null identifier when delegating to the connection handler.
   *
   * @param fs parsed fields for this message; must contain an Identifier entry.
   * @throws MessageInvalidException if Identifier is absent or empty in the provided field set.
   */
  public UnsubscribeUSKMessage(SimpleFieldSet fs) throws MessageInvalidException {
    this.subscriptionIdentifier = fs.get(IDENTIFIER);
    if (subscriptionIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier!", null, false);
  }

  /**
   * Unsupported because inbound-only messages are not serialized back onto the wire.
   *
   * <p>Unsubscribe requests originate from the client and are never forwarded or echoed by the
   * node. As such, serialization through a {@link SimpleFieldSet} is intentionally unavailable.
   * Callers should rely on the original decoded representation rather than attempting to
   * reconstruct one.
   *
   * @return never returns because this inbound-only message is not serialized outward.
   * @throws UnsupportedOperationException always thrown because this message is not serialized
   *     outbound.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the fixed FCP message name used to register unsubscribe handlers.
   *
   * <p>The name is stable and shared across all instances so dispatchers can route incoming field
   * sets without inspecting their contents. Because the value is constant, callers may safely cache
   * it and compare by identity or equality when mapping handlers. The returned string must not be
   * mutated or localized; it is part of the protocol surface.
   *
   * @return constant message name advertised to peers and protocol handlers.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the unsubscribe operation against the connection handler using the stored identifier.
   *
   * <p>The method delegates directly to {@link FCPConnectionHandler#unsubscribeUSK(String)} with
   * the validated subscription identifier extracted during construction. It completes
   * synchronously; any removal errors propagate as {@link MessageInvalidException} according to the
   * handler’s policy. Callers should ensure the handler instance matches the session that produced
   * the subscription to avoid orphaned watchers or missed cancellations. No state is retained after
   * invocation, making repeated calls idempotent only if the handler itself treats unknown
   * identifiers as no-ops.
   *
   * @param handler connection-scoped dispatcher that tracks USK subscriptions for this client.
   * @throws MessageInvalidException if the handler rejects the identifier or cannot remove the
   *     subscription.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    handler.unsubscribeUSK(subscriptionIdentifier);
  }
}
