package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Message emitted by the client layer to tell the node that a subscribed USK is now being forwarded
 * to the network rather than served from local cache.
 *
 * <p>This command wraps only a single identifier, mirroring the subscription handle originally
 * assigned by the server. The surrounding FCP session uses the identifier to correlate updates
 * flowing from the node back to the client that requested the subscription. Callers typically emit
 * this message immediately after receiving a {@code SubscribedUSK} notification, at the moment they
 * decide to publish the content upstream. The message is intentionally minimal: it contains no
 * payload beyond the identifier, does not alter subscription state, and never retries.
 *
 * <p>Thread-safety: instances are immutable and safe for reuse across threads, but the surrounding
 * {@link FCPConnectionHandler} is not guaranteed to be. Construction is cheap; allocate per
 * notification to avoid shared mutable state. Because this message is an instruction rather than a
 * data carrier, it should be sent only once per subscription lifecycle stage to avoid confusing the
 * remote peer.
 *
 * <ul>
 *   <li>Responsibility: signal intent to send the subscribed USK back into the network.
 *   <li>Correlation: {@code Identifier} must match the token assigned in the original subscription.
 *   <li>Scope: carries no file data and does not acknowledge receipt.
 * </ul>
 *
 * @see SubscribedUSKMessage
 */
public class SubscribedUSKSendingToNetworkMessage extends FCPMessage {

  final String messageIdentifier;

  SubscribedUSKSendingToNetworkMessage(String id) {
    messageIdentifier = id;
  }

  /**
   * Creates the FCP field set containing the subscription identifier that the peer expects.
   *
   * <p>The field set uses a single boolean-friendly map with the key {@code Identifier}. The value
   * must exactly match the identifier issued by the server when the subscription was created;
   * otherwise the node will ignore or reject the message. The returned structure is newly allocated
   * and can be modified by callers without affecting this message instance.
   *
   * @return mutable {@link SimpleFieldSet} with one {@code Identifier} entry representing this
   *     message's subscription token
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", messageIdentifier);
    return fs;
  }

  /**
   * Reports the FCP message name used on the wire.
   *
   * <p>The name is a stable constant defined by the protocol. It is used by the connection layer to
   * serialize outbound messages and to route incoming acknowledgements. No localization or dynamic
   * formatting is performed; callers can rely on the exact casing for protocol matching.
   *
   * @return fixed string {@code "SubscribedUSKSendingToNetwork"} required by the FCP protocol
   */
  @Override
  public String getName() {
    return "SubscribedUSKSendingToNetwork";
  }

  /**
   * This message is outbound-only and should never be executed as an inbound command.
   *
   * <p>The FCP dispatcher calls {@link FCPMessage#run(FCPConnectionHandler)} for messages received
   * from peers. Because {@code SubscribedUSKSendingToNetwork} is emitted by clients rather than
   * consumed by them, invoking this method represents a protocol misuse and results in an {@link
   * UnsupportedOperationException}. No state is changed and the provided handler and node
   * references are left untouched.
   *
   * @param handler active connection context for the current FCP session; never used here but
   *     required by the interface
   * @throws MessageInvalidException declared for interface compatibility; never intentionally
   *     thrown by this implementation
   * @throws UnsupportedOperationException always thrown to signal that inbound execution is
   *     unsupported
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new UnsupportedOperationException();
  }
}
