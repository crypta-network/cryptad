package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Notifies an FCP client that a subscribed USK polling round has completed for a given subscription
 * identifier.
 *
 * <p>The node emits this message after it has finished probing the requested update sequence key
 * (USK) for newer editions. Clients typically subscribe using the higher-level USK subscription
 * commands and receive this message to learn that the current polling interval has reached its
 * natural end, regardless of whether fresh data was discovered. The message is intentionally
 * lightweight: it only echoes the identifier provided at subscription time so the client can
 * correlate the lifecycle of concurrent subscriptions without holding additional state inside the
 * protocol layer.
 *
 * <p>Responsibilities and notable behaviors:
 *
 * <ul>
 *   <li>Communicates completion of a single subscription round, not the overall subscription.
 *   <li>Contains no payload beyond the subscription identifier to keep transport overhead low.
 *   <li>Intended for outbound delivery to clients; the server-side {@link #run} method is a guard.
 * </ul>
 *
 * <p>The class is immutable and thread-safe by construction. Instances are created per event and
 * can be shared across threads without synchronization because the identifier field is final and no
 * additional mutable state is held. Consumers should treat it as a short-lived notification object
 * that mirrors the wire format used by the FCP layer.
 *
 * @see FCPMessage
 * @see FCPConnectionHandler
 */
public class SubscribedUSKRoundFinishedMessage extends FCPMessage {
  private final String subscriptionIdentifier;

  /**
   * Creates a completion notification for the given subscription identifier so it can be emitted to
   * the subscribing FCP client after a polling round concludes.
   *
   * @param id unique token assigned by the subscriber when registering the USK interest; must not
   *     be {@code null} and should match the identifier used in the originating request.
   */
  SubscribedUSKRoundFinishedMessage(String id) {
    subscriptionIdentifier = id;
  }

  /**
   * Builds the {@link SimpleFieldSet} representation sent over the wire for this message.
   *
   * <p>The returned structure always contains the {@code Identifier} key so the receiving client
   * can match the completion event to an existing subscription context. No additional fields are
   * added, keeping the payload small and predictable even when multiple subscriptions are active at
   * once. Callers should not modify the resulting field set because it is constructed specifically
   * for immediate transmission.
   *
   * @return field set containing the single {@code Identifier} entry referencing the originating
   *     subscription; ownership remains with the caller after creation.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", subscriptionIdentifier);
    return fs;
  }

  /**
   * Returns the fixed FCP message name used to serialize this notification on the network.
   *
   * <p>The name is stable and lower camel case as required by the FCP specification. Clients use it
   * to route incoming messages to the appropriate subscription handlers, and servers rely on the
   * constant to produce predictable logs and metrics. Because the name is invariant, callers can
   * cache the value freely without risking behavioral changes between releases.
   *
   * @return constant string {@code "SubscribedUSKRoundFinished"} identifying the message type in
   *     FCP traffic.
   */
  @Override
  public String getName() {
    return "SubscribedUSKRoundFinished";
  }

  /**
   * Guard method for inbound handling; this outbound-only message should never be executed on the
   * server side and therefore throws unconditionally.
   *
   * <p>The FCP framework still requires a {@code run} implementation for completeness, so the
   * method remains to satisfy the contract but signals misuse via an {@link
   * UnsupportedOperationException} at runtime. Implementations that invoke this method should treat
   * such calls as programming errors or protocol violations. No state is modified before the
   * exception is thrown.
   *
   * @param handler connection handler associated with the subscription; never used because the
   *     method aborts immediately.
   * @throws MessageInvalidException never thrown directly here but retained for signature parity
   *     with the superclass contract and related message types.
   * @throws UnsupportedOperationException always thrown to indicate that this message is not meant
   *     to be executed on the receiving side.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new UnsupportedOperationException();
  }
}
