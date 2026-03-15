package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the server-to-client confirmation that a USK subscription request has been registered.
 *
 * <p>This message mirrors the essential fields of the originating {@link SubscribeUSKMessage} so
 * that clients can correlate the acknowledgement with their request, confirm the canonical URI that
 * the node recorded, and note whether polling was disabled via the {@code DontPoll} flag. Instances
 * are created by the node once it accepts a subscription and are emitted over the Freenet Client
 * Protocol (FCP) stream without further mutation.
 *
 * <p>Typical call patterns involve a client sending {@code SubscribeUSK}, then reading this message
 * to verify the identifier and to ensure the node will only passively track updates when {@code
 * DontPoll=true}. The class is intentionally minimal: all state lives in the wrapped request
 * object, and serialization delegates to {@link #getFieldSet()} so callers do not have to rebuild
 * protocol fields manually. Instances are effectively immutable after construction; thread safety
 * therefore depends on external callers not mutating the referenced request.
 *
 * <ul>
 *   <li>Confirms subscription metadata without initiating any fetches on its own.
 *   <li>Provides a stable message name via {@link #NAME} for routing and logging.
 *   <li>Acts as a guardrail on the inbound path by rejecting client-originated instances.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 * @see SubscribeUSKMessage
 * @see FCPMessage
 */
public class SubscribedUSKMessage extends FCPMessage {

  /**
   * Canonical FCP identifier used on the wire for this message type so routers and handlers can
   * recognize acknowledgement payloads.
   */
  public static final String NAME = "SubscribedUSK";

  /**
   * Original subscription request whose identifier, URI, and polling preference are echoed back to
   * the client to confirm what the node recorded.
   */
  public final SubscribeUSKMessage message;

  /**
   * Creates a reply wrapper around the provided subscription request so the node can echo the
   * captured fields back to the initiating client.
   *
   * <p>The supplied request instance is retained rather than copied, which keeps serialization
   * aligned with what the node originally parsed. Callers should therefore avoid mutating the
   * request after handing it to this constructor to preserve the immutability of the outgoing
   * acknowledgement.
   *
   * @param m parsed subscription request containing the identifier, URI, and polling flag to echo
   *     back to the client; must not be {@code null}.
   */
  SubscribedUSKMessage(SubscribeUSKMessage m) {
    this.message = m;
  }

  /**
   * Builds the serialized representation expected by FCP peers so the acknowledgement can be
   * transmitted over the protocol stream.
   *
   * <p>The resulting {@link SimpleFieldSet} always includes the original {@code Identifier}, the
   * canonical {@code URI} derived from {@link SubscribeUSKMessage#key}, and the {@code DontPoll}
   * boolean that instructs the node to avoid proactive polling. Each invocation returns a fresh
   * field set, ensuring callers can adjust or discard the structure without affecting subsequent
   * messages. The method does not perform null checks because the constructor already expects a
   * fully parsed request.
   *
   * @return newly allocated field set containing identifier, URI, and polling preference ready for
   *     network transmission.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Identifier", message.clientIdentifier);
    sfs.putSingle("URI", message.key.getURI().toString());
    sfs.put("DontPoll", message.dontPoll);

    return sfs;
  }

  /**
   * Provides the stable protocol name used when routing or logging this message within the client
   * and node message handling pipeline.
   *
   * <p>This method always returns {@link #NAME}, allowing handlers to rely on a single constant
   * regardless of where the message originated. Returning a string instead of inlining the constant
   * in callers keeps the message API consistent with other {@link FCPMessage} implementations that
   * also supply dynamic names. The value is free of localization or formatting concerns and can be
   * compared directly in switch statements.
   *
   * @return constant wire name {@code "SubscribedUSK"} for this acknowledgement message.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects attempts to process this acknowledgement as an inbound client message by raising an
   * explicit protocol error.
   *
   * <p>Inbound handling invokes this method when a client mistakenly sends {@code SubscribedUSK}
   * toward the node. Because the message is designed to flow only from server to client, the method
   * immediately throws {@link MessageInvalidException} with a descriptive explanation so callers
   * can surface the misuse to their users. The behavior is intentionally non-recoverable and does
   * not mutate either the {@link FCPConnectionHandler} or the {@link Node} instance.
   *
   * @param handler active FCP connection context that attempted to process the message; not
   *     modified by this method.
   * @throws MessageInvalidException always thrown to indicate the directional violation and halt
   *     further processing of the inbound payload.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        NAME,
        false);
  }
}
