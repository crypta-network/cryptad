package network.crypta.clients.fcp;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.crypt.HashResult;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the {@code ExpectedHashes} FCP message sent to clients while an insert or fetch
 * request is still streaming data. The message mirrors {@link ExpectedHashesEvent} instances and
 * relays the server-side digest calculations so front-ends can preview block integrity before the
 * payload becomes retrievable.
 *
 * <p>The object is immutable after construction: the {@link HashResult} array reference is stored
 * verbatim, but the command never mutates it once assigned. Callers therefore guarantee that the
 * provided array is stable for the lifetime of the message and that each element describes a unique
 * hash algorithm result for the underlying content. Instances are typically short-lived request
 * updates that travel from worker threads to the {@code FCPConnectionOutputHandler}, so they are
 * safe to pass across threads as long as the referenced array is not reused elsewhere.
 *
 * <p>Because the message ultimately serializes to {@link SimpleFieldSet}, the receiver must expect
 * that null hashes indicate persistence bugs. Defensive logging is kept extremely loud (errors) so
 * operators can correlate symptoms with upgrades noted in release build 1411. The {@code global}
 * flag follows the FCP 2 convention: when {@code true}, the identifier is considered globally
 * unique across the connection multiplex, whereas {@code false} scopes it to a specific client
 * context.
 *
 * <ul>
 *   <li>Conveys expected digests for UI progress panels or auditing tools.
 *   <li>Shares the request identifier so recipients can map hashes to queued jobs.
 *   <li>Flags whether the identifier participates in the global namespace negotiated per session.
 * </ul>
 *
 * @see ExpectedHashesEvent
 * @see FCPMessage
 * @see HashResult
 */
public class ExpectedHashes extends FCPMessage implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(ExpectedHashes.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Array of expected digests in the order produced by the inserter; never mutated after set. */
  final HashResult[] hashes;

  /**
   * Identifier that downstream clients use to associate the message with a specific outstanding FCP
   * request; may be {@code null} when the client relied on implicit correlation.
   */
  final String messageIdentifier;

  /**
   * Flag propagated from the originating request to signal whether {@link #messageIdentifier}
   * belongs to the global namespace shared by multiple sessions or remains scoped to the sender.
   */
  final boolean global;

  /**
   * Builds a message from an {@link ExpectedHashesEvent}, copying its digest array reference while
   * associating it with the caller-supplied identifier metadata. The constructor does not clone the
   * event payload, so upstream code must retain ownership discipline and avoid modifying the array
   * once the message is in flight.
   *
   * <p>Use this constructor inside FCP message producers whenever an {@code EventProducer}
   * dispatches {@link ExpectedHashesEvent}s. It preserves the {@code global} routing flag so client
   * libraries can differentiate per-connection and per-request notifications. Because identifiers
   * may be absent on some legacy calls, {@code identifier} may be {@code null}; downstream code
   * tolerates that and leaves the corresponding field unset in the serialized frame.
   *
   * <pre>{@code
   * ExpectedHashes msg = new ExpectedHashes(event, requestId, isGlobal);
   * handler.send(msg);
   * }</pre>
   *
   * @param event event emitted by the node containing all {@link HashResult} entries and codecs;
   *     must not be {@code null} and should already reflect finalized digests
   * @param identifier identifier that ties the update back to a client-visible job name; {@code
   *     null} is allowed when no tracking identifier was negotiated
   * @param global {@code true} when the identifier participates in the global namespace shared by
   *     multiple subscriptions; {@code false} keeps the message scoped to its original requester
   */
  public ExpectedHashes(ExpectedHashesEvent event, String identifier, boolean global) {
    this.messageIdentifier = identifier;
    this.global = global;
    this.hashes = event.hashes;
  }

  ExpectedHashes(HashResult[] hashes, String identifier, boolean global) {
    this.messageIdentifier = identifier;
    this.global = global;
    this.hashes = hashes;
  }

  /**
   * Zero-argument constructor required solely for serialization libraries that instantiate the
   * message via reflection before hydrating fields. Normal application code should avoid calling it
   * and instead rely on the strongly typed constructors above.
   *
   * <p>All members are initialized to {@code null} or {@code false} placeholders and therefore must
   * be reassigned by the deserializer before the object is used. The constructor remains protected
   * to discourage accidental misuse while still keeping compatibility with frameworks that mandate
   * a no-argument entry point.
   */
  @SuppressWarnings("unused")
  protected ExpectedHashes() {
    // For serialization.
    hashes = null;
    messageIdentifier = null;
    global = false;
  }

  /**
   * Converts the message into an immutable {@link SimpleFieldSet} suitable for on-the-wire FCP
   * transmission. The method validates that each {@link HashResult} entry and its {@code type} are
   * non-null, logging an error and returning {@code null} when corruption from legacy persistence
   * bugs is detected.
   *
   * <p>The resulting structure contains a nested {@code Hashes} sub-field with entries ordered in
   * the same sequence as the {@link #hashes} array. Subsequent callers must treat the returned
   * instance as detached because {@code SimpleFieldSet} does not share mutable state with the
   * original message.
   *
   * @return a freshly populated {@link SimpleFieldSet} mirroring the message contents, or {@code
   *     null} when validation fails due to missing hash data
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    if (hashes == null) {
      LOG.error(
          "Hashes == null, possibly persistence issue caused prior to build 1411 on {}", this);
      return null;
    }
    SimpleFieldSet fs = new SimpleFieldSet(false);
    SimpleFieldSet values = new SimpleFieldSet(false);
    for (HashResult hash : hashes) {
      if (hash == null) {
        LOG.error(
            "Hash == null, possibly persistence issue caused prior to build 1411 on {}", this);
        return null;
      }
      if (hash.type == null) {
        LOG.error(
            "Hash type == null, possibly persistence issue caused prior to build 1411 on {}", this);
        return null;
      }
      values.putOverwrite(hash.type.name(), hash.hashAsHex());
    }
    fs.put("Hashes", values);
    fs.putOverwrite(IDENTIFIER, messageIdentifier);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Returns the canonical FCP message name {@code "ExpectedHashes"}, which is used by connection
   * handlers to route serialized frames and by downstream tooling to categorize notifications. The
   * value never changes across builds so clients can rely on it for filtering or metrics without
   * parsing the inner field set.
   *
   * <p>Although the implementation is a one-line literal return, maintaining this method makes the
   * class consistent with other {@link FCPMessage} implementations and enables polymorphic logging
   * across the protocol stack. Callers should cache the value locally if they need it frequently,
   * because the method performs no allocations yet still involves a virtual dispatch.
   *
   * @return constant {@code "ExpectedHashes"} to comply with the {@link FCPMessage} naming contract
   */
  @Override
  public String getName() {
    return "ExpectedHashes";
  }

  /**
   * Execution hook invoked when an incoming {@code ExpectedHashes} message would normally be
   * processed by the node. Because this message type is outbound only, the implementation always
   * throws {@link UnsupportedOperationException} to prevent accidental execution paths that might
   * trust unverified input.
   *
   * <p>The method still declares {@link MessageInvalidException} to honor the {@link FCPMessage}
   * contract, but callers should never expect it to return successfully. Relay layers must
   * therefore short-circuit before invoking {@code run} on messages they originated locally.
   *
   * @param handler connection handler representing the peer endpoint; unused because execution is
   *     unsupported
   * @param node running node instance; included for interface symmetry but never dereferenced here
   * @throws MessageInvalidException declared for interface compatibility, though the method always
   *     fails with {@link UnsupportedOperationException}
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new UnsupportedOperationException();
  }
}
