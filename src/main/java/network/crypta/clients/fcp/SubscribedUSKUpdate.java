package network.crypta.clients.fcp;

import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Announces that a subscribed {@link USK} has advanced to a new edition and should be delivered to
 * the FCP client.
 *
 * <p>This message is created on the server side when a background subscription detects a fresher
 * slot for the given USK. The object is immutable, so the receiving client can safely hand the
 * instance across threads while it assembles follow-up requests or updates local state. Typical
 * consumers enqueue the message toward the client connection, relying on {@link #getFieldSet()} to
 * serialize the identifier, edition, and flags expected by the FCP protocol. Because this class is
 * purely descriptive and does not perform any lookups, it is cheap to instantiate and can be reused
 * in queues without additional synchronization.
 *
 * <ul>
 *   <li>Represents server-to-client notifications for USK subscriptions.
 *   <li>Encapsulates edition number, canonical URI, and freshness flags.
 *   <li>Immutable once built; thread-safe for concurrent read-only access.
 * </ul>
 *
 * @see FCPMessage
 * @see USK
 */
public class SubscribedUSKUpdate extends FCPMessage {

  final String messageIdentifier;
  final long edition;
  final USK key;
  final boolean newKnownGood;
  final boolean newSlotToo;

  static final String NAME = "SubscribedUSKUpdate";

  /**
   * Builds an update message describing a newly discovered edition for a subscribed USK.
   *
   * <p>The constructor captures only immutable value fields; it performs no validation beyond
   * assigning the arguments. Callers are expected to pass protocol-consistent values sourced from
   * the subscription logic. Instances constructed with incorrect flags will still serialize, so the
   * producer should enforce any higher-level invariants before instantiation.
   *
   * @param identifier unique message identifier echoed back to the subscriber; never null or blank
   * @param l edition number advertised for the USK; non-negative and monotonically increasing per
   *     key
   * @param key canonical USK pointing to the subscription target; must be resolvable to a URI
   * @param newKnownGood true when the edition is verified as currently fetchable without retries
   * @param newSlotToo true when a previously unknown slot index became available alongside the
   *     known-good edition
   */
  public SubscribedUSKUpdate(
      String identifier, long l, USK key, boolean newKnownGood, boolean newSlotToo) {
    this.messageIdentifier = identifier;
    this.edition = l;
    this.key = key;
    this.newKnownGood = newKnownGood;
    this.newSlotToo = newSlotToo;
  }

  /**
   * Renders this message into the wire-format {@link SimpleFieldSet} expected by FCP clients.
   *
   * <p>The returned structure contains the message identifier, edition number, canonical URI, and
   * both freshness flags. Callers may reuse the result for multiple sends because the underlying
   * values are immutable. No additional validation occurs at this stage, so any protocol checks
   * must be performed prior to calling this method.
   *
   * @return a populated {@code SimpleFieldSet} ready for transmission; never null and safe for
   *     read-only reuse
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", messageIdentifier);
    fs.put("Edition", edition);
    fs.putSingle("URI", key.getURI().toString());
    fs.put("NewKnownGood", newKnownGood);
    fs.put("NewSlotToo", newSlotToo);
    return fs;
  }

  /**
   * Reports the protocol-level message name used when serializing this update.
   *
   * <p>The value is constant and shared across all instances; callers can rely on this method for
   * routing or logging without additional allocation.
   *
   * @return the fixed FCP message name {@code "SubscribedUSKUpdate"}
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects attempts to process this message on the client-to-server path.
   *
   * <p>Subscribed USK updates are emitted by the server and must not originate from clients. This
   * override enforces that contract by always throwing {@link MessageInvalidException}, allowing
   * callers to surface a protocol error rather than silently discarding the message. The method is
   * intentionally non-idempotent because each invocation raises a new exception instance.
   *
   * @param handler connection handler attempting to process the message; expected to be non-null
   * @param node local node context; supplied for interface completeness but unused in this
   *     implementation
   * @throws MessageInvalidException always thrown to signal server-only directionality violations
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "SubscribedUSKUpdate goes from server to client not the other way around",
        messageIdentifier,
        false);
  }
}
