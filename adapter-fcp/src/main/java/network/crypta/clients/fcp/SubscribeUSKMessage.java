package network.crypta.clients.fcp;

import java.net.MalformedURLException;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.support.SimpleFieldSet;

/**
 * Client-to-node message instructing the node to subscribe to a {@link USK} and report updates.
 *
 * <p>This message is part of the FCP request/response flow: a client sends it to the node to
 * register interest in a particular USK. Once accepted, the node replies with {@link
 * SubscribedUSKMessage} and later pushes update messages whenever a newer edition of the USK
 * becomes available. Clients can choose whether the node should actively probe for new editions or
 * merely observe traffic. Typical usage is to subscribe once during session setup and keep the
 * connection open to receive asynchronous notifications. The object is immutable after parsing and
 * therefore safe to share between handler threads, while the underlying request lifecycle is
 * managed by {@link SubscribeUSK}.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Validate and normalize the incoming USK URI and client identifier.
 *   <li>Record subscription flags such as polling strategy and priority settings.
 *   <li>Initiate the backend {@link SubscribeUSK} workflow and acknowledge the client.
 * </ul>
 *
 * @see SubscribeUSK
 * @see SubscribedUSKMessage
 */
public final class SubscribeUSKMessage extends FCPMessage {

  /**
   * Message name sent over FCP to denote a USK subscription request. Constant value is stable
   * across releases, so client implementations can rely on it when constructing field sets or
   * parsing incoming traffic without hard-coding multiple variants.
   */
  public static final String NAME = "SubscribeUSK";

  final USK key;
  final boolean dontPoll;
  final String clientIdentifier;
  final short prio;
  final short prioProgress;
  final boolean realTimeFlag;
  final boolean sparsePoll;
  final boolean ignoreUSKDatehints;

  /**
   * Parses a subscription request from a field set and captures all subscription options.
   *
   * <p>The constructor expects the caller to have already extracted the FCP message into a {@link
   * SimpleFieldSet}. It validates the presence of the client identifier and a well-formed USK URI,
   * derives polling preferences, and stores priority settings for the downstream request scheduler.
   * The instance contains no mutable state after construction, so callers may reuse it across
   * pipeline stages without additional synchronization.
   *
   * @param fs parsed fields from the incoming FCP message; must include URI and Identifier values
   * @throws MessageInvalidException if mandatory fields are missing or the USK URI cannot be parsed
   */
  public SubscribeUSKMessage(SimpleFieldSet fs) throws MessageInvalidException {
    this.clientIdentifier = fs.get("Identifier");
    if (clientIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier!", null, false);
    String suri = fs.get("URI");
    if (suri == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Expected a URI on SubscribeUSK",
          clientIdentifier,
          false);
    FreenetURI uri;
    try {
      uri = new FreenetURI(suri);
      key = USK.create(uri);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, "Could not parse URI: " + e, clientIdentifier, false);
    }
    this.dontPoll = fs.getBoolean("DontPoll", false);
    if (!dontPoll) this.sparsePoll = fs.getBoolean("SparsePoll", false);
    else sparsePoll = false;
    prio = fs.getShort("PriorityClass", FcpPriorityClasses.BULK_SPLITFILE);
    prioProgress = fs.getShort("PriorityClassProgress", (short) Math.max(0, prio - 1));
    realTimeFlag = fs.getBoolean("RealTimeFlag", false);
    ignoreUSKDatehints = fs.getBoolean("IgnoreUSKDatehints", false);
  }

  /**
   * Serializes this subscription request back into an FCP field set suitable for transmission.
   *
   * <p>The returned {@link SimpleFieldSet} contains the normalized USK URI and the current polling
   * directive. It intentionally omits optional fields such as priority classes because those values
   * are applied internally by the scheduler and do not need to be echoed to the peer. Callers
   * receive a fresh, mutable instance on every invocation; modifying it does not alter the {@link
   * SubscribeUSKMessage} state.
   *
   * @return a new field set containing the USK URI and polling flag in wire format
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("URI", key.getURI().toString());
    fs.put("DontPoll", dontPoll);
    return fs;
  }

  /**
   * Returns the FCP message name used to identify this command on the wire.
   *
   * <p>The name is constant for all instances and matches the token expected by the node-side
   * dispatcher when routing incoming messages. It is safe to cache or compare by reference in
   * performance-sensitive code paths because the returned string is interned by virtue of being a
   * static constant.
   *
   * @return the literal message name {@code "SubscribeUSK"} used in FCP exchanges
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the subscription by wiring the parsed options into the node and acknowledging the
   * client.
   *
   * <p>This method is invoked on the connection handler thread. It instantiates the backend {@link
   * SubscribeUSK} workflow, which registers the subscription with the request starter using the
   * specified priorities and polling hints. If another subscription with the same identifier is
   * already active, the handler replies with {@link IdentifierCollisionMessage} and no new
   * subscription is created. On success, a {@link SubscribedUSKMessage} is sent immediately to
   * confirm that updates will be delivered asynchronously. The method performs no retries; callers
   * should interpret thrown exceptions as fatal for this message instance.
   *
   * @param handler connection-scoped handler responsible for sending replies and managing session
   *     state; must not be {@code null}
   * @throws MessageInvalidException if validation fails while creating the backend subscription
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    try {
      new SubscribeUSK(this, handler.getServer().insertRuntimeSupport(), handler);
    } catch (IdentifierCollisionException _) {
      handler.send(new IdentifierCollisionMessage(clientIdentifier, false));
      return;
    }
    SubscribedUSKMessage reply = new SubscribedUSKMessage(this);
    handler.send(reply);
  }
}
