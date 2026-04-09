package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Base helper for FCP messages that push binary payloads to a remote darknet peer.
 *
 * <p>This abstraction is used by higher-level client protocols whenever they need to stream a
 * reply, queue update, or diagnostic snapshot to a known peer without exposing the common routing
 * boilerplate in each concrete message. Subclasses parse their payload up front, then invoke {@link
 * #run(FCPConnectionHandler)} to resolve the peer, enforce darknet-only constraints, and finally
 * call {@link #handleFeed(FcpDarknetPeerHandle)} to transmit data. Instances are stateful because
 * they cache identifiers and the optional data length reported to peers during capability
 * negotiation.
 *
 * <p>Implementations are expected to be short-lived and not thread-safe; callers should create a
 * fresh instance per inbound FCP command. The base class never mutates shared node structures
 * directly, so subclasses must coordinate with node subsystems if they manipulate shared queues or
 * throttles. Typical usage flow:
 *
 * <ul>
 *   <li>Parse the incoming {@link SimpleFieldSet} when building the subclass.
 *   <li>Let the connection handler invoke {@code run} inside its dispatch thread.
 *   <li>Implement {@code handleFeed} to stream or update peer-specific state.
 * </ul>
 *
 * @see DataCarryingMessage
 * @see FCPConnectionHandler
 */
public abstract class SendPeerMessage extends DataCarryingMessage {
  /** Parsed routing fields used to construct {@link SendPeerMessage} without throwing. */
  protected record ParsedCommonFields(String identifier, String nodeIdentifier, long dataLength) {}

  /**
   * Caller-supplied identifier echoed back in {@link SentPeerMessage} notifications so clients can
   * correlate requests with asynchronous completion events, even when multiple sends are in flight.
   */
  protected final String identifier;

  /**
   * Node identifier string designating the darknet peer that must receive the payload; usually a
   * stable identity hash or noderef key agreed upon through the client connection handshake.
   */
  protected final String nodeIdentifier;

  private final long dataLength;

  /**
   * Creates a new sending request from already-validated common routing fields.
   *
   * <p>Subclasses should call {@link #parseCommonFields(SimpleFieldSet)} before invoking this
   * constructor so validation errors are surfaced from the subclass constructor rather than this
   * non-final base class constructor.
   *
   * @param parsed parsed identifier/node/data-length triple produced by {@link
   *     #parseCommonFields(SimpleFieldSet)}
   */
  protected SendPeerMessage(ParsedCommonFields parsed) {
    this.identifier = parsed.identifier;
    this.nodeIdentifier = parsed.nodeIdentifier;
    this.dataLength = parsed.dataLength;
  }

  /**
   * Parses and validates common routing fields shared by all send-peer messages.
   *
   * @param fs structured key-value payload parsed from the inbound message; must not be {@code
   *     null}
   * @return parsed common routing fields suitable for {@link #SendPeerMessage(ParsedCommonFields)}
   * @throws MessageInvalidException if {@code DataLength} is present but invalid
   */
  protected static ParsedCommonFields parseCommonFields(SimpleFieldSet fs)
      throws MessageInvalidException {
    String identifier = fs.get("Identifier");
    String nodeIdentifier = fs.get("NodeIdentifier");
    return new ParsedCommonFields(
        identifier, nodeIdentifier, parseDataLength(fs.get("DataLength"), identifier));
  }

  private static long parseDataLength(String dataLengthString, String identifier)
      throws MessageInvalidException {
    if (dataLengthString == null) return -1;
    try {
      long dataLength = Long.parseLong(dataLengthString, 10);
      if (dataLength < 0) throw new NumberFormatException("DataLength must be non-negative");
      return dataLength;
    } catch (NumberFormatException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, "Invalid DataLength field", identifier, false);
    }
  }

  /**
   * Serializes the minimal set of identifying values needed by downstream components and clients.
   *
   * <p>The returned field set is always mutable, allowing callers to append subclass-specific
   * fields before re-encoding the message. {@code DataLength} is emitted only when the value is
   * known, allowing size-agnostic streams to omit it without breaking consumers.
   *
   * @return a new {@link SimpleFieldSet} containing the identifier, node identifier, and optional
   *     data length value expressed in bytes.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.putSingle("NodeIdentifier", nodeIdentifier);
    if (dataLength >= 0) fs.put("DataLength", dataLength);
    return fs;
  }

  /**
   * Resolves the peer node, enforces darknet-only access, and delegates the actual payload
   * transmission to {@link #handleFeed(FcpDarknetPeerHandle)}.
   *
   * <p>The handler is expected to represent the active connection issuing this request, and the
   * resolved peer result is the authoritative routing context. When the peer is unknown, a
   * descriptive error message is sent automatically; when the peer is not part of the darknet, the
   * method throws {@link MessageInvalidException}. Subclasses should avoid heavy computation inside
   * {@code handleFeed} because it runs on whatever thread the handler uses for message dispatch.
   *
   * @param handler connection handler responsible for sending replies back to the client; must not
   *     be {@code null} and should already be authenticated.
   * @throws MessageInvalidException if the peer is not a darknet peer or if {@code handleFeed}
   *     reports an application-specific validation failure.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    FcpPeerLookupResult lookupResult =
        handler.getServer().messageRuntimeSupport().findPeer(nodeIdentifier);
    switch (lookupResult.kind()) {
      case UNKNOWN -> {
        FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, identifier);
        handler.send(msg);
      }
      case NON_DARKNET ->
          throw new MessageInvalidException(
              ProtocolErrorMessage.DARKNET_ONLY,
              getName() + " only available for darknet peers",
              identifier,
              false);
      case DARKNET -> {
        int nodeStatus = handleFeed(lookupResult.requireDarknetPeerHandle());
        handler.send(new SentPeerMessage(identifier, nodeStatus));
      }
    }
  }

  /**
   * Performs the message-specific work once the darknet peer has been validated and resolved.
   *
   * <p>Implementations typically stream data to the peer or update its state and must return a
   * status integer that will be echoed back to the client via {@link SentPeerMessage}. Implementers
   * should document the meaning of their status codes and ensure that any thrown exception provides
   * actionable details.
   *
   * @param peerHandle adapter-owned darknet peer handle already validated and guaranteed non-null
   * @return integer status communicated to the client; the subclass defines semantic range.
   * @throws MessageInvalidException if the payload cannot be accepted or violates protocol
   *     invariants enforced by the subclass.
   */
  protected abstract int handleFeed(FcpDarknetPeerHandle peerHandle) throws MessageInvalidException;

  @Override
  String getIdentifier() {
    return null;
  }

  @Override
  boolean isGlobal() {
    return false;
  }

  @Override
  long dataLength() {
    return dataLength;
  }
}
