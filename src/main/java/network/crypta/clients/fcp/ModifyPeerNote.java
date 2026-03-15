package network.crypta.clients.fcp;

import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.Base64;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FCP message that updates the note associated with a single darknet peer.
 *
 * <p>The {@code ModifyPeerNote} message is sent by a client over the Freenet Client Protocol (FCP)
 * when it wants to attach or change a human-readable note on a known darknet peer. The message
 * carries the target peer identifier, a numeric peer-note type, and a Base64-encoded note body.
 * This implementation focuses on the private darknet comment note type used for descriptive or
 * operational annotations that are not exposed publicly on the network.
 *
 * <p>On execution, the message handler validates that the connection has full access, resolves the
 * referenced peer through the runtime peer-management SPI, and verifies that the requested
 * operation applies to a darknet peer. It then parses the note type, decodes the supplied Base64
 * payload into UTF-8 text, and applies the change when the note type is supported. Errors in access
 * control, field presence, parsing, or peer lookup are surfaced as protocol-level failures, either
 * by throwing {@link MessageInvalidException} or by sending dedicated FCP error messages back
 * through the connection handler.
 *
 * <p>This class is stateless beyond the parsed request fields and is typically used only for the
 * lifetime of a single inbound message. Instances are not intended to be shared across threads
 * after construction.
 *
 * @see PeerNote
 * @see FCPMessage
 */
public class ModifyPeerNote extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ModifyPeerNote.class);

  static final String NAME = "ModifyPeerNote";

  final SimpleFieldSet fs;
  final String requestIdentifier;

  /**
   * Creates a new {@code ModifyPeerNote} message wrapper from an incoming field set.
   *
   * <p>The provided {@link SimpleFieldSet} is expected to contain the standard FCP fields used by
   * this message, including the client {@code Identifier} and all note-related values. The
   * constructor extracts and stores the identifier for later use, then removes it from the backing
   * field set so that only message-specific fields remain. No validation of required fields is
   * performed here; it is deferred to {@link #run(FCPConnectionHandler, Node)}.
   *
   * @param fs the non-{@code null} field set describing the request, including {@code Identifier}
   *     and note-related fields supplied by the FCP client
   */
  public ModifyPeerNote(SimpleFieldSet fs) {
    this.fs = fs;
    requestIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  /**
   * Returns the field template for this message type.
   *
   * <p>The current implementation returns a new, empty {@link SimpleFieldSet} instance. This is
   * enough because {@code ModifyPeerNote} is handled primarily as an inbound message parsed from
   * the client, and the node does not need to advertise additional fields when constructing
   * responses. Callers should not rely on the returned instance being reused.
   *
   * @return a new, empty field set instance representing the message fields for this type
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Returns the protocol-level name for this FCP message.
   *
   * <p>The name identifies this message type on the wire and is used by both client and node code
   * when routing or dispatching FCP commands. The value is stable and should not be localized or
   * modified by callers.
   *
   * @return the constant {@code "ModifyPeerNote"} used as the FCP message name
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the {@code ModifyPeerNote} request against the running node.
   *
   * <p>This method enforces full-access permissions on the connection, extracts the target peer
   * identifier from the backing field set, and resolves the peer through the runtime SPI before any
   * note-type-specific handling. Only darknet peers are accepted; other peer types cause a protocol
   * error. The handler then parses the peer-note type, decodes the Base64-encoded {@code NoteText}
   * value, applies the note when the note type is supported, and sends a {@link PeerNote} message
   * back to the client reflecting the new state. Invalid or missing fields cause {@link
   * MessageInvalidException} to be thrown or a specific error response to be sent.
   *
   * <p>The method is not idempotent with respect to note contents: later calls with the same peer
   * and note type overwrite the existing note. Behavior is undefined if the node is stopping or the
   * referenced peer disappears concurrently.
   *
   * @param handler the connection handler that received the request and is used to send any reply
   *     or error messages back to the client; must have full access for the operation to proceed
   * @param node node instance supplied by the legacy FCP dispatch signature; unused because peer
   *     note mutation is delegated through the runtime SPI
   * @throws MessageInvalidException if the caller lacks access rights, required fields are missing
   *     or malformed, or the peer cannot be updated under the current protocol rules
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ModifyPeerNote requires full access",
          requestIdentifier,
          false);
    }
    String nodeIdentifier = fs.get("NodeIdentifier");
    if (nodeIdentifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Error: NodeIdentifier field missing",
          requestIdentifier,
          false);
    }
    PeerPort peerPort = handler.getServer().runtime().peer();
    if (!ensureDarknetPeerExists(handler, peerPort, nodeIdentifier)) {
      return;
    }
    int peerNoteType;
    try {
      peerNoteType = fs.getInt("PeerNoteType");
    } catch (FSParseException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Error parsing PeerNoteType field: " + e.getMessage(),
          requestIdentifier,
          false);
    }
    String encodedNoteText = fs.get("NoteText");
    if (encodedNoteText == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Error: NoteText field missing",
          requestIdentifier,
          false);
    }
    String noteText;
    // Note: this supports the single private note type until PeerNode supports multiple notes.
    try {
      noteText = Base64.decodeUTF8(encodedNoteText);
    } catch (IllegalBase64Exception e) {
      LOG.error(
          "Bad Base64 encoding when decoding a FCP-received private darknet comment SimpleFieldSet",
          e);
      return;
    }
    if (peerNoteType != Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT) {
      FCPMessage msg = new UnknownPeerNoteTypeMessage(peerNoteType, requestIdentifier);
      handler.send(msg);
      return;
    }
    try {
      String storedNoteText = peerPort.writePrivateDarknetComment(nodeIdentifier, noteText);
      handler.send(new PeerNote(nodeIdentifier, storedNoteText, peerNoteType, requestIdentifier));
    } catch (UnknownPeerException _) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, requestIdentifier);
      handler.send(msg);
    } catch (DarknetPeerRequiredException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DARKNET_ONLY,
          "ModifyPeerNote only available for darknet peers",
          requestIdentifier,
          false);
    }
  }

  /**
   * Resolves the target peer through the runtime SPI before any note-type-specific handling.
   *
   * <p>The legacy daemon-backed implementation validated peer existence and darknet eligibility
   * before parsing or validating note contents. The SPI does not expose a generic peer-note
   * capability probe, so this method uses the existing private-comment read operation as a
   * non-mutating preflight to preserve the original FCP error precedence.
   *
   * @param handler connection handler used to send protocol error responses back to the client
   * @param peerPort runtime peer-management port used to resolve the target peer
   * @param nodeIdentifier peer identifier supplied by the FCP client
   * @return {@code true} if the peer exists and supports darknet notes, otherwise {@code false}
   *     after sending the appropriate unknown-node response
   * @throws MessageInvalidException if the peer exists but is not a darknet peer
   */
  private boolean ensureDarknetPeerExists(
      FCPConnectionHandler handler, PeerPort peerPort, String nodeIdentifier)
      throws MessageInvalidException {
    try {
      peerPort.readPrivateDarknetComment(nodeIdentifier);
      return true;
    } catch (UnknownPeerException _) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, requestIdentifier);
      handler.send(msg);
      return false;
    } catch (DarknetPeerRequiredException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DARKNET_ONLY,
          "ModifyPeerNote only available for darknet peers",
          requestIdentifier,
          false);
    }
  }
}
