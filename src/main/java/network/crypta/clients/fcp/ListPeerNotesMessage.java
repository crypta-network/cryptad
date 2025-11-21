package network.crypta.clients.fcp;

import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;

/**
 * Message that responds to an FCP request for a peer's private darknet note.
 *
 * <p>This message instance is created from an incoming {@link SimpleFieldSet} and keeps the
 * provided request identifier so responses can be correlated by the requester. The message is
 * effectively read-only after construction: it strips the {@code Identifier} field from the field
 * set to prevent accidental forwarding and retains only the minimal state needed for routing.
 * Typical use flows through {@link #run(FCPConnectionHandler, Node)} exactly once, where the
 * handler performs access checks, resolves the targeted peer, and returns the current note content
 * followed by {@link EndListPeerNotesMessage}.
 *
 * <p>Concurrency considerations: each instance is used by a single handler invocation and stores no
 * mutable global state, so it is thread-confined by design. The lifetime is short-lived—created
 * when the client issues the command and discarded immediately after the two response messages are
 * sent. Persistent data (the note text) remains managed by the underlying {@link DarknetPeerNode}.
 *
 * <ul>
 *   <li>Validates full-access session credentials before revealing peer notes.
 *   <li>Checks that the target peer exists and belongs to the darknet subset.
 *   <li>Streams the peer note and a terminator marker so clients can delimit the response.
 * </ul>
 */
public class ListPeerNotesMessage extends FCPMessage {

  static final String NAME = "ListPeerNotes";
  final SimpleFieldSet fs;
  final String requestIdentifier;

  /**
   * Builds a message from raw fields supplied by the client transport layer.
   *
   * <p>The constructor copies the provided field set, extracts the optional {@code Identifier} into
   * {@link #requestIdentifier}, and removes that key from the retained fields so it is not
   * forwarded upstream. The remaining data is used to validate and locate the target peer when the
   * message executes. Callers should supply a field set that already contains the {@code
   * NodeIdentifier} describing the peer whose note should be listed.
   *
   * @param fs mutable field set received from the client; must include {@code Identifier} and
   *     {@code NodeIdentifier} keys used to correlate the response
   */
  public ListPeerNotesMessage(SimpleFieldSet fs) {
    this.fs = fs;
    this.requestIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  /**
   * Returns a minimal field set representing this server-generated response.
   *
   * <p>The listing logic sends dedicated response messages rather than encoding data inside this
   * object's field set. Consequently, this call intentionally returns a fresh, empty {@link
   * SimpleFieldSet} with freenet-specific escaping enabled. The method is idempotent and creates a
   * new instance each time so callers cannot accidentally mutate shared state. It should be used
   * primarily by generic message code paths that expect a field-set representation even when none
   * is meaningful.
   *
   * @return new empty field set ready for serialization by the FCP layer; callers may modify the
   *     returned instance without affecting this message's internal state
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Provides the protocol-level name for this message type.
   *
   * <p>The returned value matches the identifier expected by FCP clients when requesting darknet
   * peer notes. It is a stable constant so log messages and routing tables can rely on it for
   * comparisons or switch statements. Because it performs no allocation beyond returning a string
   * literal, it is safe for frequent use in performance-sensitive paths.
   *
   * @return string literal {@code "ListPeerNotes"} used for message dispatch and diagnostics
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the message by validating access and streaming the current note for a darknet peer.
   *
   * <p>The handler must possess full access privileges; otherwise a {@link MessageInvalidException}
   * is thrown immediately. The method requires the {@code NodeIdentifier} field to be present in
   * the stored {@link SimpleFieldSet}; missing or unknown identifiers trigger protocol-compliant
   * error responses so clients can retry or repair the request. For darknet peers, the method sends
   * a {@link PeerNote} containing the private comment text followed by an {@link
   * EndListPeerNotesMessage} marker. Execution is single-pass and does not modify peer state.
   *
   * @param handler connection context used to check privileges and emit responses; must not be
   *     {@code null}
   * @param node local node context that resolves peer identifiers and provides stored note content;
   *     must not be {@code null}
   * @throws MessageInvalidException if access is denied, required fields are missing, or the target
   *     peer is not a darknet peer
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ListPeerNotes requires full access",
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
    PeerNode pn = node.getPeerNode(nodeIdentifier);
    if (pn == null) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, requestIdentifier);
      handler.send(msg);
      return;
    }
    if (!(pn instanceof DarknetPeerNode dpn)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DARKNET_ONLY,
          "ModifyPeer only available for darknet peers",
          requestIdentifier,
          false);
    }
    // Future enhancement: generalize for multiple peer notes per peer after PeerNode is updated
    String noteText = dpn.getPrivateDarknetCommentNote();
    handler.send(
        new PeerNote(
            nodeIdentifier,
            noteText,
            Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT,
            requestIdentifier));
    handler.send(new EndListPeerNotesMessage(nodeIdentifier, requestIdentifier));
  }
}
