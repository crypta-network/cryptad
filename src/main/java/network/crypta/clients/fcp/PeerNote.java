package network.crypta.clients.fcp;

import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents an FCP {@code PeerNote} message delivered from a node to a client.
 *
 * <p>The message packages a node identifier, a classified note type, and a UTF-8 note body that is
 * Base64 encoded to comply with the text-only framing used by the Freenet Client Protocol. It is
 * created server side and emitted toward connected clients; when invoked in the opposite direction
 * it is rejected as invalid. Instances are immutable after construction, so they can be safely
 * retained or shared between threads as long as the underlying note content does not change.
 * Typical consumers forward the produced {@link SimpleFieldSet} to the outbound FCP transport and
 * rely on the note type to decide how the recipient should interpret the note.
 *
 * <ul>
 *   <li>Encodes note text in Base64 with UTF-8 input semantics.
 *   <li>Includes the origin node identifier so clients can correlate notes to peers.
 *   <li>Optionally carries a message identifier for request/response correlation.
 * </ul>
 *
 * @see FCPMessage
 * @see SimpleFieldSet
 */
public class PeerNote extends FCPMessage {

  static final String NAME = "PeerNote";

  final String noteText;
  final int peerNoteType;
  final String nodeIdentifier;
  final String messageIdentifier;

  /**
   * Creates a peer note payload ready for transmission to an FCP client.
   *
   * <p>The constructor captures the immutable node identifier, the textual note content, and a
   * numeric type that indicates how the receiver should categorize the note. The optional message
   * identifier allows callers to correlate responses when a note is sent in reply to a previous
   * request; it may be {@code null} for unsolicited notifications. Note text is accepted verbatim
   * here and is Base64 encoded later when the field set is built, keeping construction lightweight
   * and deferring encoding costs to the serialization step.
   *
   * <pre>{@code
   * // Example: create a categorized note for a known peer
   * PeerNote note = new PeerNote(peerId, "Peer capacity changed", 2, "note-42");
   * }</pre>
   *
   * @param noteText human-readable note body in UTF-8; empty strings are permitted but discouraged.
   * @param peerNoteType integer classification flag understood by the remote endpoint; non-negative
   *     values typically map to predefined categories.
   * @param identifier optional correlation identifier attached to the outbound message; may be
   *     {@code null} when no response is expected.
   */
  public PeerNote(String nodeIdentifier, String noteText, int peerNoteType, String identifier) {
    this.nodeIdentifier = nodeIdentifier;
    this.noteText = noteText;
    this.peerNoteType = peerNoteType;
    this.messageIdentifier = identifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} representation for outbound transmission.
   *
   * <p>The returned field set contains the node identifier, the numeric note type, and the note
   * text encoded with {@link Base64#encodeUTF8(String, boolean)} to maintain transport safety in
   * the text-oriented FCP protocol. When a message identifier was supplied at construction time, it
   * is added under the {@code Identifier} key; otherwise the key is omitted. A fresh field set is
   * created on every call to avoid unintended sharing between multiple dispatches.
   *
   * @return new field set containing all message parts encoded for the FCP wire format.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("NodeIdentifier", nodeIdentifier);
    fs.put("PeerNoteType", peerNoteType);
    fs.putSingle("NoteText", Base64.encodeUTF8(noteText, true));
    if (messageIdentifier != null) fs.putSingle("Identifier", messageIdentifier);
    return fs;
  }

  /**
   * Returns the protocol name for this message type.
   *
   * <p>The name is a fixed constant ({@value #NAME}) used by the FCP framing layer to advertise the
   * message kind to peer implementations. The value never changes across instances or executions.
   *
   * @return constant string {@code "PeerNote"} expected by FCP clients and servers.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects attempts to process {@code PeerNote} messages sent from a client to the server.
   *
   * <p>{@code PeerNote} is a server-to-client notification, so receiving it from a client indicates
   * protocol misuse or a buggy peer. This method enforces the direction constraint by always
   * throwing a {@link MessageInvalidException}, allowing the caller to generate a protocol error
   * response that explains the violation. No state is modified prior to raising the exception.
   *
   * @param handler connection context invoking the message handler; used only for validation.
   * @throws MessageInvalidException always thrown to signal that the message direction is invalid.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PeerNote goes from server to client not the other way around",
        messageIdentifier,
        false);
  }
}
