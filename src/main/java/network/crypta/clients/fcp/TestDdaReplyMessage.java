package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * FCP message the node uses to answer a client-side TestDDA handshake with concrete file names and
 * sample content. The reply is emitted after the client initiates a directory-based DDARequest and
 * the node has chosen deterministic placeholders for the read and write probes.
 *
 * <p>The message captures the state negotiated by {@link DdaCheckJob}: directory path, optional
 * server-selected read filename, optional write filename, and an inline payload to be written by
 * the client. Consumers normally do not construct this type directly; it is built by the
 * server-side job that orchestrates the end-to-end DDA probe. The instance is immutable once
 * created, so it can safely be shared between the network thread that serializes it and any
 * diagnostic observers.
 *
 * <p>Usage expectations:
 *
 * <ul>
 *   <li>Sent from server to client immediately after a TestDDA request is accepted.
 *   <li>Provides filenames that must be echoed back in the follow-up {@code DDAResponse}.
 *   <li>Includes sample content for the write test, allowing the node to verify persistence.
 *   <li>Serialization is order-stable and contains only the fields relevant to the negotiated mode.
 * </ul>
 *
 * @see TestDdaRequestMessage
 * @see DdaCheckJob
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class TestDdaReplyMessage extends FCPMessage {

  /**
   * Message identifier emitted on the wire for the TestDDA reply stage, reused verbatim in {@link
   * #getName()} and during serialization so FCP peers can recognize the payload type.
   */
  public static final String NAME = "TestDDAReply";

  /**
   * Field key for the server-chosen filename that the client must read from the shared directory
   * when validating read access to the requested DDA location.
   */
  public static final String READ_FILENAME = "ReadFilename";

  /**
   * Field key for the filename that the client is instructed to write, enabling the node to confirm
   * write capability in the negotiated directory without risking collisions.
   */
  public static final String WRITE_FILENAME = "WriteFilename";

  /**
   * Field key containing sample data for the write probe; the client writes this exact content and
   * the node later compares it byte-for-byte to validate end-to-end write integrity.
   */
  public static final String CONTENT_TO_WRITE = "ContentToWrite";

  final DdaCheckJob checkJob;

  TestDdaReplyMessage(DdaCheckJob job) {
    this.checkJob = job;
  }

  /**
   * Serializes the negotiated TestDDA reply into a {@link SimpleFieldSet} containing only the
   * fields applicable to the current probe. The directory field is always present, while read and
   * write descriptors are added conditionally so downstream consumers can distinguish read-only and
   * write-enabled exchanges without additional flags.
   *
   * <p>The returned structure preserves insertion order for deterministic encoding and omits null
   * entries entirely, preventing ambiguous empty strings in the wire format. Callers should treat
   * the result as immutable once produced because it reflects the state captured when the {@link
   * DdaCheckJob} was created.
   *
   * @return populated field set ready for FCP serialization; contains directory and any negotiated
   *     filenames plus optional sample content for write validation.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(TestDdaRequestMessage.DIRECTORY, checkJob.directory.toString());

    if (checkJob.readFilename != null) {
      sfs.putSingle(READ_FILENAME, checkJob.readFilename.toString());
    }

    if (checkJob.writeFilename != null) {
      sfs.putSingle(WRITE_FILENAME, checkJob.writeFilename.toString());
      sfs.putSingle(CONTENT_TO_WRITE, checkJob.writeContent);
    }

    return sfs;
  }

  /**
   * Returns the canonical FCP message name for this reply, ensuring downstream serializers and
   * routers label the packet consistently during TestDDA exchanges. The value is stable and shared
   * across all instances so caches, dispatch tables, and logging frameworks can key off a single
   * token instead of inspecting payload contents. This indirection keeps the message
   * self-describing while avoiding duplication of string literals across the codebase.
   *
   * @return immutable identifier string {@code TestDDAReply} shared across all instances and
   *     visible to peers.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects attempts to process this message from the client side. TestDDA replies are strictly
   * server-to-client traffic, so invoking {@code run} on the server-side handler represents a
   * protocol violation and triggers a fatal parse error for the offending peer. The method is
   * deliberately non-idempotent: each call throws an exception to force the connection to surface a
   * clear failure instead of silently discarding unexpected traffic. No mutable state is touched,
   * which keeps the handler safe to call even if multiple validation layers attempt to process the
   * same inbound frame.
   *
   * @param handler connection handler consuming the message; supplied by dispatcher and never null.
   * @throws MessageInvalidException always thrown to signal the directionality error and terminate
   *     processing of the malformed inbound message.
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
