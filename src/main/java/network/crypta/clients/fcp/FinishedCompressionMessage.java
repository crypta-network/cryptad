package network.crypta.clients.fcp;

import network.crypta.client.events.FinishedCompressionEvent;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor;

/**
 * Final notification emitted after an FCP compression job completes.
 *
 * <p>This message is produced on the server side once a compression request initiated by an FCP
 * client either finishes successfully or is determined to be a no-op. It serializes the codec
 * metadata identifier, a best-effort codec name, and the original and resulting payload sizes so
 * that the client can reconcile accounting, update progress indicators, and decide whether to keep
 * or discard intermediate artifacts. Instances are immutable after construction to allow safe
 * sharing between the networking layer and any message-queueing infrastructure.
 *
 * <p>Typical usage is to create the message from a {@link FinishedCompressionEvent} surfaced by the
 * compression subsystem, then hand it to the outbound FCP pipeline for delivery. The {@code run}
 * method is intentionally defensive: receiving this message from a remote client is considered a
 * protocol violation and results in {@link MessageInvalidException}. The class performs no I/O on
 * its own and is safe to use concurrently as long as the referenced event remains unchanged.
 *
 * <ul>
 *   <li>Responsibilities: package final compression metrics and codec metadata for clients.
 *   <li>Notable behavior: resolves codec name when metadata can be mapped; otherwise labels it as
 *       {@code UNKNOWN} or {@code NONE}.
 *   <li>Thread safety: state is set at construction time and never mutated afterward.
 * </ul>
 */
public class FinishedCompressionMessage extends FCPMessage {
  final String messageIdentifier;
  final boolean global;
  final int codec;
  final long origSize;
  final long compressedSize;

  /**
   * Builds a message that mirrors the outcome of a completed compression request.
   *
   * <p>The constructor copies the salient fields from the supplied {@link FinishedCompressionEvent}
   * so that later serialization does not depend on the mutability or lifetime of the event object.
   * All arguments are required and must describe the same request instance for which this message
   * will be emitted.
   *
   * @param identifier unique message identifier supplied by the client; non-null and used to route
   *     acknowledgments back to the caller.
   * @param global {@code true} when the message should be broadcast to all interested listeners; a
   *     per-request flag when {@code false}.
   * @param event completed compression event providing codec id and pre/post sizes; must reflect
   *     the same logical operation denoted by {@code identifier}.
   */
  public FinishedCompressionMessage(
      String identifier, boolean global, FinishedCompressionEvent event) {
    this.messageIdentifier = identifier;
    this.codec = event.codec;
    this.compressedSize = event.compressedSize;
    this.origSize = event.originalSize;
    this.global = global;
  }

  /**
   * Converts the compression result into the wire-level {@link SimpleFieldSet} representation.
   *
   * <p>The field set contains the identifier, codec numeric id, human-readable codec name when the
   * metadata id can be resolved, the original and compressed byte sizes, and the global flag. When
   * the codec id is {@code -1}, the name field is set to {@code NONE}; when the id cannot be mapped
   * to a known codec, the name falls back to {@code UNKNOWN}. The returned instance is freshly
   * allocated and can be safely mutated by callers without affecting this message object.
   *
   * @return new {@link SimpleFieldSet} populated with codec metadata and size statistics for the
   *     completed compression request.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(IDENTIFIER, messageIdentifier);
    fs.put("Codec", codec);
    if (codec != -1) {
      Compressor.COMPRESSOR_TYPE compressorType =
          Compressor.COMPRESSOR_TYPE.getCompressorByMetadataID((short) codec);
      String codecName = (compressorType != null) ? compressorType.name() : "UNKNOWN";
      fs.putSingle("Codec.Name", codecName);
    } else {
      fs.putSingle("Codec.Name", "NONE");
    }
    fs.put("OriginalSize", origSize);
    fs.put("CompressedSize", compressedSize);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Identifies this message type within the FCP protocol exchange.
   *
   * <p>The name is constant and matches the token expected by FCP clients when parsing server
   * responses that report compression completion.
   *
   * @return the literal string {@code "FinishedCompression"} understood by FCP peers.
   */
  @Override
  public String getName() {
    return "FinishedCompression";
  }

  /**
   * Rejects attempts to execute the message on the server side.
   *
   * <p>Finished compression notifications are outbound-only. If the server receives one from a
   * client, the handler interprets it as a protocol error and responds with an {@link
   * MessageInvalidException}. No state is modified and no network writes occur inside this method;
   * all error reporting is deferred to the exception handling layer of the caller.
   *
   * @param handler active FCP connection handler invoking this method; ignored during validation
   *     because the message is not supposed to originate from clients.
   * @param node current node instance; provided for interface completeness but unused here.
   * @throws MessageInvalidException always thrown to signal that this message must not be received
   *     from an FCP client under the protocol rules.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "FinishedCompression goes from server to client not the other way around",
        messageIdentifier,
        global);
  }
}
