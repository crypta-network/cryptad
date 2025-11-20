package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.BucketTools;

/**
 * Carries server-generated metadata as an outgoing FCP message.
 *
 * <p>This message wraps a {@link Bucket} produced while servicing a client request and is written
 * to the wire by the node when responding with generated metadata. Each instance is bound to a
 * stable request identifier and a {@code global} flag to signal whether the metadata is shareable
 * across the node. The payload remains in the bucket until {@link #writeData(OutputStream)} streams
 * it, allowing callers to avoid buffering the content in memory.
 *
 * <p>The class is effectively immutable after construction, but thread-safety depends on the
 * supplied {@link Bucket} implementation; use a single sending pipeline per instance to avoid
 * concurrent reads on non-thread-safe buckets. The class intentionally omits inbound parsing, so
 * {@link #readFrom(InputStream, BucketFactory, FCPServer)} always throws.
 *
 * <ul>
 *   <li>Responsibilities: expose FCP name, headers, payload length, and streaming serializer.
 *   <li>Non-goals: accepting inbound metadata or mutating the backing bucket contents.
 * </ul>
 *
 * @see BaseDataCarryingMessage
 * @see Bucket
 */
public class GeneratedMetadataMessage extends BaseDataCarryingMessage {

  GeneratedMetadataMessage(String identifier, boolean global, Bucket data) {
    this.identifier = identifier;
    this.global = global;
    this.data = data;
  }

  private final Bucket data;
  final String identifier;
  final boolean global;

  static final String NAME = "GeneratedMetadata";

  /**
   * Returns the number of bytes that will be streamed for this message.
   *
   * <p>The value is obtained directly from the backing {@link Bucket} to avoid duplicating length
   * bookkeeping. Callers can use the result to preallocate buffers or to populate header fields
   * before invoking {@link #writeData(OutputStream)}. The length reflects the bucket state at the
   * time of the call; subsequent writes should use the same instance to keep headers and payload
   * consistent.
   *
   * @return total payload size in bytes as currently reported by the bucket, never negative
   */
  @Override
  long dataLength() {
    return data.size();
  }

  /**
   * Inbound parsing is not supported for generated metadata messages.
   *
   * <p>This class represents an outbound-only message; creation is driven by callers that already
   * hold the payload. Any attempt to populate an instance from an incoming stream results in an
   * {@link UnsupportedOperationException}. Use message types that implement parsing when handling
   * data originating from a peer.
   *
   * @param is input stream that would carry message body; ignored because parsing is disabled
   * @param bf bucket factory normally used to allocate payload storage; ignored for this type
   * @param server server context passed by the FCP layer; ignored because parsing is unsupported
   * @throws IOException never thrown; declared to match the interface contract
   * @throws MessageInvalidException never thrown; declared to satisfy caller expectations
   */
  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException {
    throw new UnsupportedOperationException();
  }

  /**
   * Streams the metadata payload to the supplied output stream.
   *
   * <p>The entire bucket is copied using {@link BucketTools#copyTo(Bucket, OutputStream, long)} so
   * the output receives exactly {@link #dataLength()} bytes. The method does not close or flush the
   * provided stream; callers remain responsible for stream lifecycle, backpressure handling, and
   * error recovery if the downstream consumer fails partway through the transfer. This method is
   * intended for single-use serialization; mutating the bucket between successive calls may produce
   * inconsistent results.
   *
   * @param os destination stream that will receive the payload bytes without being closed
   * @throws IOException if the underlying stream rejects the write or an I/O interruption occurs
   */
  @Override
  protected void writeData(OutputStream os) throws IOException {
    BucketTools.copyTo(data, os, data.size());
  }

  /**
   * Builds the FCP field set describing this message.
   *
   * <p>The returned {@link SimpleFieldSet} includes the caller-supplied identifier, the boolean
   * {@code Global} flag, and the numeric {@code DataLength}. The field set is created with ordered
   * keys to preserve predictable serialization. Modifying the returned structure will not affect
   * the already stored payload but can alter headers if reused across multiple sends. Clients
   * should treat the field set as message metadata and avoid embedding large values.
   *
   * <pre>{@code
   * var metadata = message.getFieldSet();
   * socket.send(metadata);
   * }</pre>
   *
   * @return new {@link SimpleFieldSet} containing identifier, global flag, and payload length
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.put("Global", global);
    fs.put("DataLength", data.size());
    return fs;
  }

  /**
   * Provides the protocol name for this FCP message type.
   *
   * <p>The value is the constant {@code GeneratedMetadata}, which the FCP layer relies on for
   * dispatching and logging. It is stable across versions and never localized, making it safe for
   * wire comparisons and routing keys. Callers should prefer this accessor over hardcoding the
   * string to avoid drift if the protocol constant is ever refactored.
   *
   * @return stable message name used in FCP routing and identification
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Execution is unsupported because generated metadata messages are outbound only.
   *
   * <p>The FCP framework invokes this method for inbound messages that carry executable semantics.
   * This class does not represent an actionable request or response on the receiving side, so it
   * immediately throws {@link UnsupportedOperationException}. Use a message type that implements
   * runnable behavior when expecting inbound execution.
   *
   * @param handler connection handler provided by the FCP server infrastructure; not used here
   * @param node local node instance; not used because the message is not executed
   * @throws MessageInvalidException never thrown; declared to satisfy superclass signature
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new UnsupportedOperationException();
  }
}
