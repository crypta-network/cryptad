package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.BucketTools;

/**
 * Base class for FCP messages that send multiple binary payload segments in a single message
 * instance.
 *
 * <p>Where {@link DataCarryingMessage} implementations typically stream a single {@link Bucket}
 * payload, this type manages a small ordered collection of buckets identified by field-name
 * prefixes. Each entry in {@link #buckets} contributes both a length field (for example {@code
 * SomePartLength}) in the {@link SimpleFieldSet} header and a corresponding sequence of bytes in
 * the trailing payload region. The overall data length reported to the protocol layer is the sum of
 * all bucket sizes.
 *
 * <p>Instances of this class are generally constructed and populated on the server side shortly
 * before being written to an {@link OutputStream}. The API is intentionally one-way: {@link
 * #readFrom(InputStream, BucketFactory, FCPServer)} is not supported and will always throw, because
 * decoding arbitrary multipart payloads depends on message-specific conventions. Subclasses provide
 * higher-level methods for inserting buckets in the correct order and with appropriate field names.
 *
 * <p>Thread-safety: instances are mutable and not inherently thread-safe. Callers should confine
 * each message to a single thread (typically the connection handler) between construction and
 * sending. The {@link #buckets} map preserves insertion order so that both header fields and
 * payload segments appear deterministically on the wire.
 *
 * @see BaseDataCarryingMessage
 * @see DataCarryingMessage
 * @see Bucket
 */
public abstract class MultipleDataCarryingMessage extends BaseDataCarryingMessage {

  // The iteration order matters, hence a LinkedHashMap
  /**
   * Collection of payload segments that will be serialized as part of this message.
   *
   * <p>Keys represent the logical field name prefix for each segment (for example {@code
   * "Metadata."} or {@code "Data."}), while values are {@link Bucket} instances that provide the
   * actual bytes. The concrete subclass is responsible for populating this map before sending the
   * message, typically by creating buckets through a {@link BucketFactory} and inserting them in
   * the desired order. The {@link LinkedHashMap} preserves insertion order so that header fields
   * and payload segments are emitted in a predictable sequence.
   */
  protected Map<String, Bucket> buckets = new LinkedHashMap<>();

  /**
   * Flag indicating whether buckets should be freed immediately after the message is sent.
   *
   * <p>When set to {@code true}, {@link #writeData(OutputStream)} calls {@link Bucket#free()} on
   * each bucket as soon as its contents have been written to the output stream. This is useful for
   * large, transient payloads that are not reused after transmission and allows backing resources
   * (such as temporary files or off-heap buffers) to be reclaimed promptly. Subclasses typically
   * toggle this flag through {@link #setFreeOnSent()} once they have finished constructing the
   * payload.
   */
  protected boolean freeOnSent;

  /**
   * Marks this message so that its buckets are freed once the payload has been written.
   *
   * <p>Calling this method is idempotent and only affects the behavior of the subsequent {@link
   * #writeData(OutputStream)} invocation. It does not free any buckets immediately; instead, each
   * bucket is released after its bytes have been copied to the output stream. This is typically
   * used for messages whose payload is generated on demand and does not need to be retained after
   * the client has received it.
   */
  @SuppressWarnings("unused")
  void setFreeOnSent() {
    freeOnSent = true;
  }

  // We can't read an arbitrary multiple data carrying message from an InputStream
  // This class is only used to send such messages to the client
  /**
   * Unsupported operation for {@code MultipleDataCarryingMessage}.
   *
   * <p>This implementation always throws {@link UnsupportedOperationException}. The class is
   * intended exclusively for constructing outgoing messages that aggregate multiple payload
   * segments; the corresponding on-wire representations are parsed by message-specific logic
   * elsewhere in the FCP stack. As a result, there is no generic format that would allow an
   * arbitrary instance of this type to be reconstructed from an {@link InputStream}.
   *
   * @param is input stream that would otherwise carry the binary payload; ignored by this
   *     implementation
   * @param bf bucket factory that would normally create storage for the decoded data; ignored here
   * @param server server instance associated with the connection; ignored by this implementation
   * @throws IOException never thrown by this implementation, declared to satisfy the superclass
   *     contract
   * @throws MessageInvalidException never thrown by this implementation, declared to satisfy the
   *     superclass contract
   * @throws UnsupportedOperationException always thrown to signal that reading into this message
   *     type is not supported
   */
  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException {
    throw new UnsupportedOperationException();
  }

  /**
   * Writes all buckets contained in this message to the supplied output stream.
   *
   * <p>The method iterates over {@link #buckets} in insertion order and delegates to {@link
   * BucketTools#copyTo(Bucket, OutputStream, long)} to stream each bucket's content. If {@link
   * #freeOnSent} is {@code true}, each bucket is freed immediately after its data has been written.
   * The output stream is not closed or flushed by this method; callers are responsible for
   * connection-level lifecycle management.
   *
   * @param os output stream that receives the concatenated payload segments; must remain open and
   *     writable for the duration of the call
   * @throws IOException if an I/O error occurs while reading from a bucket or writing to {@code os}
   */
  @Override
  protected void writeData(OutputStream os) throws IOException {
    for (Map.Entry<String, Bucket> entry : buckets.entrySet()) {
      Bucket bucket = entry.getValue();
      BucketTools.copyTo(bucket, os, bucket.size());
      if (freeOnSent) bucket.free(); // Always transient so no removeFrom() needed.
    }
  }

  /**
   * Builds the structured field set describing this message's payload.
   *
   * <p>For each entry in {@link #buckets}, this method adds a length field whose name is
   * constructed by appending {@code "Length"} to the bucket key. It also accumulates the total
   * payload size in bytes and publishes it under the {@code "DataLength"} field. This information
   * enables FCP clients to allocate buffers or progress indicators before the payload bytes
   * themselves are streamed over the connection.
   *
   * <p>The returned {@link SimpleFieldSet} is newly created on each invocation and may be freely
   * modified by the caller without affecting the internal state of the message.
   *
   * @return a field set that includes per-part length fields and the aggregated {@code DataLength}
   *     value describing the binary payload of this message
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    long dataLength = 0;
    SimpleFieldSet fs = new SimpleFieldSet(true);
    for (Map.Entry<String, Bucket> entry : buckets.entrySet()) {
      String field = entry.getKey();
      Bucket bucket = entry.getValue();
      fs.put(field + "Length", bucket.size());
      dataLength += bucket.size();
    }
    fs.put("DataLength", dataLength);
    return fs;
  }

  /**
   * Returns the sum of the sizes of all buckets that make up this message's payload.
   *
   * <p>This value matches the {@code DataLength} field produced by {@link #getFieldSet()} and
   * represents the exact number of bytes that {@link #writeData(OutputStream)} will attempt to
   * stream to the client. If the bucket collection is empty, the method returns {@code 0}. The
   * value is recomputed on each call by iterating over {@link #buckets}, so callers that need it
   * repeatedly should cache the result if performance is critical.
   *
   * @return total payload length in bytes across all buckets currently stored in {@link #buckets}
   */
  @Override
  public long dataLength() {
    long dataLength = 0;
    for (Bucket bucket : buckets.values()) dataLength += bucket.size();
    return dataLength;
  }

  /**
   * Returns the marker string that separates the header from the binary payload in the on-wire
   * representation of this message.
   *
   * <p>For multipart payload messages the literal string {@code "Data"} is used, matching the
   * semantics of other data-carrying FCP messages. The surrounding infrastructure uses this value
   * when composing or parsing the textual header and when deciding whether additional payload bytes
   * follow.
   *
   * @return the header terminator token {@code "Data"}, indicating that payload bytes follow
   */
  @Override
  String getEndString() {
    return "Data";
  }
}
