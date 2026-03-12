package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.api.BucketFactory;

/**
 * Base class for FCP messages that carry an additional binary payload alongside their structured
 * header fields.
 *
 * <p>While {@link FCPMessage} deals only with the textual part of a Freenet Client Protocol (FCP)
 * message, implementations of this type define how the trailing byte stream is read from and
 * written to a connection. Typical subclasses use {@link BucketFactory} and related abstractions to
 * buffer or stream large objects such as file data, directory structures, or metadata blocks
 * without loading them entirely into memory.
 *
 * <p>Instances are usually short-lived and owned by a single connection handler; they are not
 * inherently thread-safe and should not be shared across threads without external coordination. The
 * life cycle of a message normally follows this pattern:
 *
 * <ul>
 *   <li>the header is decoded into a {@link network.crypta.support.SimpleFieldSet} and mapped to a
 *       concrete {@code BaseDataCarryingMessage} subclass;
 *   <li>{@link #readFrom(InputStream, BucketFactory, FCPServer)} is invoked to consume the payload
 *       bytes from the input stream; and
 *   <li>later, {@link #send(OutputStream)} (which in turn calls {@link #writeData(OutputStream)})
 *       is used to write the message back to a client or peer.
 * </ul>
 *
 * <p>Subclasses must ensure that {@link #dataLength()} accurately reflects the number of bytes
 * consumed and produced so that higher-level framing on the connection remains consistent and
 * subsequent messages are parsed correctly.
 */
public abstract class BaseDataCarryingMessage extends FCPMessage {

  /**
   * Returns the length in bytes of the binary payload associated with this message.
   *
   * <p>The value is typically derived from header fields that have already been parsed before the
   * payload is read or written. A non-negative value indicates the exact number of bytes that
   * {@link #readFrom(InputStream, BucketFactory, FCPServer)} expects to consume from the incoming
   * stream and that {@link #writeData(OutputStream)} will attempt to produce when the message is
   * sent. Implementations may return a negative value to signal that no additional payload needs to
   * be transferred for this particular message instance.
   *
   * @return payload length in bytes, or a negative value if the message does not have a separate
   *     binary payload to transfer
   */
  abstract long dataLength();

  /**
   * Reads the binary payload for this message from the supplied input stream.
   *
   * <p>This method is invoked after the textual header has been parsed and an instance of the
   * concrete message type has been created. Implementations are expected to consume exactly {@code
   * dataLength()} bytes from {@code is} (when the length is non-negative), using {@code bf} to
   * allocate any temporary or persistent storage that backs the payload. The {@code server}
   * parameter provides access to connection-local configuration or services that may influence how
   * the data is stored. The input stream is not closed by this method; callers remain responsible
   * for connection-level resource management.
   *
   * <p>Subclasses should validate that the payload matches the expectations derived from the
   * header, and they should throw {@link MessageInvalidException} if inconsistencies, premature end
   * of stream, or other protocol violations are detected.
   *
   * @param is input stream positioned at the start of the payload; must provide at least {@link
   *     #dataLength()} readable bytes unless the implementation accepts a shorter payload
   * @param bf bucket factory that implementations may use to allocate storage for the decoded
   *     payload; typically non-{@code null} for messages that carry large or persistent data
   * @param server FCP server instance associated with the current connection, which may be
   *     consulted for configuration, logging, or helper services during decoding
   * @throws IOException if an I/O error occurs while reading from {@code is} or interacting with
   *     bucket storage
   * @throws MessageInvalidException if the payload is malformed, violates protocol constraints, or
   *     cannot be represented by this message implementation
   */
  public abstract void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException;

  /**
   * Sends this message, including its binary payload, to the supplied output stream.
   *
   * <p>This implementation first delegates to {@link FCPMessage#send(OutputStream)} to emit the
   * textual header and field set, and then invokes {@link #writeData(OutputStream)} to stream the
   * payload bytes. The method does not close or flush the stream; callers are responsible for
   * framing, buffering, and lifecycle management at the connection level.
   *
   * <p>Subclasses should ensure that {@link #writeData(OutputStream)} writes exactly {@link
   * #dataLength()} bytes when the length is non-negative so that subsequent messages are aligned
   * correctly on the wire.
   *
   * @param os output stream that receives the serialized message header and payload; must remain
   *     open and writable for the duration of the call
   * @throws IOException if writing either the header or payload to {@code os} fails for any reason
   */
  @Override
  public void send(OutputStream os) throws IOException {
    super.send(os);
    writeData(os);
  }

  /**
   * Writes the binary payload for this message to the given output stream.
   *
   * <p>This method is called exactly once by {@link #send(OutputStream)} after the textual header
   * has been written. Implementations should stream the payload directly to {@code os}, avoiding
   * unnecessary buffering for large objects when possible. They must not close or flush the stream,
   * as those responsibilities belong to the caller managing the underlying connection.
   *
   * <p>Implementations should honor the contract implied by {@link #dataLength()} and write a
   * number of bytes consistent with the value returned by that method so that the receiving side
   * can safely parse the next message on the connection.
   *
   * @param os output stream to receive the payload bytes; must be non-{@code null} and writable for
   *     the duration of the method call
   * @throws IOException if an error occurs while retrieving or streaming the payload to {@code os}
   */
  protected abstract void writeData(OutputStream os) throws IOException;
}
