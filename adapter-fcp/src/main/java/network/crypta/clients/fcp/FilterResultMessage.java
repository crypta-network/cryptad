package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;

/**
 * Carries the result of a server-side content filter test back to an FCP client.
 *
 * <p>This message captures both the textual metadata (identifier, charset, MIME type, and an
 * explicit unsafe flag) and, when permissible, the binary sample of the filtered data. The node
 * emits a {@code FilterResultMessage} after finishing its internal filtering pipeline so clients
 * can display detailed diagnostics or store the sanitized payload. Instances are intentionally
 * lightweight and immutable once constructed; the referenced {@link Bucket} is supplied by the
 * caller and therefore follows that implementation's mutability rules.
 *
 * <p>Messages are created only on the server and sent to clients; they are never accepted in the
 * opposite direction. Consumers can reliably expect the following characteristics:
 *
 * <ul>
 *   <li>The {@code Bucket} is present only when {@link #unsafeContentType} is {@code false}; raw
 *       data is withheld whenever a content type is flagged as unsafe.
 *   <li>The {@linkplain #dataLength()} result advertises the payload size clients should prepare
 *       for. A value of {@code -1} indicates that no payload accompanies the message.
 *   <li>The class is not thread-safe; callers should confine each instance to a single connection
 *       handling thread as with other {@link DataCarryingMessage} subclasses.
 * </ul>
 */
public class FilterResultMessage extends DataCarryingMessage {

  /**
   * Canonical message name announced on the wire so clients can register handlers for filter
   * results without inspecting payload contents. The value is stable across releases.
   */
  public static final String NAME = "FilterResult";

  private final String identifier;
  private final String charset;
  private final String mimeType;
  private final boolean unsafeContentType;
  private final long dataLength;

  /**
   * Create a message describing the outcome of a completed content filtering pass.
   *
   * <p>The constructor copies only primitive metadata; the {@link Bucket} reference is retained as
   * supplied, meaning the caller controls both lifecycle and mutability. When {@code
   * unsafeContentType} is {@code true}, the binary payload is deliberately suppressed and {@link
   * #dataLength()} later reports {@code -1}. Otherwise, {@link Bucket#size()} establishes the
   * advertised data length, and the bucket is attached for downstream serialization.
   *
   * @param identifier unique token that correlates responses with the originating filter request;
   *     must not be {@code null} when a client relies on matching semantics
   * @param charset canonical name (for example {@code "UTF-8"}) describing how textual payload
   *     bytes should be interpreted by the client; empty strings are allowed when unknown
   * @param mimeType MIME content type string returned by the filter engine, typically of the form
   *     {@code text/*} or {@code application/*}, enabling client-specific handling
   * @param unsafeContentType {@code true} when the filter deemed the payload unsafe to expose;
   *     forces {@link #dataLength()} to {@code -1} and suppresses the bucket reference entirely
   * @param bucket payload holder whose {@link Bucket#size()} value advertises the data length when
   *     {@code unsafeContentType} is {@code false}; may be ignored otherwise but must not be {@code
   *     null}
   */
  public FilterResultMessage(
      String identifier,
      String charset,
      String mimeType,
      boolean unsafeContentType,
      Bucket bucket) {
    this.identifier = identifier;
    this.charset = charset;
    this.mimeType = mimeType;
    this.unsafeContentType = unsafeContentType;
    if (unsafeContentType) {
      this.dataLength = -1;
    } else {
      this.dataLength = bucket.size();
      this.bucket = bucket;
    }
  }

  @Override
  String getIdentifier() {
    return identifier;
  }

  @Override
  boolean isGlobal() {
    return false;
  }

  @Override
  long dataLength() {
    return dataLength;
  }

  /**
   * Build a {@link SimpleFieldSet} representation of this message suitable for transmission.
   *
   * <p>The field set always contains identifier, charset, MIME type, an unsafe flag, and an integer
   * {@code DataLength}. When the content is unsafe the reported length is {@code -1}; callers
   * should therefore consult the unsafe flag before attempting to read the payload.
   *
   * @return a newly allocated field set containing all metadata for this message instance
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(IDENTIFIER, identifier);
    fs.putOverwrite("Charset", charset);
    fs.putOverwrite("MimeType", mimeType);
    fs.put("UnsafeContentType", unsafeContentType);
    fs.put("DataLength", dataLength);
    return fs;
  }

  /**
   * Return the FCP message identifier used in wire headers.
   *
   * <p>The value is constant and helps client handlers perform simple equality checks instead of
   * parsing the field set contents.
   *
   * @return the literal {@code FilterResult} constant representing this message type
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation always throws because {@code FilterResult} messages are server-to-client
   * only and therefore must never be executed in the inbound direction.
   *
   * @throws MessageInvalidException always thrown to signal that the client violated the protocol
   *     by attempting to send this message toward the node
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        null,
        false);
  }
}
