package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Immutable outbound FCP message that expresses the MIME type a client expects in a response.
 *
 * <p>FCP clients send {@code ExpectedMIME} immediately after initiating a high-level request to
 * inform the node about the preferred {@code Metadata.ContentType}. The node forwards this hint to
 * downstream components so HTTP translations or persistence layers can pick suitable serializers.
 * Instances of this class are lightweight value objects; callers typically create one per request,
 * transmit it over the {@link FCPConnectionHandler}, and then discard it.
 *
 * <p>The identifier and MIME type are stored as provided without validation because FCP acts as a
 * thin transport. Callers must therefore ensure the identifier uniquely scopes the outstanding
 * request and that the MIME value follows RFC 2046 syntax (for example {@code text/plain}). The
 * {@code global} flag mirrors the protocol bit that tells the node whether the preference applies
 * to the entire request or only to a single transfer segment.
 *
 * <ul>
 *   <li><strong>Thread safety:</strong> instances are immutable and can be shared across threads
 *       without coordination.
 *   <li><strong>Lifecycle:</strong> once a message is serialized via {@link #getFieldSet()}, the
 *       instance carries no additional state; repeated {@link #getFieldSet()} calls allocate new
 *       {@link SimpleFieldSet} objects.
 *   <li><strong>Usage pattern:</strong> create the message, emit it via {@link #send}, and expect
 *       no server-side action because {@link #run(FCPConnectionHandler)} is intentionally a no-op.
 * </ul>
 *
 * @see FCPMessage
 * @see FCPConnectionHandler
 */
public class ExpectedMIME extends FCPMessage {

  final String messageIdentifier;
  final boolean global;
  final String expectedContentType;

  ExpectedMIME(String identifier, boolean global, String expectedMIME) {
    this.messageIdentifier = identifier;
    this.global = global;
    this.expectedContentType = expectedMIME;
  }

  /**
   * Builds a {@link SimpleFieldSet} representation ready for transmission over an FCP socket.
   *
   * <p>The resulting field set always contains the identifier supplied at construction time, the
   * boolean {@code Global} flag, and—when non-{@code null}—the preferred MIME string stored under
   * {@code Metadata.ContentType}. The method allocates a fresh {@link SimpleFieldSet} on each call
   * to keep instances thread-safe and avoids mutating shared state. Callers may cache the result if
   * they plan to send the message multiple times.
   *
   * @return a new field set containing {@code Identifier}, {@code Global}, and optional {@code
   *     Metadata.ContentType} entries suitable for {@link #send}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putOverwrite("Identifier", messageIdentifier);
    fs.put("Global", global);
    fs.putOverwrite("Metadata.ContentType", expectedContentType);
    return fs;
  }

  /**
   * Returns the literal protocol name {@code "ExpectedMIME"} used by {@link FCPMessage}
   * serialization.
   *
   * <p>This value never changes and allows dispatchers to recognize the message type when reading
   * textual traffic or composing outgoing frames. Because the name is constant, callers can compare
   * it via reference equality if desired.
   *
   * @return the {@code ExpectedMIME} message name mandated by the FCP specification.
   */
  @Override
  public String getName() {
    return "ExpectedMIME";
  }

  /**
   * Performs no server-side work because {@code ExpectedMIME} only carries client preferences.
   *
   * <p>The node records MIME hints while parsing inbound FCP traffic, so invoking this method from
   * server tooling is unnecessary. The override exists solely to satisfy the {@link FCPMessage}
   * contract and communicates that receiving this message should not attempt side effects.
   *
   * @param handler connection handler that received the message; unused but required by the API.
   * @throws MessageInvalidException never thrown because the method does not perform validation.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    // Not supported
  }
}
