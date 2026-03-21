package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Represents an {@code ExpectedDataLength} notification emitted by the Freenet Client Protocol
 * implementation.
 *
 * <p>This lightweight message informs a connected client about the byte length that the node
 * expects for a specific identifier. It is typically sent while a download is still in progress so
 * that UI layers can prepare disk space, update progress meters, or judge whether the transfer
 * should continue. Instances are immutable; the identifier, global flag, and data length captured
 * in the constructor remain fixed for the life of the object, allowing the message to be safely
 * shared across threads provided callers do not mutate the returned {@link SimpleFieldSet}.
 *
 * <p>Typical usage patterns involve creating the message through higher-level request handlers and
 * serializing it back to the FCP connection using {@link #getFieldSet()} and {@link #getName()}.
 * Subclasses of {@link FCPMessage} can inspect the same metadata to correlate events. Because the
 * message only describes metadata and does not transport payloads, it has minimal performance
 * overhead and no blocking operations.
 *
 * <ul>
 *   <li>Immutable view of expected data lengths for a single identifier.
 *   <li>Safe to reuse across protocol layers as long as no caller mutates the emitted field set.
 *   <li>Contains no side effects when executed via {@link #run(FCPConnectionHandler)}.
 * </ul>
 */
public class ExpectedDataLength extends FCPMessage {
  final String messageIdentifier;
  final boolean global;
  final long dataLength;

  /**
   * Creates a new immutable descriptor for a future payload length.
   *
   * <p>The constructor simply stores the provided metadata without validation, so callers are
   * responsible for ensuring the identifier matches ongoing requests and that {@code dataLength}
   * reflects the best estimate currently available. Because the values are stored verbatim they can
   * represent either optimistic or pessimistic projections depending on the upstream calculation.
   *
   * @param identifier unique token provided by the client; must not be {@code null}.
   * @param global whether the message relates to a global request or a per-connection context.
   * @param dataLength expected payload size in bytes as reported by upstream logic.
   */
  ExpectedDataLength(String identifier, boolean global, long dataLength) {
    this.messageIdentifier = identifier;
    this.global = global;
    this.dataLength = dataLength;
  }

  /**
   * Builds a {@link SimpleFieldSet} representation suitable for wire encoding.
   *
   * <p>The returned field set contains three keys: {@code Identifier}, {@code Global}, and {@code
   * DataLength}. Each call creates a fresh instance so that callers may serialize it or add
   * transient metadata without affecting future invocations. The field set preserves insertion
   * order and uses decimal string renditions for boolean and numeric values, matching FCP framing.
   *
   * <pre>{@code
   * SimpleFieldSet fs = message.getFieldSet();
   * connection.send(message.getName(), fs);
   * }</pre>
   *
   * @return new field set with immutable snapshot of the identifier, global flag, and length.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putOverwrite("Identifier", messageIdentifier);
    fs.put("Global", global);
    fs.put("DataLength", dataLength);
    return fs;
  }

  /**
   * Provides the stable protocol name advertised on the wire.
   *
   * <p>The value never changes and matches the literal message identifier expected by the Freenet
   * Client Protocol dispatcher. Callers typically pair it with {@link #getFieldSet()} when emitting
   * responses or logging internal events.
   *
   * @return constant {@code "ExpectedDataLength"} string shared by all instances.
   */
  @Override
  public String getName() {
    return "ExpectedDataLength";
  }

  /**
   * Execution hook for inbound command handling; this implementation performs no action.
   *
   * <p>The message type is informational-only, so the server-side handler intentionally abstains
   * from altering the connection state or touching daemon internals. Implementations that treat
   * this message as a notification should intercept it earlier in the pipeline. Invoking this
   * method is safe and idempotent on any thread because the body contains no shared state access.
   *
   * @param handler active connection handler receiving the event; ignored while honoring the API.
   * @throws MessageInvalidException never thrown; declared to honor the {@link FCPMessage}
   *     contract.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    // Not supported
  }
}
