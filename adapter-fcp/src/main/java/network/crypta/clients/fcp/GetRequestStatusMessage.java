package network.crypta.clients.fcp;

import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.SimpleFieldSet;

/**
 * FCP message that asks the node to stream the most recent status (and optionally data) for a
 * client request identified by an {@code Identifier} token.
 *
 * <p>The instance is immutable: the identifier and accompanying flags are captured from the parsed
 * {@link SimpleFieldSet} and reused whenever the message is serialized or executed. Typical callers
 * construct it from an inbound request, hand it to the active {@link FCPConnectionHandler}, and let
 * {@link #run(FCPConnectionHandler)} walk the reboot-time and persistent queues. When a match is
 * found, pending progress or data messages are forwarded; missing identifiers trigger a {@link
 * ProtocolErrorMessage} with {@link ProtocolErrorMessage#NO_SUCH_IDENTIFIER}.
 *
 * <p>Concurrency: the object is thread-safe through immutability. Execution normally occurs on the
 * connection handler's thread while persistence lookups are offloaded at normal priority to avoid
 * blocking I/O. Each call re-queries live state; no caching is retained between invocations.
 *
 * <ul>
 *   <li>Field propagation: only the {@code Identifier} is re-emitted; flags stay local.
 *   <li>Error handling: silently returns when the client database is already killed.
 *   <li>Data-only mode: {@code onlyData=true} limits replies to payload-bearing messages.
 * </ul>
 *
 * <pre>{@code
 * // Example: forwarding a parsed message to the handler
 * var message = new GetRequestStatusMessage(parsedFields);
 * message.run(handler);
 * }</pre>
 */
public class GetRequestStatusMessage extends FCPMessage {
  final String requestIdentifier;
  final boolean global;
  final boolean onlyData;
  static final String NAME = "GetRequestStatus";

  /**
   * Creates a message from the incoming field set emitted by an FCP client. The constructor copies
   * the text identifier and optional booleans immediately so later mutations to {@code fs} do not
   * leak in. The {@code Global} flag is forwarded unchanged to downstream lookups, allowing the
   * handler to choose the scope of the request search, while {@code OnlyData} controls whether
   * status updates or solely data messages are returned when pending responses are replayed.
   *
   * @param fs field container carrying {@code Identifier} plus optional {@code Global} and {@code
   *     OnlyData} flags; must be non-null, already parsed from the wire, and logically consistent
   *     with the caller's protocol validation.
   */
  public GetRequestStatusMessage(SimpleFieldSet fs) {
    this.requestIdentifier = fs.get("Identifier");
    this.global = fs.getBoolean("Global", false);
    this.onlyData = fs.getBoolean("OnlyData", false);
  }

  /**
   * Serializes this command back into an FCP field set for transmission.
   *
   * <p>The returned structure is freshly allocated on each call to avoid cross-request mutation and
   * contains only the identifier field required by the remote peer. The runtime-only flags
   * intentionally remain local to prevent accidental leakage of connection-scoped preferences to
   * other clients or to diagnostic tooling that echoes FCP messages. Callers may use the result to
   * mirror the original request on another connection or to log the canonical wire representation.
   *
   * @return a new {@link SimpleFieldSet} containing the {@code Identifier} originally supplied;
   *     flags are runtime-only and are not re-emitted.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", requestIdentifier);
    return fs;
  }

  /**
   * Returns the canonical FCP message name for status queries.
   *
   * <p>The literal string is used by both protocol dispatchers and logging facilities to label the
   * message type. Keeping the value in a single constant avoids drift between serialization,
   * documentation, and switch-based handling inside {@link FCPConnectionHandler}. The name does not
   * vary with flags or runtime state, ensuring stable routing keys even when multiple status
   * requests for different identifiers are in flight.
   *
   * @return the literal {@code "GetRequestStatus"} string used on the wire.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the query against the node and streams any pending status or data responses back to
   * the requesting connection.
   *
   * <p>The handler is consulted for reboot-time queues first; if no match is found, the lookup is
   * delegated to the persistent job runner. When a request is located, pending messages are pushed
   * to the caller in the order maintained by {@link ClientRequest#sendPendingMessages}. If neither
   * queue contains the identifier, a {@link ProtocolErrorMessage} is sent. When the client database
   * has been killed, the method exits silently to match legacy behavior.
   *
   * @param handler connection-scoped dispatcher that resolves client requests and emits replies;
   *     must not be null and typically represents the active FCP session.
   * @throws MessageInvalidException if the handler detects protocol-level validation problems
   *     unrelated to missing identifiers.
   */
  @Override
  public void run(final FCPConnectionHandler handler) throws MessageInvalidException {
    ClientRequest req = handler.getRebootRequest(global, handler, requestIdentifier);
    if (req == null) {
      RequestQueuePort requestQueuePort = handler.getServer().runtime().requestQueue();
      if (requestQueuePort.isPersistenceDatabaseKilled()) {
        // Ignore.
        return;
      }
      try {
        requestQueuePort.submitPersistentJob(
            () -> {
              ClientRequest req1 = handler.getForeverRequest(global, handler, requestIdentifier);
              if (req1 == null) {
                ProtocolErrorMessage msg =
                    new ProtocolErrorMessage(
                        ProtocolErrorMessage.NO_SUCH_IDENTIFIER,
                        false,
                        null,
                        requestIdentifier,
                        global);
                handler.send(msg);
              } else {
                req1.sendPendingMessages(
                    handler.getOutputHandler(), requestIdentifier, true, onlyData);
              }
              return false;
            },
            RequestQueuePriority.NORMAL);
      } catch (RequestQueueUnavailableException _) {
        ProtocolErrorMessage msg =
            new ProtocolErrorMessage(
                ProtocolErrorMessage.NO_SUCH_IDENTIFIER, false, null, requestIdentifier, global);
        handler.send(msg);
      }
    } else {
      req.sendPendingMessages(handler.getOutputHandler(), requestIdentifier, true, onlyData);
    }
  }
}
