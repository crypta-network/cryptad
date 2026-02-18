package network.crypta.clients.fcp;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;

/**
 * Defines the bidirectional channel that carries FCP plugin messages between a server plugin and a
 * client-side peer.
 *
 * <p>Connections are created through {@link PluginRespirator} helpers such as {@link
 * PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)}, allowing a plugin to
 * expose services to in-node components or remote clients that speak FCP. Each connection tracks a
 * stable {@link UUID} so requests and responses stay correlated even when multiple logical
 * operations are interleaved.
 *
 * <p>The interface documents the lifecycle expectations: clients keep the connection alive by
 * retaining a strong reference, while server implementations typically interact through adapters
 * retrieved via {@link PluginRespirator#getPluginConnectionByID(UUID)}. No persistence is provided
 * beyond the lifetime of the owning plugin or socket, so callers must recreate the connection after
 * restarts and re-establish subscriptions or outstanding synchronous operations.
 *
 * <p>Concurrency is central: asynchronous sends merely enqueue work, synchronous sends coordinate
 * reply routing, and the default direction depends on whether the connection originated on the
 * client or server side. Detailed logging can be enabled through the {@code
 * freenet.clients.fcp.FCPPluginConnection} logger to diagnose message ordering, remembering that
 * entries reflect queuing time rather than delivery time.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> carry typed messages, report connection state, and
 *       bridge synchronous as well as asynchronous FCP flows.
 *   <li><strong>Invariants:</strong> identifiers remain stable, exactly one connection exists per
 *       plugin pair and transport, and replies echo the identifier of their originating request.
 *   <li><strong>Threading:</strong> send operations may execute on pooled threads, while callbacks
 *       execute on whichever handler registered with {@link FredPluginFCPMessageHandler}.
 * </ul>
 *
 * @see FredPluginFCPMessageHandler
 * @see FCPPluginMessage
 * @see PluginRespirator
 * @author xor (xor@freenetproject.org)
 */
public interface FCPPluginConnection {

  /**
   * Enumerates the direction used when routing messages so callers can unambiguously express
   * whether the next hop is a server-side handler or a client-side handler.
   *
   * <p>The direction also drives the automatic permission stamping performed by the implementation:
   * messages headed toward the server carry the client's permission snapshot, whereas replies to
   * clients omit that metadata. Knowing the direction ahead of time allows the send logic to pick
   * the right transport path, reuse local message handlers when possible, and decide whether a weak
   * reference or a network queue must be consulted.
   */
  enum SendDirection {
    /**
     * Sends toward the plugin offering services; typically chosen by client-side code and by server
     * tests that want to self-address a request for validation.
     */
    TO_SERVER,
    /**
     * Sends toward the connected client; typically chosen by server-side code and by client tests
     * that simulate callbacks or push-style traffic.
     */
    TO_CLIENT;

    /**
     * Inverts the direction so bidirectional workflows can bounce messages back without hard coding
     * both constants.
     *
     * <p>This helper is thread-safe and does not mutate the enum. It is useful inside
     * acknowledgement loops, where code needs to address the reply to the counterpart of the
     * current hop without branching on raw enums. Because the enumeration only contains two values,
     * the operation runs in constant time and allocates no new objects.
     *
     * @return {@link SendDirection#TO_CLIENT} when invoked on {@link SendDirection#TO_SERVER}, or
     *     the opposite when starting from {@link SendDirection#TO_CLIENT}.
     */
    public final SendDirection invert() {
      return (this == TO_SERVER) ? TO_CLIENT : TO_SERVER;
    }
  }

  /**
   * Enqueues a message for asynchronous delivery in the specified direction.
   *
   * <p>The implementation stamps client permissions, persists the identifier, and dispatches the
   * work to either a network transport or the relevant {@link
   * FredPluginFCPMessageHandler#handlePluginFCPMessage(FCPPluginConnection, FCPPluginMessage)}
   * callback. Because the call returns before transmission completes, delivery is only confirmed
   * after a reply arrives or when {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)}
   * is used; multiple sends may run in parallel, and ordering is not enforced.
   *
   * <p>Reusing a {@link FCPPluginMessage} instance is forbidden and results in error logging while
   * only the first payload copy is honored. To analyze delivery timing, enable the {@code
   * freenet.clients.fcp.FCPPluginConnection} logger and cross-check identifiers on both sides of
   * the connection.
   *
   * <pre>{@code
   * // Example: enqueue an asynchronous request toward the server plugin.
   * connection.send(SendDirection.TO_SERVER, FCPPluginMessage.construct(params, null));
   * }</pre>
   *
   * @param direction indicates whether the message targets the server-side handler or the
   *     client-side handler; {@link SendDirection#invert()} is useful when flipping replies.
   * @param message immutable payload created through {@link
   *     FCPPluginMessage#construct(SimpleFieldSet, Bucket)} or one of the reply helpers; must not
   *     be null or re-sent.
   * @throws IOException if the underlying transport has been closed or cannot accept further
   *     traffic; callers should treat the connection as defunct after receiving this signal.
   * @see #sendSynchronous(SendDirection, FCPPluginMessage, long)
   */
  void send(SendDirection direction, FCPPluginMessage message) throws IOException;

  /**
   * Sends a message using the connection's default direction.
   *
   * <p>The default is {@link SendDirection#TO_SERVER} for connections handed to clients (for
   * example via {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)})
   * and {@link SendDirection#TO_CLIENT} for connections handed to servers (for example via {@link
   * PluginRespirator#getPluginConnectionByID(UUID)} or the {@link ClientSideFCPMessageHandler} /
   * {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} callbacks). Choosing this
   * overload keeps usage terse when most calls travel in one direction, while still allowing {@link
   * #send(SendDirection, FCPPluginMessage)} for explicit overrides.
   *
   * @param message immutable payload constructed through {@link FCPPluginMessage} helpers; the same
   *     instance must not be reused for multiple sends or replies.
   * @throws IOException if the connection is closed or if the implementation detects broken
   *     transport while queuing the message.
   */
  void send(FCPPluginMessage message) throws IOException;

  /**
   * Sends a message and blocks until its paired reply arrives or the timeout elapses.
   *
   * <p>This variant gives explicit control over the direction and is suitable when either side
   * needs strict request/response sequencing, deterministic throttling, or immediate access to the
   * reply without involving the asynchronous handler. A successful return guarantees that the
   * remote node accepted the request and emitted a reply, although the reply can still report an
   * application-level failure through {@link FCPPluginMessage#success}.
   *
   * <p>The timeout only governs how long the caller waits; sending continues on internal threads
   * even if the wait expires. If a timeout or transport failure occurs, the connection should be
   * considered unusable and rebuilt through {@link PluginRespirator}. {@link TimeUnit} is helpful
   * for passing nanosecond values.
   *
   * @param direction indicates which side should receive the message; use {@link
   *     #sendSynchronous(FCPPluginMessage, long)} when the default direction suffices.
   * @param message outbound payload constructed through {@link FCPPluginMessage#construct(
   *     SimpleFieldSet, Bucket)}; replies to replies are disallowed because the handshake would not
   *     complete.
   * @param timeoutNanoSeconds positive timeout expressed in nanoseconds; exceeding it triggers a
   *     failure even if the remote side eventually processes the request.
   * @return the reply {@link FCPPluginMessage}, potentially with {@link FCPPluginMessage#success}
   *     set to {@code false} along with {@link FCPPluginMessage#errorCode}.
   * @throws IOException if the connection closes before the reply is obtained or if the timeout
   *     expires without a response.
   * @throws InterruptedException if the waiting thread is interrupted before completion, allowing
   *     shutdown code to cancel in-flight exchanges.
   * @see FCPPluginConnectionImpl Implementation notes describe how synchronous sends are tracked.
   * @see #send(SendDirection, FCPPluginMessage)
   */
  FCPPluginMessage sendSynchronous(
      SendDirection direction, FCPPluginMessage message, long timeoutNanoSeconds)
      throws IOException, InterruptedException;

  /**
   * Convenience overload of {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} that
   * uses the default direction.
   *
   * <p>This is the most common form for client callers, which almost always route traffic to the
   * server, and for server callbacks that mostly target the active client. The guidance on timeouts
   * and error handling mirrors the directional overload, and replies still need to be inspected for
   * {@link FCPPluginMessage#success}.
   *
   * @param message outbound payload that must not already be marked as a reply.
   * @param timeoutNanoSeconds wait time expressed in nanoseconds; see {@link TimeUnit} helpers for
   *     conversion.
   * @return the reply message supplied by the remote endpoint.
   * @throws IOException if the connection fails before the reply is available or if the wait times
   *     out.
   * @throws InterruptedException if the waiting thread is interrupted while blocked.
   */
  FCPPluginMessage sendSynchronous(FCPPluginMessage message, long timeoutNanoSeconds)
      throws IOException, InterruptedException;

  /**
   * Exposes the stable identifier assigned to this connection.
   *
   * <p>The identifier survives for as long as the connection remains strongly referenced and is
   * used by the node to correlate network transports with plugin-side adapters. Server plugins can
   * stash the value to look up a connection later through {@link PluginRespirator} or to store
   * per-client metadata in their own persistence layer.
   *
   * @return unique {@link UUID} across all live connections owned by the node.
   * @see PluginRespirator#getPluginConnectionByID(UUID)
   */
  UUID getID();

  /**
   * Provides a human-readable description of the connection state for logging.
   *
   * <p>The exact contents are implementation specific but typically include the connection
   * identifier, direction defaults, and the addresses of attached message handlers. The string is
   * intended for diagnostics only and should not be parsed programmatically.
   *
   * @return descriptive snapshot highlighting identity and lifecycle state.
   */
  @Override
  String toString();
}
