package network.crypta.pluginmanager;

import java.util.UUID;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.clients.fcp.FCPPluginConnection;
import network.crypta.clients.fcp.FCPPluginMessage;
import network.crypta.support.io.NativeThread;

/**
 * Handles messages exchanged between plugins over an {@link FCPPluginConnection}.
 *
 * <p>This interface is the shared super-type for both sides of a plugin-to-plugin FCP channel. A
 * plugin implements one of its child interfaces, {@link ServerSideFCPMessageHandler} or {@link
 * ClientSideFCPMessageHandler}, and provides a {@link #handlePluginFCPMessage(FCPPluginConnection,
 * FCPPluginMessage)} implementation to process received {@link FCPPluginMessage} instances and,
 * when appropriate, return a reply. This API is a rewrite of the plugin communication layer; it was
 * added 2015-03 and may change in ways which break backward compatibility.
 *
 * <p>The API is intentionally symmetric once a connection exists: both sides may send messages at
 * any time. Connection creation and teardown are controlled by the client side; the server does not
 * initiate a connection to a client on its own. The main reply to a message is expressed by this
 * method's return value. In particular, {@link FCPPluginConnection#sendSynchronous(SendDirection,
 * FCPPluginMessage, long)} delivers the reply to the waiting caller rather than dispatching it to
 * the handler.
 *
 * <p>Message handlers are expected to be lightweight and should avoid long blocking work on the
 * dispatch thread. For long-running operations, move work to another thread and use the connection
 * to send follow-up ("out of band") messages. To influence dispatch priority, additionally
 * implement {@link PrioritizedMessageHandler}. Calls can arrive on internal dispatch threads, so
 * implementations should consider thread-safety when sharing mutable state.
 *
 * <ul>
 *   <li>Return a correlated reply created via {@link FCPPluginMessage#constructReplyMessage}.
 *   <li>Use out-of-band sends for asynchronous events and progress updates.
 *   <li>Avoid long blocking work in the message dispatch thread.
 * </ul>
 *
 * <h2>Implementing a server</h2>
 *
 * <p>Implement {@link ServerSideFCPMessageHandler} on your plugin's main class to accept client
 * connections and messages.
 *
 * <h2>Implementing a client</h2>
 *
 * <p>Use {@link PluginRespirator#connectToOtherPlugin(String,
 * FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)} to connect to a server plugin and keep
 * a strong reference to the {@link FCPPluginConnection} while you want the connection open.
 *
 * <h2>Debugging</h2>
 *
 * <p>Enable DEBUG logging for {@code network.crypta.clients.fcp.FCPPluginConnection} to record all
 * queued sent and received messages. Log entries are emitted when a message is queued, not when it
 * is delivered, so log order can differ from delivery order. To record delivery order, log inside
 * your {@code handlePluginFCPMessage(...)} implementation.
 *
 * @author xor (xor@freenetproject.org)
 * @see FCPPluginConnection Connection lifecycle and transport behavior.
 */
public interface FredPluginFCPMessageHandler {

  /**
   * Handles an incoming message and optionally returns the main reply.
   *
   * <p>This is the shared entry point used by both the client and server side handlers. Implement
   * {@link ServerSideFCPMessageHandler} or {@link ClientSideFCPMessageHandler} rather than
   * implementing this base interface directly so you can follow the side-specific constraints.
   *
   * <p>The returned message, when non-{@code null}, is treated as the primary reply to {@code
   * message}. Construct replies using {@link FCPPluginMessage#constructReplyMessage} to preserve
   * correlation fields (such as {@link FCPPluginMessage#identifier}). For long-running work, do the
   * work asynchronously and send follow-up messages via {@code connection}. Replies to reply
   * messages are typically undesired; if {@code message} is already a reply (see {@link
   * FCPPluginMessage#isReplyMessage()}), return {@code null} to avoid reply loops.
   *
   * @param connection the connection that delivered the message; never {@code null}
   * @param message the received message to process; protocol-defined content
   * @return a correlated reply message, or {@code null} to not reply
   */
  FCPPluginMessage handlePluginFCPMessage(FCPPluginConnection connection, FCPPluginMessage message);

  /**
   * Server-side handler for messages received from connecting client plugins.
   *
   * <p>A plugin that offers an FCP service to other plugins implements this interface (typically on
   * the plugin's main class). Incoming messages from each connected client are dispatched to {@link
   * #handlePluginFCPMessage(FCPPluginConnection, FCPPluginMessage)}.
   *
   * <p>Connections are opened and closed by the client side. If you keep {@link
   * FCPPluginConnection} instances beyond a single call (for example to send asynchronous event
   * notifications), implement a strategy to detect and discard stale connections because there is
   * no explicit disconnect callback.
   *
   * <pre>{@code
   * public final class MyPlugin implements FredPluginFCPMessageHandler.ServerSideFCPMessageHandler {
   *   @Override
   *   public FCPPluginMessage handlePluginFCPMessage(FCPPluginConnection c, FCPPluginMessage m) {
   *     return null;
   *   }
   * }
   * }</pre>
   *
   * @see FredPluginFCPMessageHandler The parent interface FredPluginFCPMessageHandler provides an
   *     overview.
   * @see ClientSideFCPMessageHandler The opposite version of this interface for client plugins
   */
  interface ServerSideFCPMessageHandler extends FredPluginFCPMessageHandler {
    /**
     * Handles a message received from a client plugin and optionally returns the main reply.
     *
     * <p>This method is invoked on the server side of the connection and should return quickly. If
     * you need long-running work to compute a reply, or you want to send future messages that are
     * not triggered by an inbound message, keep the {@link FCPPluginConnection} (or its {@link
     * FCPPluginConnection#getID()} via {@link UUID}) and send follow-up ("out of band") messages
     * using the connection's send methods.
     *
     * <p>There is no explicit disconnection notification. If you store client connections for
     * longer than a single reply, implement an application-level liveness/garbage-collection
     * mechanism (for example ping/pong with a timeout) to prevent unbounded growth.
     *
     * <p>When sending the main reply to {@code message}, do not call a send method on {@code
     * connection}; return the reply instead. This allows the transport to associate the reply with
     * the original request and also supports synchronous senders via {@link
     * FCPPluginConnection#sendSynchronous(SendDirection, FCPPluginMessage, long)}.
     *
     * <p>If you return a reply, construct it via {@link FCPPluginMessage#constructReplyMessage} so
     * correlation fields (such as {@link FCPPluginMessage#identifier}) are preserved. If {@code
     * message} is already a reply (see {@link FCPPluginMessage#isReplyMessage()}), return {@code
     * null} to avoid reply loops.
     *
     * @param connection connection that delivered the inbound client message
     * @param message message to process; may be a reply message already
     * @return correlated reply message, or {@code null} to not reply
     */
    @Override
    FCPPluginMessage handlePluginFCPMessage(
        FCPPluginConnection connection, FCPPluginMessage message);
  }

  /**
   * Client-side handler for messages received from a server plugin.
   *
   * <p>A client plugin implements this interface to connect to a server plugin and process inbound
   * messages. After connecting via {@link PluginRespirator#connectToOtherPlugin(String,
   * FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)}, messages are dispatched to {@link
   * #handlePluginFCPMessage(FCPPluginConnection, FCPPluginMessage)}.
   *
   * <p>The server may send messages at any time, including unsolicited event notifications that are
   * not a direct response to a message you sent. Keep a strong reference to the {@link
   * FCPPluginConnection} while you want the connection to remain open.
   *
   * <pre>{@code
   * var connection = respirator.connectToOtherPlugin("OtherPlugin", handler);
   * // Keep a strong reference to connection while the connection should stay open.
   * }</pre>
   *
   * @see FredPluginFCPMessageHandler Shared lifecycle and reply semantics.
   * @see ServerSideFCPMessageHandler Server-side counterpart implemented by service providers.
   */
  interface ClientSideFCPMessageHandler extends FredPluginFCPMessageHandler {
    /**
     * Handles a message received from the server plugin and optionally returns the main reply.
     *
     * <p>After you connect using {@link PluginRespirator#connectToOtherPlugin(String,
     * FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)}, this method is invoked for each
     * message delivered from the server side. The server may also send unsolicited messages that
     * are not a direct response to a message you sent.
     *
     * <p>Keep this method lightweight and avoid long blocking work. For asynchronous operations or
     * later events, keep the {@link FCPPluginConnection} (or its {@link
     * FCPPluginConnection#getID()} via {@link UUID}) and send follow-up ("out of band") messages
     * using the connection's send methods.
     *
     * <p>When sending the main reply to {@code message}, do not call a send method on {@code
     * connection}; return the reply instead. This allows the transport to associate the reply with
     * the original request and also supports synchronous senders via {@link
     * FCPPluginConnection#sendSynchronous(SendDirection, FCPPluginMessage, long)}.
     *
     * <p>Replies to reply messages are not allowed: return {@code null} if {@code message} is
     * already a reply (see {@link FCPPluginMessage#isReplyMessage()}) to avoid infinite reply
     * loops. Prefer returning a reply when allowed so the remote side can observe success or
     * failure without waiting for a timeout. If you return a reply, construct it via {@link
     * FCPPluginMessage#constructReplyMessage} so correlation fields (such as {@link
     * FCPPluginMessage#identifier}) are preserved.
     *
     * @param connection connection that delivered the inbound server message
     * @param message message to process; may be a reply message already
     * @return correlated reply message, or {@code null} to not reply
     */
    @Override
    FCPPluginMessage handlePluginFCPMessage(
        FCPPluginConnection connection, FCPPluginMessage message);
  }

  /**
   * Optional interface for selecting the priority of message dispatch threads.
   *
   * <p>Implement this in addition to {@link FredPluginFCPMessageHandler} when you want the FCP
   * subsystem to choose a {@link NativeThread.PriorityLevel} for the thread that will invoke {@code
   * handlePluginFCPMessage(...)}. Implementations may return a constant priority for all messages
   * or vary it based on protocol-defined characteristics of the incoming {@link FCPPluginMessage}.
   */
  interface PrioritizedMessageHandler {
    /**
     * Returns the desired thread priority for dispatching a specific message.
     *
     * <p>The FCP subsystem may call this before invoking {@code handlePluginFCPMessage(...)} to
     * choose an appropriate {@link NativeThread.PriorityLevel} for the message dispatch thread.
     * Implementations may return a constant priority for all messages or vary the priority based on
     * message type, size, or other protocol-defined characteristics.
     *
     * @param message message about to be dispatched; examine to choose priority
     * @return the priority level to use for handling this message
     */
    NativeThread.PriorityLevel getPriority(FCPPluginMessage message);
  }
}
