package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * FCP message that toggles feed alert delivery for a client connection.
 *
 * <p>This message allows an FCP client to start or stop receiving alert feed updates produced by
 * the node. When enabled, the associated {@link FCPConnectionHandler} is registered with the node's
 * alert subsystem so that server-side feed events are forwarded to the client session. When
 * disabled, the handler is removed and the session will no longer be notified about feed changes.
 * Typical call patterns send this message once during client initialization to opt in, and again
 * before disconnecting or suspending to silence further alerts.
 *
 * <p>The message is lightweight: it carries only a boolean flag and is processed synchronously on
 * the connection thread. It does not persist state beyond the lifetime of the connection and
 * assumes the handler remains valid for the duration of the watch. The class itself is immutable
 * and thread-safe; concurrency control is delegated to the surrounding connection infrastructure.
 *
 * <ul>
 *   <li>Registers or unregisters alert watching for one client session.
 *   <li>Relies on {@link SimpleFieldSet} encoding with an {@code Enabled} boolean key.
 *   <li>Intended for interactive clients needing near-real-time feed notifications.
 * </ul>
 *
 * @see network.crypta.clients.fcp.FCPConnectionHandler
 * @see network.crypta.runtime.alerts.UserAlertManager
 */
public class WatchFeedsMessage extends FCPMessage {

  /** Message identifier used on the wire and returned by {@link #getName()}. */
  public static final String NAME = "WatchFeeds";

  /**
   * Indicates whether alert watching should be enabled ({@code true}) or disabled ({@code false})
   * for the current connection. The value is immutable and mirrors the {@code Enabled} field parsed
   * from the incoming request.
   */
  public final boolean enabled;

  /**
   * Creates a new message instance from a serialized field set received over FCP.
   *
   * <p>The constructor extracts the {@code Enabled} boolean flag from the provided {@link
   * SimpleFieldSet}. If the key is absent, watching defaults to "enabled" so clients that omit the
   * field still receive alerts. The instance is immutable and may be reused across handler calls,
   * but it is typically constructed per incoming request.
   *
   * @param fs field set containing the {@code Enabled} key; must not be {@code null} and should
   *     originate from a validated FCP request envelope.
   */
  public WatchFeedsMessage(SimpleFieldSet fs) {
    enabled = fs.getBoolean("Enabled", true);
  }

  /**
   * Returns the protocol name of this message for serialization and dispatch.
   *
   * @return constant {@link #NAME} string used by the FCP dispatcher; never {@code null}.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Applies the watch toggle to the current connection's alert routing.
   *
   * <p>When {@link #enabled} is {@code true}, the method registers the handler with the node's
   * alert broadcaster so feed notifications flow to the client. When {@code false}, it unregisters
   * the handler to suppress further notifications. The operation runs synchronously on the
   * connection thread and assumes both the handler and node are fully initialized. No persistence
   * is performed; the effect lasts only for the lifetime of the handler.
   *
   * @param handler connection handler representing the client session; must be non-{@code null} and
   *     already associated with the target node.
   * @throws MessageInvalidException if the connection state rejects alert watching, matching base
   *     FCP error propagation semantics.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    handler.getServer().messageRuntimeSupport().watchFeeds(handler, enabled);
  }

  /**
   * Serializes this message into a {@link SimpleFieldSet} for transmission.
   *
   * <p>The returned field set contains a single {@code Enabled} key mirroring the value supplied at
   * construction. Callers own the returned instance and may pass it to outbound FCP encoders; the
   * method never returns {@code null}.
   *
   * @return new field set containing the {@code Enabled} flag that represents this message state.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", enabled);
    return fs;
  }
}
