package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * FCP control message that enables or disables global event watching for a client connection.
 *
 * <p>This message is sent by an FCP client when it wants to receive node-wide notifications (such
 * as request lifecycle updates) beyond its own request scope. The handler stores the preference on
 * both the reboot-persistent client and the in-memory forever client, so the subscription survives
 * across reconnections when persistence is available. Applications typically send this once during
 * session initialization and keep the returned verbosity mask aligned with their logging strategy.
 *
 * <p>Key behaviors:
 *
 * <ul>
 *   <li>Reads {@code Enabled} and {@code VerbosityMask} from the provided field set, defaulting to
 *       enabled with a mask that accepts all events when the mask is absent.
 *   <li>Propagates the setting to both reboot-persistent and ephemeral clients so future messages
 *       follow the same filter.
 *   <li>Falls back to a protocol error when persistence has been disabled on the server, leaving
 *       the session unchanged.
 * </ul>
 *
 * <p>The class is thread-confined to the handling thread; it carries immutable fields after
 * construction and performs no synchronized work. Use separate instances per incoming message to
 * avoid unintended cross-session state sharing.
 *
 * @see FCPMessage
 * @see ProtocolErrorMessage
 */
public final class WatchGlobal extends FCPMessage {

  final boolean enabled;
  final int verbosityMask;
  static final String NAME = "WatchGlobal";

  /**
   * Parses a {@link SimpleFieldSet} into an immutable watch directive for an FCP client.
   *
   * <p>The constructor accepts the raw fields transmitted by the peer and converts them into the
   * normalized boolean/bitmask pair used at runtime. Missing {@code Enabled} values default to
   * {@code true}; missing {@code VerbosityMask} values default to {@link Integer#MAX_VALUE} so all
   * events are delivered. Invalid masks trigger {@link MessageInvalidException} and halt message
   * processing for the current request.
   *
   * <p>Usage is straightforward: instantiate within an FCP handler when a {@code WatchGlobal}
   * message arrives, then invoke {@link #run(FCPConnectionHandler, Node)} to apply the preference.
   *
   * @param fs non-null set of key/value pairs received from the peer; expects {@code Enabled}
   *     (boolean) and optional {@code VerbosityMask} (integer) entries and tolerates absent fields.
   * @throws MessageInvalidException if {@code VerbosityMask} is present but cannot be parsed as an
   *     integer, preserving the client-visible protocol error semantics.
   */
  public WatchGlobal(SimpleFieldSet fs) throws MessageInvalidException {
    enabled = fs.getBoolean("Enabled", true);
    String s = fs.get("VerbosityMask");
    if (s != null)
      try {
        verbosityMask = Integer.parseInt(s);
      } catch (NumberFormatException e) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.ERROR_PARSING_NUMBER, e.toString(), null, false);
      }
    else verbosityMask = Integer.MAX_VALUE;
  }

  /**
   * Serializes the watch preference back into an FCP field set for transmission or logging.
   *
   * <p>The returned {@link SimpleFieldSet} always contains {@code Enabled} and {@code
   * VerbosityMask} keys, mirroring the values normalized during construction so callers can forward
   * the message without re-reading instance fields. The field set is mutable, but the method
   * creates a fresh instance on each call, making it safe to hand off to downstream encoders
   * without synchronization. Callers should avoid mutating the set after sending to prevent
   * divergence from the stored state.
   *
   * @return a new field set containing the enabled flag and verbosity bitmask ready for FCP
   *     serialization; the caller owns the returned instance.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", enabled);
    fs.put("VerbosityMask", verbosityMask);
    return fs;
  }

  /**
   * Reports the canonical FCP message name used on the wire.
   *
   * <p>This identifier is stable and must match the token used by peers when constructing requests.
   * It is constant for the lifetime of the application and requires no synchronization.
   *
   * @return the literal {@code WatchGlobal} string used in FCP framing.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Applies the watch setting to the current connection and, when persistence is available, to the
   * reboot-resilient client state.
   *
   * <p>The method updates both the reboot client (for on-disk persistence) and the forever client
   * (for the active session) so verbosity and enablement stay aligned across restarts. If the
   * server has disabled persistence, it sends a {@link ProtocolErrorMessage} back to the caller and
   * leaves the existing configuration untouched. The operation is idempotent with respect to
   * repeated calls that supply the same values and performs no background work beyond delegating to
   * the handler and node-provided clients.
   *
   * <p>Example:
   *
   * <pre>{@code
   * var msg = new WatchGlobal(fields);
   * msg.run(connectionHandler, node);
   * }</pre>
   *
   * @param handler active connection handler that owns both persistent and in-memory clients; must
   *     not be {@code null} and is expected to originate the incoming FCP message.
   * @param node the current node instance supplying the client core and FCP server used to register
   *     the watch; must expose a non-null client core when invoked.
   * @throws MessageInvalidException if subordinate clients reject the configuration change, or the
   *     handler signals a protocol-level validation failure.
   */
  @Override
  public void run(final FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.getRebootClient().setWatchGlobal(enabled, verbosityMask, handler.getServer())) {
      FCPMessage err =
          new ProtocolErrorMessage(
              ProtocolErrorMessage.PERSISTENCE_DISABLED, false, "Persistence disabled", null, true);
      handler.send(err);
    }
    PersistentRequestClient client = handler.getForeverClient();
    if (client != null) client.setWatchGlobal(enabled, verbosityMask, handler.getServer());
  }
}
