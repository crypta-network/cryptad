package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.SimpleFieldSet;

/**
 * Handles the {@code ReloadPlugin} FCP command by stopping and restarting an existing plugin.
 *
 * <p>This message type is used by privileged FCP clients that need to refresh a plugin after
 * updating its code or configuration without restarting the entire node. The handler validates that
 * the caller has full access, locates the plugin by its {@code PluginName}, stops it while honoring
 * the configured maximum wait time, optionally purges any cached copy, and then launches the plugin
 * again using the cached or stored source. All heavy work is dispatched onto the node executor to
 * keep the FCP connection responsive and to isolate plugin shutdown/startup lifecycles from the
 * message thread.
 *
 * <ul>
 *   <li>Fails fast with protocol errors when the plugin identifier is unknown.
 *   <li>Supports an optional purge step to discard cached archives before restart.
 *   <li>Replies with {@link PluginInfoMessage} on success or a detailed error otherwise.
 * </ul>
 *
 * <p>Instances are effectively stateless after construction and may be created per incoming
 * message. Reload operations are not idempotent; repeated requests will stop and start the plugin
 * each time they are executed.
 *
 * @see FCPMessage
 * @see network.crypta.pluginmanager.PluginManager
 */
public class ReloadPlugin extends FCPMessage {

  static final String NAME = "ReloadPlugin";

  private final String clientIdentifier;
  private final String plugname;
  private final int maxWaitTime;
  private final boolean purge;
  private final boolean store;

  /**
   * Creates a reload request from fields supplied by an incoming FCP message.
   *
   * <p>The constructor validates that the caller provided a non-null {@code Identifier} and {@code
   * PluginName}. Optional fields include {@code MaxWaitTime} (milliseconds to wait for a clean
   * shutdown before forcing) and flags {@code Purge} and {@code Store}, both of which default to
   * {@code false}. No additional validation beyond presence is performed here; the runtime behavior
   * is handled in {@link #run(FCPConnectionHandler, Node)}.
   *
   * @param fs field set containing {@code Identifier}, plugin name, timing, and purge/store flags;
   *     must not be {@code null}.
   * @throws MessageInvalidException when mandatory fields are missing or cannot be parsed from the
   *     provided field set representation.
   */
  public ReloadPlugin(SimpleFieldSet fs) throws MessageInvalidException {
    clientIdentifier = fs.get("Identifier");
    if (clientIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must contain an Identifier field", null, false);
    plugname = fs.get("PluginName");
    if (plugname == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Must contain a PluginName field",
          clientIdentifier,
          false);
    maxWaitTime = fs.getInt("MaxWaitTime", 0);
    purge = fs.getBoolean("Purge", false);
    store = fs.getBoolean("Store", false);
  }

  /**
   * Produces an empty field set because this command does not serialize additional payload.
   *
   * <p>The returned instance is freshly allocated on each call and may be mutated by the caller
   * without affecting internal state. It primarily exists to satisfy the {@link FCPMessage}
   * contract for messages that are command-only and convey their data through parameters rather
   * than serialized fields.
   *
   * @return new {@link SimpleFieldSet} instance with no keys or values populated.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Returns the protocol-level name associated with this message type.
   *
   * <p>The name is used when routing incoming messages and when emitting responses so that the peer
   * can correlate behavior with the original command. It is a constant defined by the FCP
   * specification and should remain stable across releases for compatibility.
   *
   * @return immutable message name string {@code "ReloadPlugin"} for protocol routing purposes.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the reload workflow on the node executor to avoid blocking the FCP thread.
   *
   * <p>The handler first ensures the connection has full access; otherwise it raises an access
   * denial error. It then resolves the plugin by name, stops it while honoring the configured
   * maximum wait time, optionally purges any cached copy, and starts it again with the requested
   * persistence flag. Success results in a {@link PluginInfoMessage}; failures return protocol
   * errors that explain whether the plugin was missing or invalid.
   *
   * <pre>{@code
   * // Typical server-side call path
   * new ReloadPlugin(fs).run(handler, node);
   * }</pre>
   *
   * <p>This method is not idempotent; repeated invocations will repeatedly stop and restart the
   * plugin, which may disrupt in-flight work inside the plugin itself.
   *
   * @param handler connection handler that enforces permissions and sends replies to the client.
   * @param node node instance providing the executor and plugin manager used for lifecycle actions.
   * @throws MessageInvalidException if the caller lacks full access or if permission validation
   *     fails before the reload operation is dispatched.
   */
  @Override
  public void run(final FCPConnectionHandler handler, final Node node)
      throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "LoadPlugin requires full access",
          clientIdentifier,
          false);
    }

    node.network()
        .executor()
        .execute(
            () -> {
              PluginInfoWrapper pi =
                  node.services().pluginManager().findPluginByIdentifier(plugname);
              if (pi == null) {
                handler.send(
                    new ProtocolErrorMessage(
                        ProtocolErrorMessage.NO_SUCH_PLUGIN,
                        false,
                        "Plugin '" + plugname + "' does not exist or is not a FCP plugin",
                        clientIdentifier,
                        false));
              } else {
                String source = pi.getFilename();
                pi.stopPlugin(node.services().pluginManager(), maxWaitTime, true);
                if (purge) {
                  node.services().pluginManager().removeCachedCopy(pi.getFilename());
                }
                pi = node.services().pluginManager().startPluginAuto(source, store);
                if (pi == null) {
                  handler.send(
                      new ProtocolErrorMessage(
                          ProtocolErrorMessage.NO_SUCH_PLUGIN,
                          false,
                          "Plugin '" + plugname + "' does not exist or is not a FCP plugin",
                          clientIdentifier,
                          false));
                } else {
                  handler.send(new PluginInfoMessage(pi, clientIdentifier, true));
                }
              }
            },
            "Reload plugin");
  }
}
