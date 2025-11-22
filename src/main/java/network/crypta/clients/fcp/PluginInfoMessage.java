package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.pluginmanager.FredPlugin;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.SimpleFieldSet;

/**
 * Server-to-client message that conveys metadata about a single plugin in response to the FCP
 * {@code GetPluginInfo} request.
 *
 * <p>This message is built on the server side and serialized over FCP to help clients discover
 * whether a plugin is present, which FCP interfaces it supports, and whether it is currently
 * running. Typical callers construct one instance per plugin and immediately send it via the {@link
 * FCPConnectionHandler}; there is no persistence or reuse beyond the lifetime of the enclosing
 * request. The instance captures a snapshot of talkability and version information at construction
 * time and does not track later lifecycle changes.
 *
 * <p>Instances are immutable after construction; all fields are derived from the provided {@link
 * PluginInfoWrapper} without additional I/O. The class is thread-safe for concurrent reads because
 * it performs no mutation, but callers should avoid sharing it across requests if the underlying
 * plugin state is expected to change rapidly. Message creation assumes the plugin is already
 * loaded; unloaded plugins are not modeled by this type. When populating fields, the class defers
 * to the plugin wrapper for authoritative class names, version numbers, and talkability so
 * consumers can rely on consistent values.
 *
 * <ul>
 *   <li>Encodes legacy and server-side FCP support into the {@code IsTalkable} flag.
 *   <li>Optionally includes origin path and start timestamp for detailed queries.
 *   <li>Uses {@link SimpleFieldSet} for wire formatting to match other FCP messages.
 * </ul>
 *
 * @author saces
 */
public class PluginInfoMessage extends FCPMessage {

  static final String NAME = "PluginInfo";

  private final String messageIdentifier;

  private final boolean detailed;

  private final String classname;
  private final String originuri;
  private final long started;
  private final boolean isTalkable;
  private final long longVersion;
  private final String version;

  /**
   * Builds a new {@code PluginInfoMessage} snapshot for the given plugin wrapper.
   *
   * <p>The constructor gathers all required fields immediately, including talkability flags and
   * version strings, so the resulting message can be sent without further access to the plugin
   * manager. It does not perform any network I/O and assumes the supplied wrapper represents a
   * currently loaded plugin.
   *
   * @param pi wrapper that exposes plugin metadata and runtime instance; must not be {@code null}.
   * @param identifier optional caller-supplied correlation identifier echoed back to the client;
   *     may be {@code null} to omit the field.
   * @param detail {@code true} to include origin URI and start timestamp in the payload; {@code
   *     false} produces a minimal response.
   */
  PluginInfoMessage(PluginInfoWrapper pi, String identifier, boolean detail) {
    this.messageIdentifier = identifier;
    this.detailed = detail;
    classname = pi.getPluginClassName();
    originuri = pi.getFilename();
    started = pi.getStarted();
    // isFCPPlugin() is the deprecated old plugin FCP API, isFCPServerPlugin() the new one.
    // Plugins may implement only the old, or the new, or both. As the on-network format is
    // backwards compatible, we report them as talkable if any is implemented.
    boolean legacyFcp = isLegacyFcpPlugin(pi);
    isTalkable = legacyFcp || pi.isFCPServerPlugin();
    longVersion = pi.getPluginLongVersion();
    version = pi.getPluginVersion();
  }

  /**
   * Determines whether the plugin implements the legacy FCP interface.
   *
   * <p>The check uses the live plugin instance to test assignability against {@code FredPluginFCP}.
   * It tolerates environments where the legacy class might be absent by catching {@link
   * ClassNotFoundException} and treating the plugin as non-legacy in that scenario.
   *
   * @param pluginInfo wrapper that provides access to the plugin instance being inspected.
   * @return {@code true} when the plugin instance implements the legacy FCP API; {@code false}
   *     otherwise or when the legacy interface cannot be resolved.
   */
  private boolean isLegacyFcpPlugin(PluginInfoWrapper pluginInfo) {
    FredPlugin plugin = pluginInfo.getPlugin();
    if (plugin == null) {
      return false;
    }
    try {
      Class<?> legacyApi = Class.forName("network.crypta.pluginmanager.FredPluginFCP");
      return legacyApi.isInstance(plugin);
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  /**
   * Exports this message into a {@link SimpleFieldSet} suitable for wire transmission.
   *
   * <p>The returned structure contains the plugin name, talkability flags, and version identifiers
   * required by FCP clients. When {@code detailed} was requested at construction time, the field
   * set also includes the plugin's origin URI and start timestamp. The returned instance is mutable
   * by callers, but mutations do not affect the original message object.
   *
   * @return a new {@link SimpleFieldSet} containing all currently configured message fields in FCP
   *     format; never {@code null}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    if (messageIdentifier != null) {
      // Identifier is optional on these two only
      sfs.putSingle("Identifier", messageIdentifier);
    }
    sfs.putSingle("PluginName", classname);
    sfs.put("IsTalkable", isTalkable);
    sfs.put("LongVersion", longVersion);
    sfs.putSingle("Version", version);

    if (detailed) {
      sfs.putSingle("OriginUri", originuri);
      sfs.put("Started", started);
    }
    return sfs;
  }

  /**
   * Returns the FCP message name for this type.
   *
   * <p>The name is constant and used by the protocol layer to route messages; it does not depend on
   * any plugin-specific state.
   *
   * @return constant {@code "PluginInfo"} identifying this message type.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This message is server-originated only; invoking {@code run} from a client-initiated context
   * results in an {@link MessageInvalidException} with an {@code INVALID_MESSAGE} protocol error.
   * It performs no state changes and always throws when executed.
   *
   * @param handler connection that attempted to execute the message; must not be {@code null}.
   * @param node active node instance; unused because execution is not permitted.
   * @throws MessageInvalidException always thrown to signal that this direction is invalid for the
   *     message type.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        null,
        false);
  }
}
