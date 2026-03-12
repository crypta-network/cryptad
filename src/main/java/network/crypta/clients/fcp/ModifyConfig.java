package network.crypta.clients.fcp;

import java.util.EnumSet;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles the {@code ModifyConfig} FCP request by applying configuration updates supplied by the
 * client.
 *
 * <p>This message consumes a {@link SimpleFieldSet} whose keys mirror the hierarchical names of
 * {@link Option} instances in the node configuration. The constructor captures the request
 * identifier up front and strips it from the field set so only option names remain. During {@link
 * #run(FCPConnectionHandler, Node)} every {@link SubConfig} is traversed and each option is updated
 * when a matching key exists. Values identical to the current configuration are ignored to avoid
 * redundant writes.
 *
 * <p>The message requires the connection to possess full access; otherwise it terminates early with
 * a {@link MessageInvalidException}. After successful updates, the configuration is persisted via
 * the client core and a fresh {@link ConfigData} response is sent so callers can confirm the
 * effective state.
 *
 * <ul>
 *   <li>Responsibility: reconcile client-supplied option values with the in-memory configuration.
 *   <li>Persistence: flushes changes to disk before replying.
 *   <li>Threading: intended for use on the handler thread; no internal synchronization is added.
 * </ul>
 *
 * @see ConfigData
 * @see Option
 * @see SubConfig
 */
public class ModifyConfig extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ModifyConfig.class);

  static final String NAME = "ModifyConfig";

  final SimpleFieldSet fs;
  final String requestIdentifier;

  /**
   * Builds a new message wrapper around the incoming field set so option updates can be applied
   * later.
   *
   * <p>The supplied field set should contain the {@code Identifier} key alongside option values in
   * dotted form (for example {@code node.opennet.enabled}). The identifier is removed from the
   * stored copy because it is forwarded separately when the response is emitted.
   *
   * @param fs mutable field set holding the message identifier and requested option values; must
   *     not be {@code null} and should use fully qualified option names as keys.
   */
  public ModifyConfig(SimpleFieldSet fs) {
    this.fs = fs;
    this.requestIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  /**
   * Returns an empty field set because outgoing {@code ModifyConfig} messages carry no payload.
   *
   * <p>This message type is purely request-oriented: clients send option overrides and expect a
   * {@link ConfigData} reply rather than a chained payload. Returning a fresh, empty structure
   * maintains symmetry with other message classes while signaling to callers that no additional
   * fields need to be serialized. The field set remains mutable, so downstream code can augment it
   * if protocol extensions are introduced.
   *
   * @return new {@link SimpleFieldSet} instance with {@code true} indicating case-insensitive key
   *     handling; callers receive ownership of the returned object.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Reports the protocol-level message name recognized by FCP peers.
   *
   * <p>The name is stable and used for dispatch tables, access-control checks, and logging so that
   * FCP clients can map responses to the initiating command. Keeping the constant centralized in
   * {@link #NAME} ensures the identifier stays synchronized across factory methods and tests, and
   * avoids typos in protocol exchanges.
   *
   * @return fixed string {@code "ModifyConfig"} used when registering or dispatching the message
   *     type.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Applies the requested configuration updates and emits the latest configuration snapshot.
   *
   * <p>The method first enforces that the connection holds full access privileges; otherwise a
   * {@link MessageInvalidException} is thrown back to the caller. It then iterates through every
   * {@link SubConfig} and {@link Option} pairing, invoking {@link #updateOption(String, Option)} to
   * reconcile differences between the incoming field set and the node's current configuration. When
   * modifications occur, the configuration is persisted before a {@link ConfigData} message is
   * returned so clients can verify the applied values.
   *
   * <pre>{@code
   * // Typical server-side handling path
   * new ModifyConfig(requestFields).run(handler, node);
   * }</pre>
   *
   * @param handler connection-specific dispatcher required to validate access and send responses;
   *     must not be {@code null} and should support full access for this message.
   * @param node target node whose configuration is adjusted; expected to be initialized and ready
   *     for persistence operations.
   * @throws MessageInvalidException if the connection lacks full access, or the message is not
   *     permitted in the current context.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "ModifyConfig requires full access",
          requestIdentifier,
          false);
    }
    Config config = node.getConfig();

    for (SubConfig sc : config.getConfigs()) {
      String prefix = sc.getPrefix();
      for (Option<?> option : sc.getOptions()) {
        updateOption(prefix, option);
      }
    }
    node.services().clientCore().storeConfig();
    handler.send(new ConfigData(node, EnumSet.of(ConfigData.Section.CURRENT), requestIdentifier));
  }

  /**
   * Updates a single option when the incoming field set provides a new value.
   *
   * <p>Only different values are applied; unchanged entries are skipped to avoid unnecessary work
   * and log noise. Invalid values are reported via the logger but do not interrupt processing, so
   * the remaining options can still be evaluated.
   */
  private void updateOption(String prefix, Option<?> option) {
    String configName = option.getName();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Setting {}.{}", prefix, configName);
    }
    String value = fs.get(prefix + '.' + configName);
    if (value == null || option.getValueString().equals(value)) {
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Setting {}.{} to {}", prefix, configName, value);
    }
    try {
      option.setValue(value);
    } catch (Exception e) {
      // Bad values silently fail from an FCP perspective, but the FCP client can tell if a change
      // took by comparing ConfigData messages before and after
      LOG.error("Caught {}", e, e);
    }
  }
}
