package network.crypta.clients.fcp;

import java.io.File;
import java.net.MalformedURLException;
import java.util.Locale;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads a plugin in response to an incoming FCP {@code LoadPlugin} request.
 *
 * <p>The handler validates mandatory fields such as the message identifier and plugin URL, derives
 * or confirms the URL type, and then delegates the actual loading work to the node's executor so
 * client connections are not blocked. It supports loading official bundled plugins, local plugin
 * files, Freenet URIs, or arbitrary URLs, and uses the node's {@link
 * network.crypta.pluginmanager.PluginManager} to start the plugin while optionally persisting it to
 * disk. Errors are reported back to the client as {@link ProtocolErrorMessage} instances with
 * precise failure reasons.
 *
 * <p><strong>Responsibilities</strong>
 *
 * <ul>
 *   <li>Parse and validate FCP fields related to plugin loading.
 *   <li>Infer URL type when absent by consulting official plugin metadata, filesystem presence, or
 *       Freenet URI parsing.
 *   <li>Submit plugin start operations asynchronously via the node executor and report structured
 *       results or failures.
 * </ul>
 *
 * <p>The class is request-scoped and not thread-safe on its own; concurrency is handled by the FCP
 * connection and node executor infrastructure that invokes it.
 */
public class LoadPlugin extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(LoadPlugin.class);

  static final String NAME = "LoadPlugin";

  static final String TYPENAME_FILE = "file";
  static final String TYPENAME_FREENET = "freenet";
  static final String TYPENAME_OFFICIAL = "official";
  static final String TYPENAME_URL = "url";

  private final String messageIdentifier;
  private final String pluginURL;
  private final String urlType;
  private final boolean store;

  /**
   * Builds a {@code LoadPlugin} request representation by extracting fields from the provided
   * {@link SimpleFieldSet}.
   *
   * <p>The constructor enforces presence of {@code Identifier} and {@code PluginURL} fields and
   * optionally accepts {@code URLType} and {@code Store}. If the URL type is supplied it is
   * validated against the supported set; otherwise it is left {@code null} for later inference. Any
   * missing mandatory fields or unsupported values result in a {@link MessageInvalidException} that
   * is returned to the client by the caller.
   *
   * @param fs parsed fields of the incoming FCP message; must contain {@code Identifier} and {@code
   *     PluginURL} entries.
   * @throws MessageInvalidException if required fields are absent or an unknown URL type is
   *     provided.
   */
  public LoadPlugin(SimpleFieldSet fs) throws MessageInvalidException {
    messageIdentifier = fs.get("Identifier");
    if (messageIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must contain an Identifier field", null, false);
    pluginURL = fs.get("PluginURL");
    if (pluginURL == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Must contain a PluginURL field",
          messageIdentifier,
          false);
    String type = fs.get("URLType");
    if ((type != null) && !type.trim().isEmpty()) urlType = type.trim();
    else urlType = null;
    if (urlType != null
        && !(TYPENAME_FILE.equalsIgnoreCase(urlType)
            || TYPENAME_FREENET.equalsIgnoreCase(urlType)
            || TYPENAME_OFFICIAL.equalsIgnoreCase(urlType)
            || TYPENAME_URL.equalsIgnoreCase(urlType)))
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Unknown URL type: '" + urlType + "'",
          messageIdentifier,
          false);
    store = fs.getBoolean("Store", false);
  }

  /**
   * Returns a minimal field set because this message type is only constructed from incoming fields.
   *
   * <p>Outbound serialization of {@code LoadPlugin} requests is not performed by this class; it is
   * created after parsing client-provided data. Consequently, the returned {@link SimpleFieldSet}
   * is empty but marked recursive so that framework code can treat it as structurally valid without
   * duplicating client parameters.
   *
   * @return an empty, recursive {@link SimpleFieldSet} suitable for framework consumption.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Provides the canonical FCP message name used for routing within the protocol implementation.
   *
   * <p>The name is constant ({@code "LoadPlugin"}) and allows the connection handler to dispatch
   * incoming messages to this type. Clients constructing outbound messages should set the same
   * string to ensure interoperability with older protocol handlers and logging that keys off
   * message names.
   *
   * @return the literal message name {@code "LoadPlugin"} for protocol routing.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Verifies access and schedules the plugin to be loaded on the node executor.
   *
   * <p>The method first enforces that the FCP connection has full-access permissions and that the
   * plugin subsystem is enabled. It then submits the load operation asynchronously to avoid
   * blocking the client thread. Failure cases are reported via {@link ProtocolErrorMessage}
   * instances for missing privileges, disabled plugins, unsupported URL types, or absent plugin
   * artifacts; a successful load returns a {@link PluginInfoMessage} describing the started plugin.
   *
   * @param handler connection handler used to validate permissions and send responses; must not be
   *     {@code null}.
   * @param node active node whose plugin manager performs loading; expected to be fully
   *     initialized.
   * @throws MessageInvalidException if the caller lacks permissions or initial validation fails
   *     before asynchronous execution begins.
   */
  @Override
  public void run(final FCPConnectionHandler handler, final Node node)
      throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "LoadPlugin requires full access",
          messageIdentifier,
          false);
    }

    if (!node.services().pluginManager().isEnabled()) {
      handler.send(
          new ProtocolErrorMessage(
              ProtocolErrorMessage.PLUGINS_DISABLED,
              false,
              "Plugins disabled",
              messageIdentifier,
              false));
      return;
    }

    node.network().executor().execute(() -> processLoad(handler, node), "Load Plugin");
  }

  private void processLoad(FCPConnectionHandler handler, Node node) {
    String type = resolveUrlType(node);
    if (type == null) {
      handler.send(
          new ProtocolErrorMessage(
              ProtocolErrorMessage.INVALID_FIELD,
              false,
              "Was not able to guess the URL type from URL, check the URL or add a 'URLType' field",
              messageIdentifier,
              false));
      return;
    }
    PluginInfoWrapper pluginInfo = startPlugin(node, type, handler);
    if (pluginInfo == null) {
      handler.send(
          new ProtocolErrorMessage(
              ProtocolErrorMessage.NO_SUCH_PLUGIN,
              false,
              "Plugin '" + pluginURL + "' does not exist or is not a FCP plugin",
              messageIdentifier,
              false));
    } else {
      handler.send(new PluginInfoMessage(pluginInfo, messageIdentifier, true));
    }
  }

  private String resolveUrlType(Node node) {
    if (urlType != null) {
      return urlType.toLowerCase(Locale.ROOT);
    }
    if (node.services().pluginManager().isOfficialPlugin(pluginURL) != null) {
      return TYPENAME_OFFICIAL;
    }
    if (new File(pluginURL).exists()) {
      return TYPENAME_FILE;
    }
    try {
      new FreenetURI(pluginURL);
      return TYPENAME_FREENET;
    } catch (MalformedURLException e) {
      LOG.debug("Failed to parse plugin URL as Freenet URI: {}", pluginURL, e);
      return null;
    }
  }

  @SuppressWarnings("StatementSwitchToExpressionSwitch")
  private PluginInfoWrapper startPlugin(Node node, String type, FCPConnectionHandler handler) {
    switch (type) {
      case TYPENAME_OFFICIAL:
        return node.services().pluginManager().startPluginOfficial(pluginURL, store);
      case TYPENAME_FILE:
        return node.services().pluginManager().startPluginFile(pluginURL, store);
      case TYPENAME_FREENET:
        return node.services().pluginManager().startPluginFreenet(pluginURL, store);
      case TYPENAME_URL:
        return node.services().pluginManager().startPluginURL(pluginURL, store);
      default:
        LOG.error("This should really not happen!");
        handler.send(
            new ProtocolErrorMessage(
                ProtocolErrorMessage.INTERNAL_ERROR,
                false,
                "This should really not happen! See logs for details.",
                messageIdentifier,
                false));
        return null;
    }
  }
}
