package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.SimpleFieldSet;

/**
 * Processes the FCP {@code GetPluginInfo} request and returns metadata for a loaded FCP-capable
 * plugin. Instances are immutable after construction and are typically created by the FCP parser
 * when a remote client asks the node for details about a plugin by its identifier. The handler
 * enforces access restrictions for detailed queries and responds with either a structured {@link
 * PluginInfoMessage} or a protocol error without mutating node state.
 *
 * <p>Use this message class when a client needs to discover what plugins are present, whether they
 * expose an FCP interface, and optionally fetch extended metadata that may require elevated
 * privileges. The lifecycle is short-lived: once constructed from an incoming {@link
 * SimpleFieldSet}, {@link #run(FCPConnectionHandler, Node)} is invoked exactly once on the
 * connection thread. All fields are {@code final}, so concurrent invocations for different
 * connections remain thread-safe provided the surrounding {@link FCPConnectionHandler}
 * serialization rules are respected.
 *
 * <ul>
 *   <li>Validates that the request carries both an identifier and a plugin name.
 *   <li>Checks whether the caller has full access before serving detailed metadata.
 *   <li>Sends either {@link PluginInfoMessage} or a {@link ProtocolErrorMessage} to the client.
 * </ul>
 *
 * @see FCPMessage
 * @see PluginInfoMessage
 * @see Node
 */
public class GetPluginInfo extends FCPMessage {

  static final String NAME = "GetPluginInfo";

  private final String requestIdentifier;
  private final boolean detailed;
  private final String plugname;

  /**
   * Creates a {@code GetPluginInfo} command from a parsed field set received over FCP.
   *
   * <p>The field set must contain an {@code Identifier} for correlating responses and a {@code
   * PluginName} that matches the target plugin's identifier. An optional {@code Detailed} flag
   * requests extended metadata and defaults to {@code false} when absent. The contents are read
   * immediately and stored immutably so the provided {@link SimpleFieldSet} instance is not
   * retained or modified.
   *
   * @param fs structured set containing {@code Identifier}, {@code PluginName}, and optional {@code
   *     Detailed} flag; must not be {@code null}.
   * @throws MessageInvalidException if required fields are missing or malformed in the request.
   */
  public GetPluginInfo(SimpleFieldSet fs) throws MessageInvalidException {
    requestIdentifier = fs.get("Identifier");
    if (requestIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "GetPluginInfo must contain an Identifier field",
          null,
          false);
    plugname = fs.get("PluginName");
    if (plugname == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "GetPluginInfo must contain a PluginName field",
          requestIdentifier,
          false);
    detailed = fs.getBoolean("Detailed", false);
  }

  /**
   * Returns the serialized representation for this message type when sent from the client side.
   *
   * <p>{@code GetPluginInfo} is populated entirely from inbound values, so the server-side instance
   * does not expose dynamic fields to be echoed back. An empty, always-valid {@link SimpleFieldSet}
   * is returned to satisfy the {@link FCPMessage} contract and preserve protocol symmetry without
   * leaking internal state.
   *
   * @return an empty field set appropriate for a {@code GetPluginInfo} request envelope.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Provides the FCP message name that routes this handler within the connection dispatcher.
   *
   * <p>The name is stable, uppercase, and matches the protocol token emitted by clients when
   * requesting plugin metadata. Callers typically use this value to register or verify supported
   * commands without performing string allocations at the call site; it is also exposed via the
   * {@link #NAME} constant.
   *
   * @return the literal {@code "GetPluginInfo"} protocol command identifier.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the request by validating access, locating the target plugin, and sending an
   * appropriate response to the client.
   *
   * <p>If {@code detailed} information was requested, the handler must provide full access or a
   * {@link ProtocolErrorMessage#ACCESS_DENIED} is thrown. The node's plugin manager is queried by
   * identifier; missing or non-FCP plugins trigger a {@link ProtocolErrorMessage#NO_SUCH_PLUGIN}
   * reply. When a matching plugin is found, a {@link PluginInfoMessage} containing basic or
   * detailed metadata is sent over the existing connection. The method performs no retries or
   * stateful changes and assumes the caller provides serialization appropriate for the connection
   * lifecycle.
   *
   * @param handler active FCP connection handler used to enforce permissions and emit responses.
   * @param node running node instance whose plugin manager will be queried for metadata.
   * @throws MessageInvalidException if permission checks fail for a detailed request.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (detailed && !handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "GetPluginInfo detailed requires full access",
          requestIdentifier,
          false);
    }

    PluginInfoWrapper pi = node.services().pluginManager().findPluginByIdentifier(plugname);
    if (pi == null) {
      handler.send(
          new ProtocolErrorMessage(
              ProtocolErrorMessage.NO_SUCH_PLUGIN,
              false,
              "Plugin '" + plugname + "' does not exist or is not a FCP plugin",
              requestIdentifier,
              false));
    } else {
      handler.send(new PluginInfoMessage(pi, requestIdentifier, detailed));
    }
  }
}
