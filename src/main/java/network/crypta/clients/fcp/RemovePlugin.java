package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the {@code RemovePlugin} FCP message sent by a client to stop a running plugin and
 * optionally delete its cached copy. The message is validated eagerly to ensure the identifier and
 * plugin name are present, and execution later delegates the heavy work to the node's executor so
 * the connection thread remains responsive.
 *
 * <p>Typical callers construct this message from a parsed {@link SimpleFieldSet}, then pass it to
 * the connection handler which invokes {@link #run(FCPConnectionHandler, Node)}. Removal requires
 * full-access credentials and will fail fast with an access error otherwise. When allowed, the
 * handler locates the plugin by its registered identifier, requests a graceful stop bounded by the
 * supplied maximum wait time, and purges any cached installer file if requested.
 *
 * <p>Concurrency: {@link #run(FCPConnectionHandler, Node)} schedules work on the node executor and
 * does not block the calling thread. The {@link FCPConnectionHandler} remains responsible for
 * serializing responses back to the client.
 *
 * <ul>
 *   <li>Message name: {@link #NAME}
 *   <li>Required fields: {@code Identifier}, {@code PluginName}
 *   <li>Optional fields: {@code MaxWaitTime}, {@code Purge}
 * </ul>
 *
 * @see PluginRemovedMessage
 * @see network.crypta.pluginmanager.PluginManager#findPluginByIdentifier(String)
 */
public class RemovePlugin extends FCPMessage {

  static final String NAME = "RemovePlugin";

  private final String messageIdentifier;
  private final String plugname;
  private final int maxWaitTime;
  private final boolean purge;

  /**
   * Creates a new message instance from the provided field set, validating that mandatory fields
   * are present and extracting optional tuning flags. Parsing happens immediately so malformed
   * requests fail fast and do not reach the executor stage. The constructor is idempotent with
   * respect to input, storing only primitive or immutable values for later execution.
   *
   * @param fs incoming request fields; must supply {@code Identifier} and {@code PluginName};
   *     optional {@code MaxWaitTime} (milliseconds) and {@code Purge} flag are respected when set.
   * @throws MessageInvalidException if any required field is missing or cannot be parsed; the
   *     exception is sent back to the client with the identifier when available.
   */
  public RemovePlugin(SimpleFieldSet fs) throws MessageInvalidException {
    messageIdentifier = fs.get("Identifier");
    if (messageIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must contain an Identifier field", null, false);
    plugname = fs.get("PluginName");
    if (plugname == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Must contain a PluginName field",
          messageIdentifier,
          false);
    maxWaitTime = fs.getInt("MaxWaitTime", 0);
    purge = fs.getBoolean("Purge", false);
  }

  /**
   * Returns an empty response payload for this control message. Remove operations do not embed
   * additional fields in the request body beyond those supplied at construction time. The returned
   * {@link SimpleFieldSet} is freshly allocated for each call so callers can serialize the message
   * without worrying about cross-request mutation or shared state. Because the message is fully
   * defined by constructor arguments, the field set intentionally contains no optional fields; any
   * future extensions should remain compatible with this choice.
   *
   * @return immutable empty field set instance used when serializing the message over FCP; callers
   *     may treat it as read-only and short-lived.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Provides the protocol-visible message name so dispatchers can route it to the correct handler.
   * The value remains constant for the lifetime of the application and mirrors the string clients
   * use on the wire, ensuring that logging, routing, and equality checks are consistent across the
   * FCP implementation. This method is side effect free and safe to call repeatedly.
   *
   * @return constant string {@code "RemovePlugin"} identifying the message type.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the remove operation on the node executor, enforcing access checks before scheduling.
   * The handler receives either a {@link PluginRemovedMessage} on success or an appropriate error
   * message when the plugin cannot be found or access is denied. Execution is asynchronous; the
   * calling thread returns immediately after enqueuing work, while the plugin shutdown observes the
   * configured maximum wait time before forcing termination. If {@code purge} is set, any cached
   * installer artifacts are deleted after the stop attempt to keep disk usage predictable.
   *
   * @param handler connection handler that performs authorization and sends responses; must expose
   *     the calling client's privilege level and messaging queue.
   * @param node active node instance supplying executor access and plugin management facilities;
   *     must be alive for the removal to proceed.
   * @throws MessageInvalidException if the caller lacks full access rights; other failures are
   *     reported asynchronously via error messages rather than exceptions.
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
                        messageIdentifier,
                        false));
              } else {
                pi.stopPlugin(node.services().pluginManager(), maxWaitTime, false);
                if (purge) {
                  node.services().pluginManager().removeCachedCopy(pi.getFilename());
                }
                handler.send(new PluginRemovedMessage(plugname, messageIdentifier));
              }
            },
            "Remove Plugin");
  }
}
