package network.crypta.clients.fcp;

import network.crypta.node.RequestStarter;
import network.crypta.runtime.spi.RequestQueuePort;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FCP message: Modify an existing persistent request associated with an FCP client.
 *
 * <p>This message is sent by an FCP client when it wants to adjust how a previously created
 * persistent request is handled by the node without recreating the request. Typical adjustments
 * include changing the request priority, switching between global and connection-local lifetimes,
 * or updating the client token used to correlate notifications with the client application. The
 * message does not itself create or remove a request; it only targets an already known identifier.
 *
 * <p>On receipt the node resolves the request identifier against its in-memory and, if enabled,
 * persistent request stores. If the request is found, the node delegates to {@link
 * ClientRequest#modifyRequest(String, short, FCPServer)} to apply the modifications and propagate
 * them to the internal scheduling layer. If the identifier cannot be resolved, or if persistence is
 * disabled when a globally persistent request is required, an appropriate {@link
 * ProtocolErrorMessage} is sent back to the client instead of silently ignoring the request.
 *
 * <p>Wire format example:
 *
 * <pre>{@code
 * ModifyPersistentRequest
 * Identifier=request identifier
 * Verbosity=1023          # optional, not interpreted here
 * PriorityClass=1         # change priority class, -1 means leave unchanged
 * ClientToken=new token   # change client token used in callbacks
 * Global=true             # true for global (forever) requests, false for reboot-persistent
 * EndMessage
 * }</pre>
 */
public final class ModifyPersistentRequest extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ModifyPersistentRequest.class);

  static final String NAME = "ModifyPersistentRequest";

  final String requestIdentifier;
  final boolean global;
  // negative means don't change
  final short priorityClass;
  final String clientToken;

  ModifyPersistentRequest(SimpleFieldSet fs) throws MessageInvalidException {
    this.global = fs.getBoolean("Global", false);
    this.requestIdentifier = fs.get("Identifier");
    this.clientToken = fs.get("ClientToken");
    if (requestIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Missing field: Identifier", null, global);
    String prio = fs.get("PriorityClass");
    if (prio != null) {
      try {
        priorityClass = Short.parseShort(prio);
        if (!RequestStarter.isValidPriorityClass(priorityClass))
          throw new MessageInvalidException(
              ProtocolErrorMessage.INVALID_FIELD,
              "Invalid priority class "
                  + priorityClass
                  + " - range is "
                  + RequestStarter.PAUSED_PRIORITY_CLASS
                  + " to "
                  + RequestStarter.MAXIMUM_PRIORITY_CLASS,
              requestIdentifier,
              global);
      } catch (NumberFormatException e) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.ERROR_PARSING_NUMBER,
            "Could not parse PriorityClass: " + e.getMessage(),
            requestIdentifier,
            global);
      }
    } else priorityClass = -1;
  }

  /**
   * Builds the {@link SimpleFieldSet} representation of this message for transmission over the FCP
   * connection.
   *
   * <p>The returned structure always contains the {@code Identifier} field and a {@code Global}
   * flag mirroring the values supplied by the client. The {@code PriorityClass} field is also
   * present for every message instance; a negative value indicates that the node should leave the
   * existing priority unchanged. When a non-{@code null} client token is supplied, it is encoded as
   * the {@code ClientToken} field so that later status notifications can be correlated by the
   * client application.
   *
   * <p>A new {@link SimpleFieldSet} is allocated on each call and populated only from the immutable
   * fields of this instance, so callers are free to modify the returned instance without affecting
   * other invocations.
   *
   * @return a newly created field set containing the wire representation of this {@code
   *     ModifyPersistentRequest}, suitable for sending over an FCP connection
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", requestIdentifier);
    fs.put("Global", global);
    fs.put("PriorityClass", priorityClass);
    if (clientToken != null) fs.putSingle("ClientToken", clientToken);
    return fs;
  }

  /**
   * Returns the protocol-level name used to identify this FCP message type.
   *
   * <p>The name is a stable constant defined by the FCP specification and is used both by clients
   * when composing requests and by the node when emitting responses that refer back to this message
   * type. Implementations of {@link FCPMessage} typically delegate to this method when deciding how
   * to label a message on the wire or in diagnostic logs. The value never changes for the lifetime
   * of the JVM and is shared by all instances of this class.
   *
   * @return the constant string {@code "ModifyPersistentRequest"} that identifies this message
   *     type; never {@code null}
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the modification against the node, updating the matching persistent request if it can
   * be found.
   *
   * <p>The method first consults the connection's reboot-persistent request store via {@link
   * FCPConnectionHandler#getRebootRequest(boolean, FCPConnectionHandler, String)}. When a matching
   * request is found, the change is applied immediately on the caller's thread by invoking {@link
   * ClientRequest#modifyRequest(String, short, FCPServer)} with the stored client token and
   * priority. If no reboot-persistent request is present, the method submits a persistent lookup
   * task through {@link RequestQueuePort#submitPersistentJob(
   * network.crypta.runtime.spi.RequestQueueTask, RequestQueuePriority)} to search the
   * forever-persistent store using {@link FCPConnectionHandler#getForeverRequest(boolean,
   * FCPConnectionHandler, String)} and apply the same modification there.
   *
   * <p>If neither store contains the referenced identifier, a {@link ProtocolErrorMessage} with
   * code {@link ProtocolErrorMessage#NO_SUCH_IDENTIFIER} is sent back to the client. When the
   * persistence layer is disabled and a forever-persistent lookup would be required, the client is
   * likewise informed that the identifier cannot be resolved. The operation is best-effort and does
   * not retry automatically; callers should handle failures surfaced through the FCP connection.
   *
   * @param handler connection handler used to resolve the request identifier and send any protocol
   *     error responses; must not be {@code null}
   * @throws MessageInvalidException if the identifier or request parameters violate protocol
   *     constraints while attempting to execute the modification
   */
  @Override
  public void run(final FCPConnectionHandler handler) throws MessageInvalidException {

    ClientRequest req = handler.getRebootRequest(global, handler, requestIdentifier);
    if (req == null) {
      RequestQueuePort requestQueuePort = handler.getServer().runtime().requestQueue();
      try {
        requestQueuePort.submitPersistentJob(
            () -> {
              ClientRequest req1 = handler.getForeverRequest(global, handler, requestIdentifier);
              if (req1 == null) {
                LOG.error("Huh ? the request is null!");
                ProtocolErrorMessage msg =
                    new ProtocolErrorMessage(
                        ProtocolErrorMessage.NO_SUCH_IDENTIFIER,
                        false,
                        null,
                        requestIdentifier,
                        global);
                handler.send(msg);
                return false;
              }
              req1.modifyRequest(clientToken, priorityClass, handler.getServer());
              return true;
            },
            RequestQueuePriority.NORMAL);
      } catch (RequestQueueUnavailableException _) {
        ProtocolErrorMessage msg =
            new ProtocolErrorMessage(
                ProtocolErrorMessage.NO_SUCH_IDENTIFIER, false, null, requestIdentifier, global);
        handler.send(msg);
      }
    } else {
      req.modifyRequest(clientToken, priorityClass, handler.getServer());
    }
  }
}
