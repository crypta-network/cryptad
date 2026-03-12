package network.crypta.clients.fcp;

import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Removes a persistent client request from the node on behalf of an FCP client.
 *
 * <p>This message is emitted by a client that wishes to cancel a request which was previously
 * registered for persistence, regardless of whether it has finished or is still queued. It carries
 * the opaque request identifier and a flag indicating whether the request was global. Instances are
 * immutable after creation; they simply transport the parameters required for removal and delegate
 * the actual work to the {@link FCPConnectionHandler} when {@link #run(FCPConnectionHandler, Node)}
 * is invoked. Because persistence and request queues may span multiple subsystems, the class favors
 * clarity and explicit branching over silent failure.
 *
 * <p>The handler treats three stages distinctly: removal from reboot-persistent queues, removal
 * from in-memory queues, and finally removal from the long-term persistence store via a scheduled
 * job. This mirrors the lifecycle of a request across restarts. The type itself is thread-safe
 * because it holds only final fields and performs no mutation. Consumers should assume the work is
 * executed on the handler's dispatcher thread and avoid blocking operations in callbacks.
 *
 * <ul>
 *   <li>Responsibilities: validate required fields and forward removal instructions.
 *   <li>Scope: applies to both global and client-specific persistent requests.
 *   <li>Error handling: reports persistence-disabled states with an explicit protocol error.
 * </ul>
 *
 * @see FCPMessage
 * @see FCPConnectionHandler
 * @see ClientRequest
 */
public final class RemovePersistentRequest extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(RemovePersistentRequest.class);

  static final String NAME = "RemoveRequest";
  static final String ALT_NAME = "RemovePersistentRequest";

  final String requestIdentifier;
  final boolean global;

  /**
   * Constructs the request wrapper from an incoming {@link SimpleFieldSet} payload.
   *
   * <p>The constructor validates that the {@code Identifier} field is present and extracts the
   * optional {@code Global} flag. Callers normally pass the parsed field set from the raw FCP
   * message. The created instance is safe to reuse across handler invocations because it contains
   * only immutable state derived from the original message.
   *
   * @param fs field set decoded from the client message; must contain {@code Identifier} and may
   *     include {@code Global} when the request spans the entire node scope rather than a single
   *     client session.
   * @throws MessageInvalidException if the identifier is absent or otherwise fails validation
   *     required by the protocol.
   */
  public RemovePersistentRequest(SimpleFieldSet fs) throws MessageInvalidException {
    this.global = fs.getBoolean("Global", false);
    this.requestIdentifier = fs.get(IDENTIFIER);
    if (requestIdentifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must have Identifier", null, global);
  }

  /**
   * Builds a minimal field set representing this message for transmission.
   *
   * <p>Only the persistent request identifier is serialized because removal requests do not carry
   * payload data. The returned structure is newly allocated and independent of the instance so it
   * can be freely mutated by downstream serialization layers without affecting the stored state.
   *
   * @return a new {@link SimpleFieldSet} containing the {@code Identifier} entry required by the
   *     FCP protocol for removal messages.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(IDENTIFIER, requestIdentifier);
    return fs;
  }

  /**
   * Provides the protocol name for this FCP message type.
   *
   * <p>The name is stable and used by the dispatcher to route requests to the proper handler. It
   * aligns with the legacy {@value #NAME} constant while {@link #ALT_NAME} remains available for
   * compatibility when parsing inbound messages.
   *
   * @return the canonical FCP message name used during serialization and routing.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the removal of the persistent request within the provided handler context.
   *
   * <p>The method first attempts to remove the request from reboot-persistent queues, then from
   * in-memory queues for non-global requests. If neither path succeeds, it schedules a
   * high-priority job to remove the request from the long-term persistence store, ensuring the
   * operation eventually completes even when persistence is handled asynchronously. When
   * persistence is disabled and the request cannot be found, the client receives a protocol error
   * message instead of silent failure.
   *
   * @param handler connection handler responsible for coordinating client requests; must not be
   *     {@code null} and is assumed to execute callbacks on its internal dispatcher thread.
   * @param node current node instance supplied by the dispatcher; the parameter is reserved for
   *     interface compliance and is not modified by this implementation.
   * @throws MessageInvalidException if the handler detects that the request parameters violate
   *     protocol rules or if downstream validation fails during removal.
   */
  @Override
  public void run(final FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    ClientRequest req = handler.removePersistentRebootRequest(global, requestIdentifier);
    if (req == null && !global) {
      req = handler.removeRequestByIdentifier(requestIdentifier, true);
    }
    if (req == null) {
      try {
        handler
            .getServer()
            .getCore()
            .getClientContext()
            .jobRunner
            .queue(
                (PersistentJob)
                    context -> {
                      ClientRequest req1 =
                          handler.removePersistentForeverRequest(global, requestIdentifier);
                      if (req1 == null) {
                        if (LOG.isDebugEnabled()) {
                          LOG.debug(
                              "RemovePersistentRequest missing identifier {} (global={})",
                              requestIdentifier,
                              global);
                        }
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
                      return true;
                    },
                NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      } catch (PersistenceDisabledException _) {
        FCPMessage err =
            new ProtocolErrorMessage(
                ProtocolErrorMessage.PERSISTENCE_DISABLED,
                false,
                "Persistence disabled and non-persistent request not found",
                requestIdentifier,
                global);
        handler.send(err);
      }
    }
  }
}
