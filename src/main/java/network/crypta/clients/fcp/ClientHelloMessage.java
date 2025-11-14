package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Initiates the FCP handshake by representing the inbound {@code ClientHello} message that every
 * external client must send before issuing any other requests.
 *
 * <p>This message captures the human-readable client name together with the protocol version that
 * the remote tool expects the node to support. Instances are normally created when the server
 * parses the {@link SimpleFieldSet} sent by a socket peer, immediately validating that mandatory
 * fields are present so malformed peers can be rejected with a clear {@link ProtocolErrorMessage}.
 * Consumers may also build a {@code ClientHelloMessage} to echo the same data back over the wire
 * when exercising integration tests or diagnostics.
 *
 * <p>The class is effectively immutable once constructed, so it can be safely passed across threads
 * as part of the connection pipeline. Invocation of {@link #run(FCPConnectionHandler, Node)} is
 * expected to happen on the per-connection handler thread; after it completes the handler registers
 * the supplied client name and the node replies with a {@link NodeHelloMessage}. No synchronization
 * is and remains thread-safe as long as the surrounding {@link FCPConnectionHandler} keeps its
 * single-threaded contract.
 *
 * <ul>
 *   <li>Validates Name and ExpectedVersion fields and surfaces protocol errors early.
 *   <li>Provides serialization back into a {@link SimpleFieldSet} for outbound relay scenarios.
 *   <li>Finalizes the handshake by triggering {@link NodeHelloMessage} dispatch and naming the
 *       client.
 * </ul>
 *
 * @see NodeHelloMessage
 * @see FCPConnectionHandler
 */
public class ClientHelloMessage extends FCPMessage {

  /**
   * Canonical FCP message identifier returned by {@link #getName()} and used by decoders to route
   * the payload to this type, ensuring compatibility with legacy peers that expect this literal.
   */
  public static final String NAME = "ClientHello";

  String clientName;
  String clientExpectedVersion;

  /**
   * Creates the message by extracting the {@code Name} and {@code ExpectedVersion} values from the
   * provided {@link SimpleFieldSet}, rejecting the input if mandatory parameters are absent so
   * broken clients do not progress further in the handshake.
   *
   * <p>The constructor trusts the caller to supply a field set that originated from the remote peer
   * and therefore performs only presence checks; version compatibility enforcement happens in
   * higher layers that have the context to compare against the actual node build. The stored values
   * are kept verbatim, allowing diagnostics to display whatever identifier the client announced.
   *
   * @param fs field set from the peer containing both {@code Name} and {@code ExpectedVersion}.
   * @throws MessageInvalidException if {@code Name} or {@code ExpectedVersion} is absent during
   *     validation.
   */
  public ClientHelloMessage(SimpleFieldSet fs) throws MessageInvalidException {
    clientName = fs.get("Name");
    clientExpectedVersion = fs.get("ExpectedVersion");
    if (clientName == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "ClientHello must contain a Name field", null, false);
    if (clientExpectedVersion == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "ClientHello must contain a ExpectedVersion field",
          null,
          false);
    // Note: check the expected version
  }

  /**
   * Converts the stored handshake data back into a {@link SimpleFieldSet} so that downstream
   * components can serialize or mirror the message when interacting with compatibility harnesses or
   * logging pipelines.
   *
   * <p>The method always returns a newly allocated, mutable field set containing exactly the {@code
   * Name} and {@code ExpectedVersion} keys that were accepted during construction. Callers may add
   * additional entries if they need to enrich the message before forwarding it, but must avoid
   * mutating the two canonical keys to preserve the invariant that this object reflects the
   * original client announcement.
   *
   * @return new field set containing Name and ExpectedVersion keys for serialization.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Name", clientName);
    sfs.putSingle("ExpectedVersion", clientExpectedVersion);
    return sfs;
  }

  /**
   * Reports the literal {@link #NAME} identifier so that protocol dispatchers and logging hooks can
   * treat this instance as a {@code ClientHello} message regardless of how it was constructed or
   * routed.
   *
   * <p>The return value is constant and side effect free, making it safe to cache or compare by
   * reference inside switch statements. Returning a dedicated constant avoids allocations and
   * prevents accidental drift if other code spells the identifier differently.
   *
   * @return constant literal {@code "ClientHello"}, never {@code null}, for routing and tracing.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Completes the handshake by sending a {@link NodeHelloMessage} back through the supplied handler
   * and recording the announced client name for later auditing and quota attribution.
   *
   * <p>The method assumes the {@link FCPConnectionHandler} already verified message authenticity,
   * so it focuses on the happy path: building a node response using the handler's connection UUID
   * and dispatching it over the same channel. After the response leaves, the handler remembers the
   * client name so future log lines can refer to it even if the socket closes unexpectedly. The
   * {@link Node} parameter is currently unused but retained for parity with other {@link
   * FCPMessage} hooks.
   *
   * <pre>{@code
   * ClientHelloMessage hello = ...;
   * hello.run(handler, node);
   * }</pre>
   *
   * @param handler connection handler sending {@link NodeHelloMessage} and storing the announced
   *     client label.
   * @param node owning node reference reserved for future behavior, currently unused.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) {
    // We know the Hello is valid.
    FCPMessage msg = new NodeHelloMessage(handler.getConnectionIdentifierUUID().toString());
    handler.send(msg);
    handler.setClientName(clientName);
  }
}
