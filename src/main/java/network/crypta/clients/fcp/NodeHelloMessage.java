package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.node.Node;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.support.SimpleFieldSet;

/**
 * Outbound server greeting sent over the Freenet Client Protocol (FCP).
 *
 * <p>The message is emitted immediately after accepting an FCP connection, so the client can learn
 * peer capabilities before issuing further commands. It advertises the negotiated protocol version
 * alongside the daemon metadata already captured in a detached {@link NodeGreetingSnapshot}. The
 * greeting echoes a connection-scoped identifier supplied at construction time so clients can
 * correlate socket handshakes with session state.
 *
 * <p>Instances are immutable after construction and only assemble metadata; they never write to the
 * network or mutate node state. Threads may reuse the same instance safely because all fields are
 * final and {@link #getFieldSet()} returns a fresh {@link SimpleFieldSet} each time. Typical usage
 * creates one instance per accepted connection and hands its field set to the surrounding {@link
 * FCPConnectionHandler} for serialization.
 *
 * <ul>
 *   <li>Responsibilities: assemble greeting metadata for new FCP connections.
 *   <li>Notable behavior: always rejects inbound use via {@link MessageInvalidException}.
 * </ul>
 */
public class NodeHelloMessage extends FCPMessage {

  /**
   * Canonical FCP message name used by the wire protocol and registry lookups.
   *
   * <p>This constant is stable across releases, so downstream components can perform equality
   * checks without depending on instantiated objects.
   */
  public static final String NAME = "NodeHello";

  private static final String FCP_VERSION = "2.0";

  private final NodeGreetingSnapshot greeting;
  private final String connectionIdentifier;

  /**
   * Creates a greeting message from a detached runtime snapshot and connection identifier.
   *
   * @param greeting runtime snapshot containing node metadata to serialize
   * @param connectionIdentifier opaque connection identifier chosen by the server; never {@code
   *     null}; echoed back to clients so they can match greetings to sockets or queued session
   *     metadata.
   */
  public NodeHelloMessage(NodeGreetingSnapshot greeting, String connectionIdentifier) {
    this.greeting = Objects.requireNonNull(greeting, "greeting");
    this.connectionIdentifier =
        Objects.requireNonNull(connectionIdentifier, "connectionIdentifier");
  }

  /**
   * Builds a {@link SimpleFieldSet} describing the node and its negotiated connection settings.
   *
   * <p>The returned set is freshly allocated on each call and includes the protocol version, the
   * stored node metadata snapshot, and the supplied connection identifier. All values are formatted
   * using primitive types or strings ready for FCP serialization.
   *
   * @return mutable field set ready for encoding; callers may add additional keys before sending
   *     without affecting later invocations because a new instance is produced each time.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("FCPVersion", FCP_VERSION);
    sfs.putSingle("Node", greeting.nodeName());
    sfs.putSingle("Version", greeting.versionString());
    sfs.put("Build", greeting.buildNumber());
    sfs.putSingle("Revision", greeting.revision());
    sfs.put("Testnet", greeting.testnetEnabled());
    sfs.putSingle("CompressionCodecs", greeting.compressionCodecs());
    sfs.putSingle("ConnectionIdentifier", connectionIdentifier);
    sfs.putSingle("NodeLanguage", greeting.nodeLanguage());
    return sfs;
  }

  /**
   * Returns the static FCP message name used on the wire.
   *
   * @return constant {@code "NodeHello"} identifying this message type during encoding and
   *     dispatch.
   */
  @Override
  public String getName() {
    return NodeHelloMessage.NAME;
  }

  /**
   * Rejects any inbound invocation of this message from a client.
   *
   * <p>The FCP specification defines {@code NodeHello} as a server-to-client greeting only. If a
   * client attempts to send it, the handler treats the message as invalid and surfaces a protocol
   * error.
   *
   * @param handler connection context that delivered the message; never {@code null}; not used in
   *     the rejection path but present to satisfy {@link FCPMessage} dispatch signatures.
   * @param node node instance backing the handler; never {@code null}; unused because the operation
   *     always fails.
   * @throws MessageInvalidException always thrown to signal that {@code NodeHello} is outbound-only
   *     and must not be received from clients.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "NodeHello goes from server to client not the other way around",
        null,
        false);
  }
}
