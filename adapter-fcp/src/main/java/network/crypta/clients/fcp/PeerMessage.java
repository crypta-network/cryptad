package network.crypta.clients.fcp;

import java.util.Map;
import java.util.Objects;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the server-to-client {@code Peer} FCP message built from a detached peer snapshot.
 *
 * <p>This type is lightweight and immutable; each instance stores only an immutable {@link
 * PeerSnapshot} plus an optional request identifier. Serialization is deferred until {@link
 * #getFieldSet()} rebuilds a fresh {@link SimpleFieldSet}, allowing callers to queue the message
 * without keeping a live daemon peer object in the response.
 */
public class PeerMessage extends FCPMessage {
  static final String NAME = "Peer";

  final PeerSnapshot snapshot;
  final String messageIdentifier;

  /**
   * Creates a {@code PeerMessage} that serializes the provided peer snapshot for downstream FCP
   * clients.
   *
   * @param snapshot detached peer snapshot to serialize
   * @param messageIdentifier optional caller-supplied token to correlate downstream responses
   */
  public PeerMessage(PeerSnapshot snapshot, String messageIdentifier) {
    this.snapshot = Objects.requireNonNull(snapshot);
    this.messageIdentifier = messageIdentifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} payload representing the stored peer snapshot for FCP
   * transmission.
   *
   * @return a mutable field set containing base peer data plus any requested optional sections
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = toSimpleFieldSet(snapshot.root());
    if (messageIdentifier != null) {
      fs.putSingle("Identifier", messageIdentifier);
    }
    return fs;
  }

  private static SimpleFieldSet toSimpleFieldSet(PeerFieldSet source) {
    SimpleFieldSet target = new SimpleFieldSet(true);
    for (Map.Entry<String, String> entry : source.directValues().entrySet()) {
      target.putSingle(entry.getKey(), entry.getValue());
    }
    for (Map.Entry<String, PeerFieldSet> entry : source.directSubsets().entrySet()) {
      target.tput(entry.getKey(), toSimpleFieldSet(entry.getValue()));
    }
    return target;
  }

  /**
   * Returns the fixed FCP message name used on the wire for peer descriptions.
   *
   * <p>The name is stable and shared across all instances, so routing and parsing logic in FCP
   * handlers can match incoming messages efficiently. Because it returns a constant, this method is
   * effectively free of side effects and can be invoked frequently by higher-level dispatchers
   * without additional allocations.
   *
   * @return the literal {@code "Peer"} message identifier expected by FCP clients
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Always rejects attempts to process a {@code Peer} message from client to server.
   *
   * <p>Peer messages are intended solely for server-to-client delivery; invoking this method on an
   * inbound path signals a protocol violation. The method therefore throws a {@link
   * MessageInvalidException} with the {@link ProtocolErrorMessage#INVALID_MESSAGE} code to ensure
   * the caller receives a clear, predictable failure. No state changes occur before the exception
   * is raised, and the operation is idempotent because it never mutates either the handler or the
   * node.
   *
   * @param handler connection handler that attempted to execute the message; not mutated here
   * @throws MessageInvalidException always thrown to indicate the direction is unsupported
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "Peer goes from server to client not the other way around",
        null,
        false);
  }
}
