package network.crypta.node;

/**
 * Listener for node‑to‑node messages exchanged between peers.
 *
 * <p>Implementations are registered for a specific message type via {@link
 * Node#registerNodeToNodeMessageListener(int, NodeToNodeMessageListener)}. When a message with that
 * type is received from a remote peer, the node invokes {@link #handleMessage(byte[], boolean,
 * PeerNode, int)} with the raw payload and basic metadata. The payload format is defined by the
 * producer of the message; some built‑in handlers use UTF‑8 encoded {@code SimpleFieldSet}, but
 * callers are free to define other formats.
 *
 * <p>Threading and call ordering are controlled by the caller. No serialization guarantees are
 * provided by this interface; implementations should assume that invocations may occur on internal
 * I/O or networking threads and should return promptly. If substantial work is needed, prefer
 * offloading to application‑controlled executors.
 *
 * <p>Implementations should handle their own errors; the node does not wrap calls to {@link
 * #handleMessage(byte[], boolean, PeerNode, int)} in a protective {@code try/catch} at the
 * interface boundary.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public interface NodeToNodeMessageListener {

  /**
   * Handle a node‑to‑node message for the registered type.
   *
   * @param data Raw message payload in bytes. Never {@code null}; may be empty. The caller defines
   *     the encoding and schema.
   * @param fromDarknet {@code true} if {@code source} is a darknet (manually added) peer; {@code
   *     false} for opennet peers.
   * @param source Originating peer. Never {@code null}. When {@code fromDarknet} is {@code true},
   *     this is an instance of {@link DarknetPeerNode}.
   * @param type Numeric message type identifier associated with the registration. Provided for
   *     completeness and diagnostics; listeners are typically registered per type.
   */
  void handleMessage(byte[] data, boolean fromDarknet, PeerNode source, int type);
}
