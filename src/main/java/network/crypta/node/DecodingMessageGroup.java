package network.crypta.node;

/**
 * Callback contract for handling a batch of decrypted messages extracted from a single
 * datagram/packet.
 *
 * <p>The packet format ({@link NewPacketFormat}) decrypts an incoming packet, reassembles any
 * fragmented messages, and then delivers the raw, encoded message frames to an implementation of
 * this interface. Messages belonging to the same decrypted packet are delivered via consecutive
 * calls to {@link #processDecryptedMessage(byte[], int, int, int)} followed by a single call to
 * {@link #complete()} to signal end of batch. Implementations may decode, buffer, prioritize, or
 * otherwise process the provided frames before or at {@code complete()}.
 *
 * <p>Threading: the caller invokes these methods synchronously as part of packet handling. The
 * exact thread or executor is an implementation detail of the networking layer; implementations
 * should avoid long‑running or blocking work on the calling thread unless they explicitly own the
 * scheduling.
 */
public interface DecodingMessageGroup {

  /**
   * Receives one encoded message frame from the decrypted packet.
   *
   * <p>The provided byte region identifies a single message in the on‑wire format. Typical
   * implementations pass this buffer to the message codec for parsing (for example, {@code
   * node.network().usm().decodeSingleMessage(...)}), optionally deferring further handling until
   * {@link #complete()}.
   *
   * @param data backing array containing the encoded message bytes
   * @param offset start offset within {@code data}
   * @param length number of bytes to read starting at {@code offset}
   * @param overhead additional bytes to attribute to the received packet for statistics (e.g., link
   *     or protocol overhead); forwarded to decoders such as {@link
   *     network.crypta.io.comm.Message#decodeMessageFromPacket(byte[], int, int,
   *     network.crypta.io.comm.PeerContext, int)} when applicable
   */
  void processDecryptedMessage(byte[] data, int offset, int length, int overhead);

  /**
   * Signals that all message frames for the current decrypted packet have been delivered.
   *
   * <p>Implementations should use this callback to flush any deferred work, dispatch buffered
   * messages, and release temporary resources associated with the batch. The caller invokes this
   * exactly once per group, after zero or more {@link #processDecryptedMessage(byte[], int, int,
   * int)} calls.
   */
  void complete();
}
