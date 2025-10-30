package network.crypta.node;

/**
 * Immutable descriptor for a single message fragment in the node's packet format.
 *
 * <p>A fragment contains a slice of payload and minimal metadata required for reassembly on the
 * receiver. Its encoded size on the wire is the sum of:
 *
 * <ul>
 *   <li>2 bytes: message id and flags
 *   <li>1 or 2 bytes: fragment length (1 byte when {@code shortMessage} is {@code true})
 *   <li>optional 1 or 2 bytes: present only when {@code isFragmented} is {@code true} (size again
 *       follows {@code shortMessage})
 *   <li>N bytes: payload ({@code fragmentData.length})
 * </ul>
 *
 * <p>All fields are {@code final}; instances are thread-safe and may be shared across threads.
 */
class MessageFragment {
  final boolean shortMessage;
  final boolean isFragmented;
  final boolean firstFragment;
  final int messageID;
  final int fragmentLength;
  final int messageLength;
  final int fragmentOffset;
  final byte[] fragmentData;
  final MessageWrapper wrapper;

  /**
   * Creates a new immutable fragment description.
   *
   * @param shortMessage {@code true} when the message uses single-byte size fields
   * @param isFragmented {@code true} when the message is split across multiple fragments
   * @param firstFragment {@code true} when this is the first fragment of the message
   * @param messageID identifier of the logical message this fragment belongs to
   * @param fragmentLength declared fragment length (may differ from {@code fragmentData.length})
   * @param messageLength total message length for first fragments; otherwise ignored
   * @param fragmentOffset byte offset of this fragment within the full message (0-based)
   * @param fragmentData payload bytes of this fragment; used for size and transmission
   * @param wrapper originating wrapper when sending; {@code null} when created by a receiver
   */
  public MessageFragment(
      boolean shortMessage,
      boolean isFragmented,
      boolean firstFragment,
      int messageID,
      int fragmentLength,
      int messageLength,
      int fragmentOffset,
      byte[] fragmentData,
      MessageWrapper wrapper) {
    this.shortMessage = shortMessage;
    this.isFragmented = isFragmented;
    this.firstFragment = firstFragment;
    this.messageID = messageID;
    this.fragmentLength = fragmentLength;
    this.messageLength = messageLength;
    this.fragmentOffset = fragmentOffset;
    this.fragmentData = fragmentData;
    this.wrapper = wrapper;
  }

  /**
   * Returns the number of bytes this fragment occupies in a packet.
   *
   * <p>The calculation includes the fixed header (message id and flags), the fragment length field,
   * the optional extra field present for fragmented messages, and the payload size ({@code
   * fragmentData.length}). The return value is independent of {@code fragmentLength}.
   *
   * @return encoded length in bytes
   */
  public int length() {
    // Compute header sizes explicitly to avoid nested ternaries for readability.
    int messageIdAndFlagsBytes = 2; // 2 bytes for message id and flags
    int fragmentLengthBytes = shortMessage ? 1 : 2; // size of the fragment-length field

    // Size of the additional header field present only when the message is fragmented.
    // The field carries either the total message length (first fragment) or the fragment offset.
    int offsetOrMessageLengthBytes = 0;
    if (isFragmented) {
      // Use 1 byte for short messages; otherwise 2 bytes.
      offsetOrMessageLengthBytes = shortMessage ? 1 : 2;
    }

    return messageIdAndFlagsBytes
        + fragmentLengthBytes
        + offsetOrMessageLengthBytes
        + fragmentData.length;
  }

  /**
   * Returns a concise, single-line summary containing the message id, byte offset, and payload
   * length. The format is stable and consumed by tests.
   */
  @Override
  public String toString() {
    return "Fragment from message "
        + messageID
        + ": offset "
        + fragmentOffset
        + ", data length "
        + fragmentData.length;
  }
}
