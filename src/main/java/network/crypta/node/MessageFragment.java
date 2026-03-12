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
   * @param header header flags and message identifier metadata
   * @param sizes length and offset metadata for the fragment
   * @param payload payload bytes and originating wrapper reference
   */
  public MessageFragment(
      MessageFragmentHeader header, MessageFragmentSizes sizes, MessageFragmentPayload payload) {
    this.shortMessage = header.shortMessage();
    this.isFragmented = header.isFragmented();
    this.firstFragment = header.firstFragment();
    this.messageID = header.messageID();
    this.fragmentLength = sizes.fragmentLength();
    this.messageLength = sizes.messageLength();
    this.fragmentOffset = sizes.fragmentOffset();
    this.fragmentData = payload.fragmentData();
    this.wrapper = payload.wrapper();
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

    // The size of the additional header field present only when the message is fragmented.
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
