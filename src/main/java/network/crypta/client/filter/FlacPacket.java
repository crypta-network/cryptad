package network.crypta.client.filter;

import java.nio.ByteBuffer;

/**
 * Base representation of a FLAC data packet handled by the client filter pipeline.
 *
 * <p>This abstract type models a unit of FLAC content as it flows through decoding and
 * transformation stages. Instances wrap an immutable payload buffer supplied to the constructor and
 * delegate common behavior such as byte-array equality to the {@link CodecPacket} superclass.
 * Subclasses typically differentiate between metadata blocks and audio frames while preserving a
 * consistent binary representation for transport and inspection.
 *
 * <p>Use this type when you need a uniform view over FLAC structures without committing to a
 * specific block or frame shape. Typical call patterns include constructing a concrete subclass
 * from parsed bytes, forwarding the packet through filters, and, when needed, materializing the
 * packet back to a byte array via {@code toArray()}. Instances are effectively read-only after
 * creation and are not thread-confined; callers may share them safely as long as they observe the
 * immutability of the payload array.
 *
 * <ul>
 *   <li>Immutability: packet instances do not modify their payload.
 *   <li>Equality: defined by the underlying payload bytes and length.
 *   <li>Use cases: parsing, validation, and relay across filter stages.
 * </ul>
 *
 * @see CodecPacket
 */
public abstract class FlacPacket extends CodecPacket {

  FlacPacket(byte[] payload) {
    super(payload);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj) {
    // No additional state in this subclass; defer to superclass equality
    return super.equals(obj);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    // Preserve contract with equals by delegating to superclass
    return super.hashCode();
  }
}

/**
 * FLAC metadata block packet carrying a parsed header and raw block payload.
 *
 * <p>The instance exposes the "is last" flag, block type, and the declared length as parsed from
 * the 32-bit FLAC metadata header. The on-wire representation consists of the 4-byte header
 * followed by the block payload. The {@link #toArray()} method re-materializes this exact layout,
 * which is useful for forwarding or re-encoding without modification.
 *
 * <p>This type is intended for clients that need to inspect or rewrite metadata while preserving
 * binary compatibility with existing streams. The header returned by {@link #getHeader()} is a
 * defensive copy so callers cannot mutate the internal state inadvertently. The payload array comes
 * from the superclass and is treated as immutable by conventions in this package.
 */
class FlacMetadataBlock extends FlacPacket {
  /**
   * Known FLAC metadata block types as defined by the FLAC specification. Values outside the
   * enumerated set are surfaced as {@link #UNKNOWN}, and the reserved value {@code 127} maps to
   * {@link #INVALID} to reflect a non-conformant block.
   */
  enum BlockType {
    STREAMINFO,
    PADDING,
    APPLICATION,
    SEEKTABLE,
    VORBIS_COMMENT,
    CUESHEET,
    PICTURE,
    UNKNOWN,
    INVALID
  }

  private final FlacMetadataBlockHeader header = new FlacMetadataBlockHeader();

  /**
   * Create a metadata block from a parsed 32-bit header and payload bytes.
   *
   * <p>The most significant bit of {@code header} denotes the last-metadata-block flag. The next 7
   * bits carry the block type, and the lower 24 bits carry the block length in bytes. The provided
   * {@code payload} length is not validated against the length field here; callers should ensure
   * consistency before constructing instances when strict validation is required.
   *
   * @param header packed 32-bit FLAC metadata header (flag, type, length), already parsed
   * @param payload block payload bytes; treated as read-only by callers after construction
   */
  FlacMetadataBlock(int header, byte[] payload) {
    super(payload);
    this.header.lastMetadataBlock = ((header & 0x80000000) >>> 31) == 1;
    this.header.blockType = (byte) ((header & 0x7F000000) >>> 24);
    this.header.length = (header & 0x00FFFFFF);
  }

  /**
   * Return the canonical byte representation of this metadata block.
   *
   * <p>The result contains the 4-byte header (reconstructed from the current header fields)
   * followed by the raw payload bytes in their original order. The returned array is a fresh buffer
   * that callers own and may modify without affecting this instance.
   *
   * @return a new byte array composed of the 4-byte header followed by the payload bytes
   */
  @Override
  public byte[] toArray() {
    ByteBuffer bb = ByteBuffer.allocate(getLength());
    bb.putInt(header.toInt());
    bb.put(payload);
    return bb.array();
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj) {
    // Equality is defined by payload in the superclass; header is auxiliary
    return super.equals(obj);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    // Keep hashCode consistent with equals (payload-based)
    return super.hashCode();
  }

  /**
   * Indicate whether this is flagged as the last metadata block in the stream info section.
   *
   * @return {@code true} when the header's last-metadata-block flag is set; otherwise {@code false}
   */
  public boolean isLastMetadataBlock() {
    return header.lastMetadataBlock;
  }

  /**
   * Map the numeric block type from the header to a stable {@link BlockType} value.
   *
   * <p>Types outside the known range are returned as {@link BlockType#UNKNOWN}. The FLAC-reserved
   * value {@code 127} is returned as {@link BlockType#INVALID} to indicate a definite protocol
   * violation.
   *
   * @return the semantic block type corresponding to the header's 7-bit type field
   */
  public BlockType getMetadataBlockType() {
    return switch (header.blockType) {
      case 0 -> BlockType.STREAMINFO;
      case 1 -> BlockType.PADDING;
      case 2 -> BlockType.APPLICATION;
      case 3 -> BlockType.SEEKTABLE;
      case 4 -> BlockType.VORBIS_COMMENT;
      case 5 -> BlockType.CUESHEET;
      case 6 -> BlockType.PICTURE;
      case 127 -> BlockType.INVALID;
      default -> BlockType.UNKNOWN;
    };
  }

  /**
   * Set the block type field in the header using a semantic {@link BlockType} value.
   *
   * <p>Only supported, well-defined types are written. Passing {@link BlockType#UNKNOWN} or {@link
   * BlockType#INVALID} leaves the current header value unchanged to avoid committing non-conformant
   * type codes. This method does not alter the payload.
   *
   * @param type the target metadata category; unsupported values are ignored safely
   */
  public void setMetadataBlockType(BlockType type) {
    switch (type) {
      case STREAMINFO:
        this.header.blockType = 0;
        break;
      case PADDING:
        this.header.blockType = 1;
        break;
      case APPLICATION:
        this.header.blockType = 2;
        break;
      case SEEKTABLE:
        this.header.blockType = 3;
        break;
      case VORBIS_COMMENT:
        this.header.blockType = 4;
        break;
      case CUESHEET:
        this.header.blockType = 5;
        break;
      case PICTURE:
        this.header.blockType = 6;
        break;
      default:
        // No action for UNKNOWN/INVALID types
        break;
    }
  }

  /**
   * Obtain a defensive copy of the parsed header values for inspection or serialization.
   *
   * <p>The returned object is a shallow value holder. Mutating it does not affect this metadata
   * block instance. To derive the byte representation of the current header, use {@link
   * FlacMetadataBlockHeader#toInt()} on the returned copy.
   *
   * @return a new {@code FlacMetadataBlockHeader} populated with this block's header fields
   */
  public FlacMetadataBlockHeader getHeader() {
    FlacMetadataBlockHeader newHeader = new FlacMetadataBlockHeader();
    newHeader.lastMetadataBlock = this.header.lastMetadataBlock;
    newHeader.blockType = this.header.blockType;
    newHeader.length = this.header.length;
    return newHeader;
  }

  /**
   * Compute the total encoded size of this metadata block including the 4-byte header.
   *
   * @return the number of bytes that {@link #toArray()} will produce
   */
  public int getLength() {
    return 4 + header.length;
  }

  /**
   * Lightweight value holder for FLAC metadata header fields.
   *
   * <p>It contains the "last" flag, the block type (as an unsigned 8-bit value stored in a byte),
   * and the declared payload length. The {@link #toInt()} method packs these fields into the
   * canonical 32-bit representation used on the wire.
   */
  static class FlacMetadataBlockHeader {
    boolean lastMetadataBlock;
    byte blockType;
    int length;

    /**
     * Pack the header fields to the 32-bit FLAC metadata header encoding.
     *
     * @return an integer with bit 31 as the last-block flag, bits 30..24 as type, and 23..0 length
     */
    public int toInt() {
      return ((lastMetadataBlock ? 1 : 0) << 31) | ((blockType & 0xFF) << 24) | length;
    }
  }
}

/**
 * FLAC audio frame packet that carries encoded sample data.
 *
 * <p>This subclass exists for symmetry with {@code FlacMetadataBlock} and to convey intent when a
 * packet represents an audio frame rather than a metadata structure. Behavior is inherited from
 * {@link CodecPacket}; payload equality and hashing follow the same rules as other packet types.
 * Instances are immutable with respect to their payload.
 */
class FlacFrame extends FlacPacket {

  /**
   * Construct a frame packet from the supplied encoded frame bytes.
   *
   * @param payload raw FLAC frame payload; callers should treat the array as read-only thereafter
   */
  FlacFrame(byte[] payload) {
    super(payload);
  }
}
