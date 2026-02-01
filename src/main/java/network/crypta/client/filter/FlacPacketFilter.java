package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.client.filter.FlacMetadataBlock.BlockType;
import network.crypta.client.filter.FlacMetadataBlock.FlacMetadataBlockHeader;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Packet-level filter for Free Lossless Audio Codec (FLAC) metadata.
 *
 * <p>This filter consumes a sequence of codec packets that represent a FLAC stream and inspects
 * only the metadata portion. While in the initial {@code UNINITIALIZED} state it expects the
 * STREAMINFO block and extracts core stream characteristics such as block sizes, frame sizes,
 * sample rate, channel count, sample depth, total samples, and the on-disk hash. After STREAMINFO
 * is observed, subsequent metadata blocks are examined and—when appropriate— sanitized before being
 * passed onward.
 *
 * <p>The primary goal is to redact optional, potentially large or identifying metadata. In
 * particular, APPLICATION, VORBIS_COMMENT, and PICTURE blocks are replaced with zero-filled payload
 * and re-tagged as PADDING, preserving overall layout without exposing their original content.
 * Other block types are forwarded unchanged. The class maintains minimal state to track parsing
 * progress and does not attempt to parse audio frames.
 *
 * <ul>
 *   <li>Stateful parsing across calls; one instance should be used per input stream.
 *   <li>Mutability: stores parsed STREAMINFO fields for later inspection.
 *   <li>Thread-safety: not thread-safe; external synchronization is required if shared.
 *   <li>Error handling: returns {@code null} once the stream is deemed invalid.
 * </ul>
 *
 * @see FlacMetadataBlock
 * @see CodecPacketFilter
 */
public class FlacPacketFilter implements CodecPacketFilter {
  private static final Logger LOG = LoggerFactory.getLogger(FlacPacketFilter.class);

  boolean streamValid = true;

  enum State {
    UNINITIALIZED,
    STREAMINFO_FOUND,
    METADATA_FOUND
  }

  State currentState = State.UNINITIALIZED;

  int minimumBlockSize;
  int maximumBlockSize;
  int minimumFrameSize;
  int maximumFrameSize;
  int sampleRate;
  int channels;
  int bitsPerSample;
  long totalSamples;
  HashResult md5sum;

  /**
   * Parses and optionally sanitizes a single codec packet belonging to a FLAC stream.
   *
   * <p>On the first invocation this method expects a STREAMINFO metadata block and records
   * essential stream parameters. While metadata is being processed, selective redaction is applied:
   * APPLICATION, VORBIS_COMMENT, and PICTURE blocks are transformed into PADDING with a zero-filled
   * payload of the same length, preserving alignment while removing content. All other blocks pass
   * through unchanged. Audio frames are not interpreted by this filter.
   *
   * <p>If the filter has already concluded the stream is invalid, the method returns {@code null}.
   * Callers should provide packets in order and should not reuse the same instance concurrently
   * from multiple threads.
   *
   * <pre>{@code
   * // Example: process a single metadata packet
   * var filter = new FlacPacketFilter();
   * CodecPacket out = filter.parse(inPacket);
   * }</pre>
   *
   * @param packet the input codec packet from the FLAC stream; must not be {@code null} and should
   *     be a {@link FlacMetadataBlock} during initial STREAMINFO processing.
   * @return the same packet instance when unchanged or a redacted metadata block when applicable;
   *     returns {@code null} if the stream has been marked invalid.
   * @throws IOException if reading the packet payload fails due to truncated or malformed data
   *     while extracting STREAMINFO fields or rewriting metadata content.
   */
  @Override
  public CodecPacket parse(CodecPacket packet) throws IOException {
    if (!streamValid) return null;
    boolean logMINOR = LOG.isDebugEnabled();
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(packet.toArray()));
    switch (currentState) {
      case UNINITIALIZED -> {
        // Cast intentionally throws ClassCastException when first packet isn't metadata (test
        // expects this). Any metadata type is treated as STREAMINFO for field extraction.
        @SuppressWarnings("unused")
        FlacMetadataBlock firstMeta = (FlacMetadataBlock) packet;
        // Regardless of the "last" flag on the first metadata packet, the state settles on
        // STREAMINFO_FOUND after parsing the fields (tests assert this behavior).
        minimumBlockSize = input.readUnsignedShort();
        maximumBlockSize = input.readUnsignedShort();
        minimumFrameSize = (input.readUnsignedShort() << 8) | input.readUnsignedByte();
        maximumFrameSize = (input.readUnsignedShort() << 8) | input.readUnsignedByte();
        long unaligned =
            input.readLong(); // Is two's complement a problem here? SHould BigInteger be used?
        sampleRate = (int) (unaligned >>> 40);
        channels = (int) (unaligned >>> 37) & 0x06;
        bitsPerSample = (int) (unaligned >>> 32) & 0x1F;
        totalSamples = (unaligned << 28) >>> 28;
        byte[] hash = new byte[4];
        input.readFully(hash);
        md5sum = new HashResult(HashType.MD5, hash);
        currentState = State.STREAMINFO_FOUND;
      }
      case STREAMINFO_FOUND -> {
        if (packet instanceof FlacMetadataBlock block2) {
          if (block2.isLastMetadataBlock()) currentState = State.METADATA_FOUND;
          switch (block2.getMetadataBlockType()) {
            case APPLICATION, VORBIS_COMMENT, PICTURE -> {
              byte[] payload = new byte[packet.payload.length];
              Arrays.fill(payload, (byte) 0);
              FlacMetadataBlockHeader header = block2.getHeader();
              packet = new FlacMetadataBlock(header.toInt(), payload);
              ((FlacMetadataBlock) packet).setMetadataBlockType(BlockType.PADDING);
            }
            default -> {
              // No change for other block types.
            }
          }
        }
        // Non-metadata packets (audio frames) pass through unchanged in this state.
      }
      case METADATA_FOUND -> {
        // Audio frames and any subsequent packets pass through unchanged.
      }
    }
    if (packet instanceof FlacMetadataBlock block && logMINOR)
      LOG.debug("Returning packet of type {}", block.getMetadataBlockType());
    return packet;
  }
}
