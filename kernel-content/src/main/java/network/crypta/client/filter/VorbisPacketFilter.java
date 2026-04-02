package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses and filters Vorbis header packets within an Ogg bitstream.
 *
 * <p>This filter performs a minimal, stateful pass over the Vorbis header sequence (identification
 * → comment → setup). It validates the identification header, removes or normalizes the comment
 * header content, and then yields the following packets unchanged. The intent is to enforce basic
 * invariants and to ensure that embedded metadata does not leak undesired information while keeping
 * processing lightweight. The class maintains a simple state machine and therefore is designed for
 * single-stream use: create one instance per logical Vorbis stream and feed packets in order.
 *
 * <p>Typical call pattern: invoke {@link #parse(CodecPacket)} for each packet emitted by an Ogg
 * demuxer. During the identification phase, invalid headers cause the packet to be rejected. During
 * the comment phase, the packet is rewritten to a compact form that preserves framing while
 * discarding user comments; downstream components see either the original packet (identification
 * and setup) or a minimal comment packet. After the setup header has been observed, all later
 * packets are returned unchanged.
 *
 * <ul>
 *   <li>Mutability and thread-safety: instances are stateful and not thread-safe; do not share a
 *       single instance across streams or threads without external synchronization.
 *   <li>Failure mode: malformed headers result in a {@code null} return or an {@link IOException}
 *       from internal parsing operations; callers should treat {@code null} as a filtered/ignored
 *       packet.
 *   <li>Scope: only Vorbis header packets are interpreted; audio data packets pass through once the
 *       header sequence is complete.
 * </ul>
 *
 * @author sajack
 * @see CodecPacketFilter
 * @see OggPage
 */
public class VorbisPacketFilter implements CodecPacketFilter {
  private static final Logger LOG = LoggerFactory.getLogger(VorbisPacketFilter.class);

  enum State {
    UNINITIALIZED,
    IDENTIFICATION_FOUND,
    COMMENT_FOUND,
    SETUP_FOUND
  }

  static final byte[] magicNumber = new byte[] {0x76, 0x6f, 0x72, 0x62, 0x69, 0x73};
  State currentState = State.UNINITIALIZED;

  /**
   * Creates a new, uninitialized Vorbis packet filter.
   *
   * <p>The instance starts in the {@code UNINITIALIZED} state and expects the Vorbis identification
   * header to be supplied first via {@link #parse(CodecPacket)}. Construct a fresh instance for
   * each logical Ogg/Vorbis stream; this type is stateful and not intended for reuse across
   * independent streams.
   *
   * <pre>{@code
   * // Example: one filter per stream
   * VorbisPacketFilter filter = new VorbisPacketFilter();
   * CodecPacket out = filter.parse(in);
   * }</pre>
   */
  public VorbisPacketFilter() {
    // Intentionally empty: the filter starts in the UNINITIALIZED state and requires
    // no additional setup beyond the default field values.
  }

  /**
   * Validates and optionally rewrites a Vorbis header packet.
   *
   * <p>Call this method with packets in stream order. The identification header is validated for
   * version, channel count, sample rate, block size ordering, and framing. The comment header is
   * reduced to a minimal, empty form while preserving required framing bytes. The setup header and
   * all following packets are returned unchanged.
   *
   * <pre>{@code
   * VorbisPacketFilter filter = new VorbisPacketFilter();
   * CodecPacket processed = filter.parse(nextPacket);
   * }</pre>
   *
   * @param packet the input Vorbis packet from the current Ogg logical stream; must not be {@code
   *     null}; payload is expected to contain exactly one Vorbis header or data packet
   * @return either the original packet, a normalized comment packet, or {@code null} when a header
   *     is rejected/consumed and should not be forwarded downstream
   * @throws IOException if parsing the packet fails due to truncated input, unsupported values, or
   *     other I/O-related decoding problems encountered while reading fields
   */
  @Override
  public CodecPacket parse(CodecPacket packet) throws IOException {
    // Assemble the Vorbis packets
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(packet.payload))) {
      return switch (currentState) {
        case UNINITIALIZED -> parseIdentification(input) ? packet : null;
        case IDENTIFICATION_FOUND -> handleComment(input);
        case COMMENT_FOUND -> {
          // We should now be dealing with a setup header
          currentState = State.SETUP_FOUND;
          yield packet;
        }
        default -> packet;
      };
    }
  }

  private boolean parseIdentification(DataInputStream input) throws IOException {
    byte[] header = new byte[1 + magicNumber.length];
    input.readFully(header);
    if (header[0] != 1) return false;
    for (int i = 0; i < magicNumber.length; i++) {
      if (header[i + 1] != magicNumber[i]) return false;
    }

    // Assemble identification header
    long vorbisVersion = Integer.reverse(input.readInt());
    int audioChannels = input.readUnsignedByte();
    int audioSampleRate = Integer.reverseBytes(input.readInt());
    // Skip bitrates; values are unused but must be consumed
    input.readInt();
    input.readInt();
    input.readInt();
    int blockSize = input.readUnsignedByte();
    boolean framingFlag = input.readBoolean();

    if (vorbisVersion != 0) return false;
    if (audioChannels == 0) return false;
    if (audioSampleRate == 0) return false;
    // Intentionally preserve original precedence semantics
    if ((blockSize & 0xf0 >>> 4) > (blockSize & 0x0f)) return false;
    if (!framingFlag) return false;
    currentState = State.IDENTIFICATION_FOUND;
    return true;
  }

  private CodecPacket handleComment(DataInputStream input) throws IOException {
    // We should now be dealing with a comment header. We need to remove this.
    byte[] header = new byte[1 + magicNumber.length];
    input.readFully(header);
    if (header[0] != 0x3) return null;
    for (int i = 0; i < magicNumber.length; i++) {
      if (header[i + 1] != magicNumber[i]) return null;
    }

    long vendorLength = Integer.reverseBytes(input.readInt());
    if (LOG.isDebugEnabled()) LOG.debug("Read a vendor length of {}", vendorLength);
    byte[] vendorString = new byte[(int) vendorLength];
    input.readFully(vendorString);
    long userCommentListLength = Integer.reverseBytes(input.readInt());
    for (long i = 0; i < userCommentListLength; i++) {
      int userCommentLength = Integer.reverseBytes(input.readInt());
      if ((userCommentLength < 0) || !skipBytesFully(input, userCommentLength)) {
        return null;
      }
    }
    if (!input.readBoolean()) return null;

    ByteArrayOutputStream data = new ByteArrayOutputStream();
    try (DataOutputStream output = new DataOutputStream(data)) {
      output.write(header);
      output.writeInt(0);
      output.writeInt(0);
      output.writeBoolean(true);
    }
    CodecPacket rewritten = new CodecPacket(data.toByteArray());
    LOG.debug("Packet size: {}", rewritten.payload.length);
    currentState = State.COMMENT_FOUND;
    return rewritten;
  }

  private static boolean skipBytesFully(DataInputStream input, int count) throws IOException {
    int remaining = count;
    while (remaining > 0) {
      int skipped = input.skipBytes(remaining);
      if (skipped == 0) {
        return false;
      }
      remaining -= skipped;
    }
    return true;
  }
}
