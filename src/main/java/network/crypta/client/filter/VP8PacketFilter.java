package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 * Validates and minimally parses a VP8 frame header.
 *
 * <p>This lightweight filter inspects only the fixed-size header fields defined by the VP8
 * bitstream format (RFC 6386). It determines whether a buffer appears to contain a well-formed
 * frame and, when configured for WebP, enforces WebP-specific constraints such as the requirement
 * that the frame be a keyframe and marked as shown. The class does not decode video, manage state
 * across frames, or mutate the provided buffer; it performs a quick structural check suitable for
 * early rejection of invalid inputs.
 *
 * <p>Typical usage is to create one instance per decoding context and call {@link #parse(byte[],
 * int)} for each incoming buffer before handing it to downstream consumers. The method is strict by
 * design: it throws when encountering unsupported features (e.g., experimental version bits) or
 * obvious size mismatches. This helps surface input errors early and prevents unnecessary work in
 * later stages.
 *
 * <p>Thread-safety: instances are effectively immutable after construction and contain no mutable
 * shared state. They can be safely reused across threads provided the caller ensures the input
 * buffers themselves are not concurrently modified.
 *
 * <ul>
 *   <li>Reads only the first 3 or 10 bytes as required by the format.
 *   <li>Checks keyframe flag, experimental bit, shown flag (for WebP), and sync code.
 *   <li>Rejects inconsistent sizes to avoid partial/truncated inputs.
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6386">RFC 6386: VP8 Data Format and Decoding
 *     Guide</a>
 */
public class VP8PacketFilter {
  private final boolean isWebP;

  /**
   * Creates a new filter with optional WebP-specific validation.
   *
   * <p>When {@code isWebP} is {@code true}, the parser applies additional rules expected for WebP
   * still images embedded with VP8. Specifically, it requires the frame to be a keyframe, forbids
   * the experimental version bit, and enforces that the frame is marked as shown. When {@code
   * false}, the parser validates only generic VP8 header invariants.
   *
   * @param isWebP whether to enforce WebP constraints in addition to generic VP8 checks; pass
   *     {@code true} for WebP image validation or {@code false} for general VP8 streams.
   */
  public VP8PacketFilter(boolean isWebP) {
    this.isWebP = isWebP;
  }

  /**
   * Parses and validates the VP8 frame header contained in a byte buffer.
   *
   * <p>The method reads the minimal number of bytes required to validate a frame according to RFC
   * 6386. For generic VP8 streams it verifies core header invariants; when the instance was created
   * in WebP mode, it also requires the frame to be a keyframe and marked as shown. The buffer is
   * not modified. The call is idempotent with respect to the supplied bytes; repeated invocations
   * with the same input have no side effects.
   *
   * <p>On malformed input or unsupported features the method throws a runtime exception used by the
   * surrounding infrastructure to signal a data filtering failure. I/O failures while reading from
   * the in-memory stream surface as {@link IOException}.
   *
   * <pre>{@code
   * // Example: validate a VP8/WebP buffer before further processing
   * VP8PacketFilter f = new VP8PacketFilter(true);
   * f.parse(buffer, bufferLength);
   * }</pre>
   *
   * @param buf the input buffer that starts at the beginning of a VP8 frame; must contain at least
   *     {@code size} readable bytes and must not be {@code null}.
   * @param size the number of meaningful bytes in {@code buf} to consider; must be non-negative and
   *     not exceed {@code buf.length}.
   * @throws IOException if reading the in-memory stream fails unexpectedly while validating header
   *     bytes.
   */
  public void parse(byte[] buf, int size) throws IOException {
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(buf))) {
      // Reference: RFC 6386
      // Following code is based on vp8_parse_frame_header from RFC 6386
      int[] header = new int[6];
      for (int i = 0; i < 6; i++) header[i] = input.readUnsignedByte();
      int sizeInHeader;
      boolean isKeyframe;
      int tmp = header[0] | (header[1] << 8) | (header[2] << 16);
      isKeyframe = (tmp & 1) == 0;
      if (!isKeyframe && isWebP) {
        throw new DataFilterException(
            "VP8 decode error", "VP8 decode error", "Not a keyframe in WebP image");
      }
      if ((tmp & 0x8) != 0) { // is_experimental bit is unsupported
        throw new DataFilterException(
            "VP8 decode error", "VP8 decode error", "VP8 frame version is unsupported");
      }
      if ((tmp & 0x10) == 0 && isWebP) { // is_shown must be true for a WebP image
        throw new DataFilterException(
            "VP8 decode error",
            "VP8 decode error",
            "WebP frame contains an image without is_shown flag");
      }
      sizeInHeader = (tmp >> 5) & 0x7ffff;
      if (size <= sizeInHeader + (isKeyframe ? 10 : 3)) {
        throw new DataFilterException(
            "VP8 decode error", "VP8 decode error", "VP8 frame size is invalid");
      }
      if (isKeyframe && (header[3] != 0x9d || header[4] != 0x01 || header[5] != 0x2a)) {
        throw new DataFilterException(
            "VP8 decode error", "VP8 decode error", "VP8 frame sync code is invalid");
      }
    }
    // Rest of video: I don't know there is an attack
  }
}
