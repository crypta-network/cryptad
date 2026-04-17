package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Content data filter for MP3 (MPEG-1/2 audio) streams.
 *
 * <p>This filter performs lightweight structural validation of an MP3 bitstream and forwards audio
 * frames unchanged to the provided output. It recognizes and skips both ID3v2 headers at the
 * beginning of a stream and ID3v1 tags typically found at the end. While scanning, the filter
 * searches for a valid frame sync, validates header fields (MPEG version, layer, sample rate,
 * emphasis), and computes the length of each frame to copy it verbatim. Frames marked as protected
 * include a two-byte CRC which is preserved but not recalculated.
 *
 * <p>The implementation rejects uncommon or hard-to-handle cases to remain safe by default. In
 * particular, so-called “free format” bitstreams (non-standard bitrates) are considered invalid for
 * filtering purposes. Streams that never yield a plausible sequence of frames result in a
 * descriptive {@link DataFilterException} so callers can present meaningful error messages. The
 * filter does not attempt any decoding, transcoding, or re-encoding; it only validates headers,
 * skips metadata, and copies bytes.
 *
 * <ul>
 *   <li>Responsibilities: skip ID3 tags, validate frame headers, copy verified frames.
 *   <li>Concurrency: instances are stateless and effectively thread-safe.
 *   <li>Usage: typically invoked via {@link ContentFilter} dispatch for {@code audio/mpeg}.
 * </ul>
 *
 * @see ContentFilter
 * @see FilterCallback
 */
public class MP3Filter implements ContentDataFilter {
  private static final Logger LOG = LoggerFactory.getLogger(MP3Filter.class);

  // Various sources on the Internet.
  // The most comprehensive one appears to be:
  // http://mpgedit.org/mpgedit/mpeg_format/mpeghdr.htm
  // Others:
  // http://www.mp3-tech.org/programmer/frame_header.html
  // http://www.codeproject.com/KB/audio-video/mpegaudioinfo.aspx
  // http://www.id3.org/mp3Frame
  // http://www.mp3-converter.com/mp3codec/

  static final short[][][] bitRateIndices = {
    // Version 2.5
    {
      {},
      {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
      {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
      {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256}
    },
    // Reserved
    {},
    // Version 2.0
    {
      {},
      {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
      {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
      {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256}
    },
    // Version 1
    {
      {},
      {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320},
      {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384},
      {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448}
    }
  };

  static final int[][] sampleRateIndices = {
    // Version 2.5
    {11025, 12000, 8000},
    // Reserved
    {},
    // Version 2.0
    {22050, 24000, 16000},
    // Version 1
    {44100, 48000, 32000}
  };

  // Samples per frame for each [version][layer]
  static final int[][] samplesPerFrame = {
    // Version 2.5
    {0, 576, 1152, 384},
    // Reserved
    {},
    // Version 2
    {0, 576, 1152, 384},
    // Version 1
    {0, 1152, 1152, 384}
  };

  // Bits per slot for each layer
  static final int[] bitsPerSlot = {
    // Reserved
    0,
    // Layer III
    8,
    // Layer II
    8,
    // Layer I
    32
  };

  /**
   * Run the MP3 read filter, delegating to {@link #filter(InputStream, OutputStream)}.
   *
   * <p>This method is the {@link ContentDataFilter} integration point used by {@link
   * ContentFilter}. It ignores character set and auxiliary parameter hints because MP3 is a binary
   * container with self-describing frame headers. Upon encountering an invalid stream (for example,
   * no detectable sequence of frames or “free format” bitrate), the implementation throws a
   * descriptive {@link DataFilterException} which is a subtype of {@link IOException}. Successful
   * operation copies validated frames to {@code output} and leaves both streams open.
   *
   * <pre>{@code
   * var filter = new MP3Filter();
   * filter.readFilter(in, out, null, Map.of(), host, callback);
   * }</pre>
   *
   * @param input the source of MP3 bytes; must remain readable for the duration of filtering; not
   *     closed by this method
   * @param output the destination for validated frames; bytes are written as-is; the stream is
   *     flushed but not closed
   * @param charset unused for MP3 content; callers may pass {@code null} or an empty string safely
   * @param otherParams additional parameters supplied by the dispatcher; ignored by this filter but
   *     accepted for interface compatibility; may be {@code null}
   * @param schemeHostAndPort request authority used by higher layers; not used by this filter but
   *     passed through by the framework; may be {@code null}
   * @param cb callback for link discovery and tag replacement in text formats; not used here
   * @throws IOException if an I/O error occurs while reading input or writing output; includes
   *     validation failures signaled as {@link DataFilterException}
   */
  @Override
  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    filter(input, output);
  }

  /**
   * Validate an MP3 stream and forward verified frames to an output stream.
   *
   * <p>The method scans for the first valid frame sync, skipping ID3v2 and ID3v1 metadata when
   * present. For each candidate frame header it verifies version, layer, sample rate, and emphasis
   * fields, and computes the frame size using the bitrate, sampling rate, and slot size. CRC fields
   * are preserved transparently when present. So-called “free format” (non-indexed) bitrates are
   * intentionally rejected. If no plausible sequence of frames is found, a {@link
   * DataFilterException} is thrown to signal that the input does not resemble an MP3 stream.
   *
   * <pre>{@code
   * // Example: copy validated frames
   * new MP3Filter().filter(in, out);
   * }</pre>
   *
   * @param input readable stream of bytes expected to contain MP3 data; not closed by this method
   * @param output destination-receiving frames verbatim after validation; flushed but not closed
   * @throws IOException if reading or writing fails, or if validation fails with a {@link
   *     DataFilterException}
   */
  public void filter(InputStream input, OutputStream output) throws IOException {
    // Note: Free formatted files are uncommon and not supported.
    DataInputStream in = new DataInputStream(input);
    DataOutputStream out = new DataOutputStream(output);
    State st = new State();
    try {
      st.frameHeader = in.readInt();
    } catch (EOFException _) {
      handleEOF(out, st);
      return;
    }
    st.foundStream = hasFrameSync(st.frameHeader);
    boolean eof = false;
    while (!eof) {
      try {
        if (st.foundStream && hasFrameSync(st.frameHeader)) {
          processFrame(in, out, st);
        } else if (!st.foundStream && isID3v2Header(st.frameHeader)) {
          skipID3v2(in, st);
        } else if (!st.foundStream && isID3v1Tag(st.frameHeader)) {
          skipID3v1(in, st);
        } else {
          handleOutOfSync(in, st);
        }
      } catch (EOFException _) {
        eof = true;
      }
    }
    handleEOF(out, st);
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("MP3Filter." + key);
  }

  private static final class State {
    boolean foundStream = true;
    int totalFrames = 0;
    int totalCRCs = 0;
    int foundFrames = 0;
    int maxFoundFrames = 0;
    long countLostSyncBytes = 0;
    int countFreeBitrate = 0;
    int frameHeader;
  }

  private static boolean hasFrameSync(int header) {
    return (header & 0xffe00000) == 0xffe00000;
  }

  private static boolean isID3v2Header(int header) {
    return (header & 0xffffff00) == 0x49443300; // "ID3\0"
  }

  private static boolean isID3v1Tag(int header) {
    return (header & 0xffffff00) == 0x54414700; // "TAG\0"
  }

  private static void skipFully(InputStream in, int n) throws IOException {
    long remaining = n;
    while (remaining > 0) {
      long skipped = in.skip(remaining);
      if (skipped <= 0) {
        int b = in.read();
        if (b == -1) throw new EOFException();
        remaining--;
      } else {
        remaining -= skipped;
      }
    }
  }

  private static void skipID3v2(DataInputStream in, State st) throws IOException {
    skipFully(in, 2); // minor version, flags
    byte[] encodedSize = new byte[4];
    in.readFully(encodedSize);
    int size = 0;
    size |= (encodedSize[0] & 0x7F) << 21;
    size |= (encodedSize[1] & 0x7F) << 14;
    size |= (encodedSize[2] & 0x7F) << 7;
    size |= (encodedSize[3] & 0x7F);
    skipFully(in, size);
    LOG.info("ID3v2 header skipped: {} bytes", size);
    st.frameHeader = in.readInt();
    st.foundStream = hasFrameSync(st.frameHeader);
  }

  private static void skipID3v1(DataInputStream in, State st) throws IOException {
    skipFully(in, 124); // the fixed length is 128 bytes; 4 already read
    LOG.info("ID3v1 tag skipped");
    st.frameHeader = in.readInt();
    st.foundStream = hasFrameSync(st.frameHeader);
  }

  private static void handleOutOfSync(DataInputStream in, State st) throws IOException {
    if (st.foundFrames != 0) LOG.info("Frame run ended before resync: {} frames", st.foundFrames);
    if (st.foundFrames > st.maxFoundFrames) st.maxFoundFrames = st.foundFrames;
    st.foundFrames = 0;
    st.frameHeader = st.frameHeader << 8;
    st.frameHeader |= in.readUnsignedByte();
    if (hasFrameSync(st.frameHeader)) {
      st.foundStream = true;
    } else {
      st.countLostSyncBytes++;
    }
  }

  private static void processFrame(DataInputStream in, DataOutputStream out, State st)
      throws IOException {
    final int frameHeader = st.frameHeader;
    final int version = (frameHeader >>> 19) & 0x03; // 2 bits
    if (version == 1) {
      st.foundStream = false;
      return; // Not valid
    }
    final int layer = (frameHeader >>> 17) & 0x03; // 2 bits
    if (layer == 0) {
      st.foundStream = false;
      return; // Not valid
    }
    // WARNING: layer is encoded! 1 = layer 3, 2 = layer 2, 3 = layer 1!
    final boolean hasCRC = ((frameHeader & 0x00010000) >>> 16) != 1; // 1 bit, but inverted
    final int bitrateIndex = (frameHeader >>> 12) & 0x0F; // 4 bits
    if (bitrateIndex == 0) {
      // Free bitrate ("freeformat") is hard to support and uncommon.
      st.foundStream = false;
      st.countFreeBitrate++;
      return; // Not valid
    }
    if (bitrateIndex == 15) {
      st.foundStream = false;
      return; // Not valid
    }
    final int samplerateIndex = (frameHeader >>> 10) & 0x03; // 2 bits
    if (samplerateIndex == 3) {
      st.foundStream = false;
      return; // Not valid
    }
    final boolean paddingBit = ((frameHeader & 0x00000200) >>> 9) == 1;
    byte emphasis = (byte) (frameHeader & 0x00000003);
    if (emphasis == 2) {
      st.foundStream = false;
      return; // Not valid
    }

    final int bitrate = bitRateIndices[version][layer][bitrateIndex] * 1000;
    final int samplerate = sampleRateIndices[version][samplerateIndex];
    final int samples = samplesPerFrame[version][layer];
    final int granularity = bitsPerSlot[layer];
    int frameLength = samples / granularity * bitrate / samplerate;
    frameLength += paddingBit ? 1 : 0;
    // Avoid integer-division-before-multiplication; multiply first, then divide
    frameLength = (frameLength * granularity) / 8;

    short crc = 0;
    if (hasCRC) {
      st.totalCRCs++;
      crc = in.readShort();
      LOG.info("Frame CRC present");
      // CRC calculation is not implemented; the value is preserved.
    }

    byte[] frame = new byte[frameLength - 4];
    in.readFully(frame);
    out.writeInt(frameHeader);
    if (hasCRC) out.writeShort(crc);
    out.write(frame);
    st.totalFrames++;
    st.foundFrames++;
    if (st.countLostSyncBytes != 0)
      LOG.info("Recovered frame sync after {} bytes", st.countLostSyncBytes);
    st.countLostSyncBytes = 0;
    st.frameHeader = in.readInt();
  }

  private void handleEOF(DataOutputStream out, State st) throws IOException {
    if (st.foundFrames != 0) LOG.info("EOF after final frame run: {} frames", st.foundFrames);
    if (st.countLostSyncBytes != 0)
      LOG.info("EOF with trailing out-of-sync bytes: {}", st.countLostSyncBytes);
    if (st.totalFrames == 0 || st.maxFoundFrames < 10) {
      if (st.countFreeBitrate > 100)
        throw new DataFilterException(
            l10n("freeBitrateNotSupported"),
            l10n("freeBitrateNotSupported"),
            l10n("freeBitrateNotSupportedExplanation"));
      if (st.totalFrames == 0)
        throw new DataFilterException(
            l10n("bogusMP3NoFrames"),
            l10n("bogusMP3NoFrames"),
            l10n("bogusMP3NoFramesExplanation"));
    }

    out.flush();
    LOG.info("MP3 filter completed: {} frames ({} with CRC)", st.totalFrames, st.totalCRCs);
  }
}
