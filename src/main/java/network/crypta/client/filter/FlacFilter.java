package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import network.crypta.l10n.NodeL10n;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FLAC bitstream filter that validates and passes through native FLAC streams.
 *
 * <p>This filter reads a byte stream that starts with the canonical {@code fLaC} marker followed by
 * one or more metadata blocks and then audio frames, as specified by the FLAC format. It validates
 * the file signature, forwards (and, when required, minimally rewrites) metadata blocks, and then
 * copies audio frames while preserving frame boundaries. The implementation performs conservative
 * checks and avoids format reinterpretation: it does not decode audio, resample, or alter the
 * content beyond the limited metadata sanitation performed by {@link FlacPacketFilter}.
 *
 * <p>Typical usage is to construct a single instance and invoke {@link #readFilter(InputStream,
 * OutputStream, String, Map, String, FilterCallback)} for each input stream that needs validation
 * and pass-through filtering. Instances hold no external state and are safe to reuse sequentially
 * on multiple inputs. The filter operates synchronously; it performs no internal threading and does
 * not retain references to the input or output streams after returning.
 *
 * <p><strong>Notable behaviors</strong>:
 *
 * <ul>
 *   <li>Validates the leading magic number and propagates it to the output.
 *   <li>Reads and forwards metadata blocks; application, comment, and picture blocks are padded via
 *       {@link FlacPacketFilter} to remove potentially identifying information.
 *   <li>Detects FLAC frame sync markers to delineate frames; the filter copies frame payloads
 *       without re-encoding.
 *   <li>Stops gracefully on end‑of‑stream; partial trailing frames are not emitted.
 * </ul>
 *
 * @see FlacPacketFilter
 * @see FlacMetadataBlock
 */
public class FlacFilter implements ContentDataFilter {
  private static final Logger LOG = LoggerFactory.getLogger(FlacFilter.class);

  static final byte[] magicNumber = new byte[] {0x66, 0x4C, 0x61, 0x43};

  enum State {
    UNINITIALIZED,
    STREAMINFO_FOUND,
    METADATA_FOUND,
    STREAM_FINISHED
  }

  private record AudioReadResult(byte[] payload, short nextFrameHeader, boolean streamFinished) {
    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      AudioReadResult that = (AudioReadResult) o;
      return nextFrameHeader == that.nextFrameHeader
          && streamFinished == that.streamFinished
          && Arrays.equals(payload, that.payload);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(payload);
      result = 31 * result + Objects.hash(nextFrameHeader, streamFinished);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "AudioReadResult{"
          + "payload="
          + Arrays.toString(payload)
          + ", nextFrameHeader="
          + nextFrameHeader
          + ", streamFinished="
          + streamFinished
          + '}';
    }
  }

  private static void validateAndWriteMagic(DataInputStream in, OutputStream output)
      throws IOException {
    for (byte magicCharacter : magicNumber) {
      if (magicCharacter != in.readByte()) {
        throw new DataFilterException(
            l10n("InvalidFLACStreamTitle"),
            l10n("InvalidFLACStreamTitle"),
            l10n("InvalidFLACStreamMessage"));
      }
    }
    output.write(magicNumber);
  }

  private static FlacMetadataBlock readMetadataBlock(DataInputStream in) throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Reading metadata packet");
    int header = in.readInt();
    byte[] payload = new byte[header & 0x00FFFFFF];
    if (LOG.isDebugEnabled()) LOG.debug("About to read {} bytes", payload.length);
    in.readFully(payload);
    FlacMetadataBlock block = new FlacMetadataBlock(header, payload);
    if (LOG.isDebugEnabled()) LOG.debug("{} packet read", block.getMetadataBlockType());
    return block;
  }

  private static void addFrameHeaderBytes(ArrayList<Byte> buffer, short frameHeader) {
    buffer.add((byte) ((frameHeader & 0xFF00) >>> 8));
    buffer.add((byte) (frameHeader & 0x00FF));
  }

  private static byte[] toByteArray(ArrayList<Byte> buffer) {
    byte[] payload = new byte[buffer.size()];
    for (int i = 0; i < buffer.size(); i++) {
      payload[i] = buffer.get(i);
    }
    return payload;
  }

  private static int readUnsignedByteOrEOF(DataInputStream in) throws IOException {
    try {
      return in.readUnsignedByte();
    } catch (EOFException _) {
      return -1;
    }
  }

  private static AudioReadResult readAudioPayload(DataInputStream in, short frameHeader)
      throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Reading audio packet");
    boolean firstHalfOfSyncHeaderFound = false;
    ArrayList<Byte> buffer = new ArrayList<>();
    int data;
    addFrameHeaderBytes(buffer, frameHeader);
    while (true) {
      data = readUnsignedByteOrEOF(in);
      if (data < 0) {
        // End of stream. If we had seen a leading 0xFF for a potential next
        // frame sync, it was actually just a trailing data byte; preserve it.
        if (firstHalfOfSyncHeaderFound) buffer.add((byte) 0xFF);
        return new AudioReadResult(toByteArray(buffer), (short) 0, true);
      }

      if (!firstHalfOfSyncHeaderFound) {
        if ((data & 0xFF) == 0xFF) {
          firstHalfOfSyncHeaderFound = true;
        } else {
          buffer.add((byte) (data & 0xFF));
        }
        continue; // Single continue in this loop to keep control flow simple
      }

      // FLAC frame sync is 0x3FFE (14 bits): first byte 0xFF, then (second byte & 0xFE) == 0xF8
      if ((data & 0xFE) == 0xF8) {
        // Found next frame header; current frame payload ends before this
        short nextHeader = (short) (0xFF00 | data);
        return new AudioReadResult(toByteArray(buffer), nextHeader, false);
      }
      // False alarm: emit the pending 0xFF and the current byte
      firstHalfOfSyncHeaderFound = false;
      buffer.add((byte) 0xFF);
      buffer.add((byte) (data & 0xFF));
    }
  }

  /**
   * Create a new {@code FlacFilter} instance.
   *
   * <p>The class is stateless and immutable with respect to input/output handling. A single
   * instance can be used to process many different streams sequentially. There is no shared cache
   * or background activity across instances.
   */
  public FlacFilter() {
    // Intentionally empty: the filter is stateless and requires no initialization.
  }

  private static short nextFrameHeaderOrRead(DataInputStream in, short pendingNextFrameHeader)
      throws IOException {
    return (pendingNextFrameHeader != 0)
        ? pendingNextFrameHeader
        : (short) (in.readUnsignedShort() & 0x0000FFFF);
  }

  /**
   * Read, validate, and forward a native FLAC stream from the given input to the provided output.
   *
   * <p>The method assumes the input begins at the first byte of a FLAC file and therefore starts by
   * verifying the four-byte magic number. It then copies metadata blocks and audio frames to the
   * output in the order encountered. Some metadata block types may be sanitized by {@link
   * FlacPacketFilter} (e.g., rewritten to padding with zeroed payloads) to reduce exposure of
   * extraneous data that is not required for playback.
   *
   * <p>The operation is streaming and synchronous. Reads and writes proceed incrementally until
   * end‑of‑stream or an I/O error occurs. The method does not close either stream.
   *
   * <p>Example:
   *
   * <pre>{@code
   * var filter = new FlacFilter();
   * try (var in = Files.newInputStream(path); var out = Files.newOutputStream(outPath)) {
   *   filter.readFilter(in, out, null, Map.of(), null, null);
   * }
   * }</pre>
   *
   * @param input the source byte stream positioned at the beginning of a FLAC file; must remain
   *     readable for the duration of the call and may be unbuffered
   * @param output the destination stream that receives validated bytes; must be writable and is not
   *     closed by this method
   * @param charset an optional character set hint carried by the surrounding framework; this
   *     implementation does not interpret it and may receive {@code null}
   * @param otherParams optional, framework-provided parameters influencing higher-level filtering;
   *     this implementation does not require specific entries and tolerates an empty map
   * @param schemeHostAndPort optional scheme/host/port context for absolute URL resolution in other
   *     filters; not used by this implementation and may be {@code null}
   * @param cb optional callback from the surrounding filtering framework used to report progress or
   *     side effects; this implementation may pass {@code null} through the pipeline
   * @throws IOException if an I/O error occurs while reading from {@code input} or writing to
   *     {@code output}; partial output may already be written when the exception is thrown
   */
  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    FlacPacketFilter parser = new FlacPacketFilter();
    DataInputStream in = new DataInputStream(input);
    State currentState = State.UNINITIALIZED;
    short frameHeader;
    // Cache the next frame header returned by readAudioPayload(). When non-zero,
    // reuse it instead of reading from the stream to avoid dropping two bytes
    // at the start of each subsequent frame.
    short pendingNextFrameHeader = 0;
    validateAndWriteMagic(in, output);

    // Grab packets
    try {
      while (currentState != State.STREAM_FINISHED) {
        CodecPacket packet = null;
        switch (currentState) {
          case UNINITIALIZED -> packet = readMetadataBlock(in);
          case METADATA_FOUND -> {
            frameHeader = nextFrameHeaderOrRead(in, pendingNextFrameHeader);
            AudioReadResult res = readAudioPayload(in, frameHeader);
            // Stash the header for the next frame (0 if stream finished or not found).
            pendingNextFrameHeader = res.nextFrameHeader();
            if (res.streamFinished()) {
              currentState = State.STREAM_FINISHED;
            }
            packet = new FlacFrame(res.payload());
          }
          default -> {
            // No-op: other states are unused here or filtered by the loop guard.
          }
        }
        if (packet instanceof FlacMetadataBlock block && block.isLastMetadataBlock()) {
          currentState = State.METADATA_FOUND;
        }
        packet = parser.parse(packet);
        if (packet != null) output.write(packet.toArray());
      }
    } catch (EOFException _) {
      // Reached end of input; nothing more to write.
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("FLAC." + key);
  }
}
