package network.crypta.client.filter;

import java.io.IOException;
import network.crypta.l10n.NodeL10n;

/**
 * RIFF/WAVE filter that validates and sanitizes WAV containers while preserving
 * byte‑for‑byte‑compatible structure.
 *
 * <p>This implementation specializes {@link RIFFFilter} for the {@code WAVE} form and enforces a
 * conservative subset of the format: it requires a single {@code fmt } chunk with a supported
 * encoding (PCM, IEEE float, A‑law, or mu‑law) and a {@code data} chunk containing the audio
 * payload. The filter passes through known‑safe chunks, emits zero‑filled {@code JUNK} blocks for
 * unknown or oversized sections, and ensures RIFF alignment by padding to even byte boundaries
 * where applicable. Ordering rules are kept strict: {@code fmt } must be seen before audio data and
 * both must be present by end of stream.
 *
 * <p>Use this filter when WAV files are accepted from untrusted sources and must be validated
 * before distribution. Typical call paths rely on the streaming API of {@link RIFFFilter}: the
 * caller provides input and output streams, the filter performs minimal in‑place transformations
 * while reading, and a final consistency check runs in {@link #eofCheck(Object)}. The instance is
 * stateless and reusable across requests; per‑parse state is carried by an internal context.
 *
 * <ul>
 *   <li>Thread‑safety: instances are thread‑safe; do not share a single parse context.
 *   <li>Mutability: no mutable instance fields; state lives only in a per‑parse context.
 *   <li>Notable validations: supported encodings only; A‑law/μ‑law require 8 bits per sample; odd
 *       chunk sizes are padded; unknown chunks are preserved structurally as {@code JUNK}.
 * </ul>
 *
 * @see RIFFFilter
 */
public class WAVFilter extends RIFFFilter {
  /**
   * Creates a new {@code WAVFilter}.
   *
   * <p>The filter is stateless and reusable; per‑parse details are kept in a short‑lived context
   * allocated for each call path. Construction performs no I/O and has no side effects.
   */
  public WAVFilter() {
    // Intentionally empty: the filter is stateless and requires no initialization.
  }

  // RFC 2361 / common header sizes
  private static final int FMT_SIZE_BASIC = 16; // fmt header without cbSize field
  private static final int FMT_SIZE_CBSIZE = 18; // fmt header with cbSize = 0
  private static final int FMT_SIZE_CBSIZE_EXTENSION = 40; // fmt header with cbSize and extensions

  // Supported WAVE format tags
  private static final int WAVE_FORMAT_PCM = 1;
  private static final int WAVE_FORMAT_IEEE_FLOAT = 3;
  private static final int WAVE_FORMAT_ALAW = 6;
  private static final int WAVE_FORMAT_MULAW = 7;

  private static final String KEY_INVALID_TITLE = "invalidTitle";

  /**
   * Returns the FourCC that identifies the RIFF form handled by this filter.
   *
   * <p>For WAV files the expected form type is {@code WAVE}. The returned array contains exactly
   * four ASCII bytes and must not be mutated by callers.
   *
   * @return a four‑byte array with the characters {@code 'W','A','V','E'} representing the RIFF
   *     form
   */
  @Override
  protected byte[] getChunkMagicNumber() {
    return new byte[] {'W', 'A', 'V', 'E'};
  }

  private static final class WAVFilterContext {
    boolean hasfmt = false;
    boolean hasdata = false;
    int nSamplesPerSec = 0;
    int nChannels = 0;
    int nBlockAlign = 0;
    int wBitsPerSample = 0;
    int format = 0;
  }

  /**
   * Creates a fresh per‑parse context used to track WAV‑specific validation state.
   *
   * <p>The context records whether mandatory chunks were encountered and caches key header fields
   * (sample rate, channels, alignment, and format tag) for later checks. A new instance is returned
   * for every invocation of the streaming read method in the base class.
   *
   * @return an opaque context object used only by this filter and later consumed by {@link
   *     #eofCheck(Object)}
   */
  @Override
  protected Object createContext() {
    return new WAVFilterContext();
  }

  /**
   * Processes a single WAV chunk and mirrors or sanitizes it to the output stream.
   *
   * <p>Recognized chunks include:
   *
   * <ul>
   *   <li>{@code fmt }: validates header length, supported encoding (PCM, IEEE float, A‑law,
   *       mu‑law), and basic field ranges; passes through the header structure.
   *   <li>{@code data}: streams audio payload verbatim and preserves RIFF padding for odd sizes.
   *   <li>{@code fact}: when exactly 4 bytes, passes through; otherwise discards via {@code JUNK}.
   *   <li>Any other chunk: discarded via a size‑matched {@code JUNK} block to keep structure.
   * </ul>
   *
   * <p>The context is updated to record whether {@code fmt } and {@code data} were observed. The
   * method must consume exactly {@code size} bytes from the input stream (plus a padding byte when
   * {@code size} is odd) and may write a normalized representation to the output.
   *
   * @param id four‑character chunk identifier as read from the stream; the buffer is not reused by
   *     the caller and may be written to by the implementation
   * @param size payload size in bytes, excluding the 8‑byte chunk header; must be respected when
   *     reading from the input stream
   * @param context internal state previously created by {@link #createContext()} and used to carry
   *     validation results across chunks
   * @param params helpers and caller‑provided options aggregated by {@link
   *     RIFFFilter.ReadFilterContext}; contains input/output streams, charset, and callback
   * @throws IOException if reading or writing fails, or when validation triggers a {@link
   *     DataFilterException}
   */
  @Override
  protected void readFilterChunk(byte[] id, int size, Object context, ReadFilterContext params)
      throws IOException {
    WAVFilterContext ctx = (WAVFilterContext) context;
    if (isFourCC(id, 'f', 'm', 't', ' ')) {
      handleFmtChunk(size, ctx, params, id);
      return;
    }
    if (!ctx.hasfmt) {
      throw new DataFilterException(
          l10nInvalidTitle(),
          l10nInvalidTitle(),
          "Unexpected header chunk was encountered, instead of fmt chunk");
    }
    if (isFourCC(id, 'd', 'a', 't', 'a')) {
      handleDataChunk(size, ctx, params, id);
    } else if (isFourCC(id, 'f', 'a', 'c', 't')) {
      handleFactChunk(size, params, id);
    } else {
      // Unknown block
      writeJunkChunk(params.input, params.output, size);
    }
  }

  /**
   * Verifies that the minimal set of required chunks were encountered during parsing.
   *
   * <p>The WAV container must include exactly one {@code fmt } chunk and at least one {@code data}
   * chunk. If either is missing by end of file, a {@link DataFilterException} is raised to signal
   * invalid input. No I/O occurs in this method.
   *
   * @param context the per‑parse context created in {@link #createContext()} and updated during
   *     chunk processing; expected to be a non‑null instance of the internal context type
   * @throws DataFilterException if either the {@code fmt } or {@code data} chunk was not seen
   */
  @Override
  protected void eofCheck(Object context) throws DataFilterException {
    WAVFilterContext ctx = (WAVFilterContext) context;
    if (!ctx.hasfmt || !ctx.hasdata) {
      throw new DataFilterException(
          l10nInvalidTitle(), l10nInvalidTitle(), "WAV file is missing fmt chunk or data chunk");
    }
  }

  private static String l10nInvalidTitle() {
    return NodeL10n.getBase().getString("WAVFilter." + KEY_INVALID_TITLE);
  }

  private static boolean isFourCC(byte[] id, char a, char b, char c, char d) {
    return id[0] == (byte) a && id[1] == (byte) b && id[2] == (byte) c && id[3] == (byte) d;
  }

  private void handleFmtChunk(int size, WAVFilterContext ctx, ReadFilterContext params, byte[] id)
      throws IOException {
    if (ctx.hasfmt) {
      throw new DataFilterException(
          l10nInvalidTitle(), l10nInvalidTitle(), "Unexpected fmt chunk was encountered");
    }
    // Header sizes (https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html)
    if (size != FMT_SIZE_BASIC && size != FMT_SIZE_CBSIZE && size != FMT_SIZE_CBSIZE_EXTENSION) {
      throw new DataFilterException(
          l10nInvalidTitle(), l10nInvalidTitle(), "fmt chunk size is invalid");
    }
    ctx.format = Short.reverseBytes(params.input.readShort());
    if (ctx.format != WAVE_FORMAT_PCM
        && ctx.format != WAVE_FORMAT_IEEE_FLOAT
        && ctx.format != WAVE_FORMAT_ALAW
        && ctx.format != WAVE_FORMAT_MULAW) {
      throw new DataFilterException(
          l10nInvalidTitle(), l10nInvalidTitle(), "WAV file uses a not yet supported format");
    }
    ctx.nChannels = Short.reverseBytes(params.input.readShort());
    params.output.write(id);
    writeLittleEndianInt(params.output, size);
    params.output.writeInt(
        (Short.reverseBytes((short) ctx.format) << 16) | Short.reverseBytes((short) ctx.nChannels));
    ctx.nSamplesPerSec = readLittleEndianInt(params.input);
    writeLittleEndianInt(params.output, ctx.nSamplesPerSec);
    int nAvgBytesPerSec = readLittleEndianInt(params.input);
    writeLittleEndianInt(params.output, nAvgBytesPerSec);
    ctx.nBlockAlign = Short.reverseBytes(params.input.readShort());
    ctx.wBitsPerSample = Short.reverseBytes(params.input.readShort());
    params.output.writeInt(
        (Short.reverseBytes((short) ctx.nBlockAlign) << 16)
            | Short.reverseBytes((short) ctx.wBitsPerSample));
    ctx.hasfmt = true;

    if (size > FMT_SIZE_BASIC) {
      short cbSize = Short.reverseBytes(params.input.readShort());
      if (cbSize + FMT_SIZE_CBSIZE != size) {
        throw new DataFilterException(
            l10nInvalidTitle(), l10nInvalidTitle(), "fmt chunk size is invalid");
      }
      params.output.writeShort(Short.reverseBytes(cbSize));
    }
    if (size > FMT_SIZE_CBSIZE) {
      // wValidBitsPerSample, dwChannelMask, and SubFormat GUID
      passthroughBytes(params.input, params.output, FMT_SIZE_CBSIZE_EXTENSION - FMT_SIZE_CBSIZE);
    }
    // Further checks
    if ((ctx.format == WAVE_FORMAT_ALAW || ctx.format == WAVE_FORMAT_MULAW)
        && ctx.wBitsPerSample != 8) {
      // These formats are 8-bit
      throw new DataFilterException(
          l10nInvalidTitle(), l10nInvalidTitle(), "Unexpected bits per sample value");
    }
  }

  private void handleDataChunk(int size, WAVFilterContext ctx, ReadFilterContext params, byte[] id)
      throws IOException {
    // audio data
    params.output.write(id);
    writeLittleEndianInt(params.output, size);
    passthroughBytes(params.input, params.output, size);
    if ((size & 1) != 0) { // Add padding if necessary
      params.output.writeByte(params.input.readByte());
    }
    ctx.hasdata = true;
  }

  private void handleFactChunk(int size, ReadFilterContext params, byte[] id) throws IOException {
    if (size != 4) {
      // It should be 4 bytes, so don't know what to do with the data other than discarding it.
      writeJunkChunk(params.input, params.output, size);
    } else {
      // Just dwSampleLength (Number of samples) here, pass through
      params.output.write(id);
      writeLittleEndianInt(params.output, size);
      passthroughBytes(params.input, params.output, size);
    }
  }
}
