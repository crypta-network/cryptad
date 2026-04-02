package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.l10n.NodeL10n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters and validates WebP images within a RIFF container.
 *
 * <p>This filter parses WebP chunks and either passes through valid, supported data (e.g., VP8
 * lossy image data, optional uncompressed alpha) or converts unsupported/irrelevant auxiliary
 * chunks into {@code JUNK}. The implementation focuses on minimally altering the original byte
 * stream while enforcing structural constraints defined by the WebP container format. Typical usage
 * is indirect via the {@link RIFFFilter} framework: the caller feeds bytes to the parent reader,
 * and this filter is invoked per chunk to validate, rewrite headers when necessary, and stream data
 * to the output.
 *
 * <p>Behavioral highlights include:
 *
 * <ul>
 *   <li>Validation of chunk ordering and coherence (e.g., VP8/VP8L/ALPH/ANIM/ANMF rules).
 *   <li>Canvas size checks for animated frames and upper bounds on image dimensions.
 *   <li>Stripping of ICCP/EXIF/XMP by rewriting those blocks as {@code JUNK} to avoid leakage of
 *       metadata while preserving overall container layout.
 * </ul>
 *
 * <p>The filter is stateless across files but maintains a per-file parsing context to enforce
 * invariants. It performs I/O sequentially and does not retain large buffers; it is therefore
 * suitable for streaming pipelines. No synchronization is performed; instances are not thread-safe
 * and should be used by a single thread per stream.
 *
 * @see RIFFFilter
 */
public class WebPFilter extends RIFFFilter {
  private static final Logger LOG = LoggerFactory.getLogger(WebPFilter.class);

  // Derived from mux_type.h in libwebp
  private static final int ANIMATION_FLAG = 0x00000002;
  private static final int ALPHA_FLAG = 0x00000010;
  private static final int ICCP_FLAG = 0x00000020;
  private static final int EXIF_FLAG = 0x00000008;
  private static final int XMP_FLAG = 0x00000004;
  private static final int ALL_VALID_FLAGS = 0x0000003e;
  private static final String L10N_INVALID_TITLE = "invalidTitle";

  /**
   * Creates a new WebP filter suitable for use with the {@link RIFFFilter} processing pipeline.
   *
   * <p>The constructor performs no I/O and allocates no large buffers. Instances are lightweight
   * and may be created per stream. The filter keeps all state in a per-image context object created
   * via {@link #createContext()} and passed back to each {@link #readFilterChunk(byte[], int,
   * Object, ReadFilterContext)} invocation. Callers typically construct the filter once and then
   * delegate chunk processing to it while streaming from an input to an output.
   */
  public WebPFilter() {
    // Intentionally empty: construction is lightweight and stateless.
    // All per-stream state is tracked in the context created by createContext().
  }

  /**
   * Returns the RIFF chunk magic that identifies a WebP container.
   *
   * <p>The returned array is a constant four-byte ASCII sequence {@code "WEBP"}. Callers do not own
   * the returned object and must not modify its contents. The value is used by the {@link
   * RIFFFilter} framework to match and route files to this filter.
   *
   * @return a four-byte array with the ASCII characters {@code 'W','E','B','P'} identifying WebP
   *     files
   */
  @Override
  protected byte[] getChunkMagicNumber() {
    return new byte[] {'W', 'E', 'B', 'P'};
  }

  private static final class WebPFilterContext {
    int vp8xFlags = 0;
    boolean hasVP8X = false;
    boolean hasANIM = false;
    boolean hasANMF = false;
    boolean hasALPH = false;
    boolean hasVP8 = false;
    boolean hasVP8L = false;
    int width = 0;
    int height = 0;
  }

  /**
   * Creates a new per-stream parsing context.
   *
   * <p>The context carries state derived from previously seen chunks (for example flags from the
   * {@code VP8X} header, canvas dimensions, and the presence of animation blocks). It is opaque to
   * callers and is passed back to subsequent invocations of this filter while processing a single
   * file.
   *
   * @return an opaque, mutable context object to be supplied on subsequent callbacks and not shared
   *     across concurrent streams
   */
  @Override
  protected Object createContext() {
    // A new per-image parsing context is created for each stream processed by this filter.
    return new WebPFilterContext();
  }

  /**
   * Validates and processes a single WebP RIFF chunk, writing a sanitized representation downstream
   * when acceptable.
   *
   * <p>This method implements the core chunk-by-chunk logic. Depending on the chunk type it may
   * pass the data through verbatim, adjust headers, or translate unsupported/unsafe blocks into
   * {@code JUNK} while maintaining container alignment. Certain combinations and orders are
   * rejected; in those cases a {@code DataFilterException} is thrown to stop processing.
   *
   * @param id a 4-byte identifier denoting the chunk type (e.g., {@code VP8 }, {@code ANMF}); the
   *     array must contain exactly four bytes and is not modified by the implementation
   * @param size the size in bytes of the chunk payload preceding any RIFF padding; negative values
   *     are invalid; odd sizes imply a one-byte padding follows
   * @param context the per-file context previously created by {@link #createContext()}; must be the
   *     same instance across callbacks for a given stream; never {@code null}
   * @param params I/O bridge that supplies a {@code DataInputStream} and {@code DataOutputStream}
   *     used to read from the source and write the filtered output; streams must be positioned at
   *     the start of the chunk payload on entry
   * @throws IOException if an underlying I/O error occurs while reading or writing the chunk data;
   *     semantic validation failures surface as {@code DataFilterException}
   */
  @Override
  protected void readFilterChunk(byte[] id, int size, Object context, ReadFilterContext params)
      throws IOException {
    WebPFilterContext ctx = (WebPFilterContext) context;
    if (isChunk(id, 'V', 'P', '8', ' ')) {
      handleVP8(id, size, ctx, params);
    } else if (isChunk(id, 'V', 'P', '8', 'L')) {
      handleVP8L(ctx);
    } else if (isChunk(id, 'A', 'L', 'P', 'H')) {
      handleALPH(id, size, ctx, params);
    } else if (isChunk(id, 'A', 'N', 'I', 'M')) {
      handleANIM(id, size, ctx, params);
    } else if (isChunk(id, 'A', 'N', 'M', 'F')) {
      handleANMF(id, size, ctx, params);
    } else if (isChunk(id, 'V', 'P', '8', 'X')) {
      handleVP8X(id, size, ctx, params);
    } else if (isChunk(id, 'I', 'C', 'C', 'P')) {
      handleICCP(size, params);
    } else if (isChunk(id, 'E', 'X', 'I', 'F')) {
      handleEXIF(size, params);
    } else if (isChunk(id, 'X', 'M', 'P', ' ')) {
      handleXMP(size, params);
    } else {
      handleUnknown(size, params);
    }
  }

  /**
   * Performs end-of-file validation after the final chunk is processed.
   *
   * <p>The check ensures the stream contained at least one decodable image block (lossy VP8,
   * lossless VP8L, or an animated frame). If none were encountered, the input is considered invalid
   * and the filter reports a failure.
   *
   * @param context the per-file parsing context created by {@link #createContext()}; must not be
   *     {@code null}
   * @throws DataFilterException if no suitable image payload was found in the processed stream, or
   *     when accumulated context indicates an invalid file structure
   */
  @Override
  protected void eofCheck(Object context) throws DataFilterException {
    WebPFilterContext ctx = (WebPFilterContext) context;
    if (!ctx.hasVP8 && !ctx.hasVP8L && !ctx.hasANMF) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "No image chunk in the WebP file is found");
    }
  }

  private void filterVP8Block(byte[] id, int size, DataInputStream input, DataOutputStream output)
      throws IOException {
    // VP8 Lossy format: RFC 6386
    // Most WebP files just contain a single chunk of this kind
    if (size < 10) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "The VP8 chunk was too small to be valid");
    }
    output.write(id);
    if (LOG.isTraceEnabled()) LOG.trace("Passing through WebP VP8 block with {} bytes.", size);
    VP8PacketFilter vp8Filter = new VP8PacketFilter(true);
    // Just read 6 bytes of the header to validate
    byte[] buf = new byte[6];
    input.readFully(buf);
    vp8Filter.parse(buf, size);
    writeLittleEndianInt(output, size);
    output.write(buf);
    passthroughBytes(input, output, size - buf.length);
    if ((size & 1) != 0) { // Add padding if necessary
      output.writeByte(input.readByte());
    }
  }

  private void filterALPHBlock(byte[] id, int size, DataInputStream input, DataOutputStream output)
      throws IOException {
    if (size == 0) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE), l10n(L10N_INVALID_TITLE), "Unexpected empty ALPH chunk");
    }
    // Alpha channel
    int flags = input.readUnsignedByte();
    if ((flags & 2) != 0) {
      // Compression is not uncompressed
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "WebP alpha channel contains reserved bits");
    }
    if ((flags & 0xc0) != 0) {
      // Compression is not uncompressed.
      // Note: CVE-2023-4863 affects lossless paths; these are treated as unsupported.
      throw new DataFilterException(
          l10n("alphUnsupportedTitle"), l10n("alphUnsupportedTitle"), l10n("alphUnsupported"));
    }
    output.write(id);
    if (LOG.isTraceEnabled()) LOG.trace("Passing through WebP ALPH block with {} bytes.", size);
    writeLittleEndianInt(output, size);
    output.writeByte(flags);
    passthroughBytes(input, output, size - 1);
    if ((size & 1) != 0) { // Add padding if necessary
      output.writeByte(input.readByte());
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("WebPFilter." + key);
  }

  private static boolean isChunk(byte[] id, char c0, char c1, char c2, char c3) {
    return id[0] == c0 && id[1] == c1 && id[2] == c2 && id[3] == c3;
  }

  private void handleVP8(byte[] id, int size, WebPFilterContext ctx, ReadFilterContext params)
      throws IOException {
    if (ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected VP8 chunk was encountered");
    }
    ctx.hasVP8 = true;
    filterVP8Block(id, size, params.input, params.output);
  }

  private void handleVP8L(WebPFilterContext ctx) throws IOException {
    if (ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM || ctx.hasALPH) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected VP8L chunk was encountered");
    }
    ctx.hasVP8L = true;
    throw new DataFilterException(
        l10n("losslessUnsupportedTitle"),
        l10n("losslessUnsupportedTitle"),
        l10n("losslessUnsupported"));
  }

  private void handleALPH(byte[] id, int size, WebPFilterContext ctx, ReadFilterContext params)
      throws IOException {
    if (ctx.hasVP8L
        || ctx.hasANIM
        || ctx.hasALPH
        || !ctx.hasVP8X
        || ((ctx.vp8xFlags & ALPHA_FLAG) == 0)) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected ALPH chunk was encountered");
    }
    ctx.hasALPH = true;
    filterALPHBlock(id, size, params.input, params.output);
  }

  private void handleANIM(byte[] id, int size, WebPFilterContext ctx, ReadFilterContext params)
      throws IOException {
    if ((ctx.vp8xFlags & ANIMATION_FLAG) == 0 || ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected ANIM chunk was encountered");
    }
    ctx.hasANIM = true;
    params.output.write(id);
    writeLittleEndianInt(params.output, size);
    if (size != 6) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "ANIM chunk size is too small or too big");
    }
    passthroughBytes(params.input, params.output, size);
  }

  private void handleANMF(byte[] id, int size, WebPFilterContext ctx, ReadFilterContext params)
      throws IOException {
    validateAnmfPreconditions(ctx, size);
    ctx.hasANMF = true;
    params.output.write(id);
    writeLittleEndianInt(params.output, size);
    int[] anmfHeader = readAnmfHeader(params);
    validateAnmfCanvas(ctx, anmfHeader);
    writeAnmfHeader(params, anmfHeader);
    processAnmfSubchunks(params, size - 16);
  }

  private void validateAnmfPreconditions(WebPFilterContext ctx, int size) throws IOException {
    if ((ctx.vp8xFlags & ANIMATION_FLAG) == 0 || ctx.hasVP8 || ctx.hasVP8L || !ctx.hasANIM) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected ANMF chunk was encountered");
    }
    if ((size < 16 + 8) || (size % 2 != 0)) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "ANMF chunk size is invalid (size=" + size + ")");
    }
  }

  private static int[] readAnmfHeader(ReadFilterContext params) throws IOException {
    int[] h = new int[16];
    for (int i = 0; i < 16; i++) {
      h[i] = params.input.readUnsignedByte();
    }
    return h;
  }

  private static void writeAnmfHeader(ReadFilterContext params, int[] h) throws IOException {
    for (int i = 0; i < 16; i++) {
      params.output.writeByte(h[i]);
    }
  }

  private void validateAnmfCanvas(WebPFilterContext ctx, int[] h) throws IOException {
    int frameX = h[0] | (h[1] << 8) | (h[2] << 16);
    int frameY = h[3] | (h[4] << 8) | (h[5] << 16);
    int frameWidth = (h[6] | (h[7] << 8) | (h[8] << 16)) + 1;
    int frameHeight = (h[9] | (h[10] << 8) | (h[11] << 16)) + 1;
    int frameFlags = h[15];
    if ((frameX + frameWidth > ctx.width) || (frameY + frameHeight > ctx.height)) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "ANMF canvas size extends beyond image size");
    }
    if ((frameFlags & 0xfc) != 0) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE), l10n(L10N_INVALID_TITLE), "ANMF block contains reserved flag");
    }
  }

  private void processAnmfSubchunks(ReadFilterContext params, int remainingSize)
      throws IOException {
    AnmfState st = new AnmfState();
    byte[] blockID = new byte[4];
    while (remainingSize >= 8) {
      params.input.readFully(blockID);
      int blockSize = readLittleEndianInt(params.input);
      handleAnmfSingleSubchunk(params, blockID, blockSize, st);
      remainingSize -= (blockSize + blockSize % 2) + 8;
    }
    if (remainingSize != 0) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected data remaining at the end of ANMF chunk");
    }
  }

  private static final class AnmfState {
    boolean hasVP8;
    boolean hasALPH;
  }

  private void handleAnmfSingleSubchunk(
      ReadFilterContext params, byte[] blockID, int blockSize, AnmfState st) throws IOException {
    if (isChunk(blockID, 'V', 'P', '8', ' ')) {
      if (st.hasVP8) {
        throw new DataFilterException(
            l10n(L10N_INVALID_TITLE),
            l10n(L10N_INVALID_TITLE),
            "Unexpected VP8 chunk was encountered inside ANMF block");
      } else {
        st.hasVP8 = true;
      }
      filterVP8Block(blockID, blockSize, params.input, params.output);
      return;
    }
    if (isChunk(blockID, 'V', 'P', '8', 'L')) {
      throw new DataFilterException(
          l10n("animUnsupportedTitle"), l10n("animUnsupportedTitle"), l10n("animUnsupported"));
    }
    if (isChunk(blockID, 'A', 'L', 'P', 'H')) {
      if (st.hasALPH) {
        throw new DataFilterException(
            l10n(L10N_INVALID_TITLE),
            l10n(L10N_INVALID_TITLE),
            "Unexpected ALPH chunk was encountered inside ANMF block");
      } else {
        st.hasALPH = true;
      }
      filterALPHBlock(blockID, blockSize, params.input, params.output);
      return;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "WebP image has Unknown block with {} bytes within ANMF chunk converted into JUNK chunk.",
          blockSize);
    writeJunkChunk(params.input, params.output, blockSize);
  }

  private void handleVP8X(byte[] id, int size, WebPFilterContext ctx, ReadFilterContext params)
      throws IOException {
    if (ctx.hasVP8 || ctx.hasVP8L || ctx.hasANIM || ctx.hasVP8X) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "Unexpected VP8X chunk was encountered");
    }
    ctx.vp8xFlags = readLittleEndianInt(params.input);
    if ((ctx.vp8xFlags & ~ALL_VALID_FLAGS) != 0) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE), l10n(L10N_INVALID_TITLE), "VP8X header has reserved flags");
    }
    if (size != 10) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE),
          l10n(L10N_INVALID_TITLE),
          "VP8X header is too small or too big");
    }
    params.output.write(id);
    writeLittleEndianInt(params.output, size);
    ctx.vp8xFlags &= ~(XMP_FLAG | EXIF_FLAG | ICCP_FLAG);
    writeLittleEndianInt(params.output, ctx.vp8xFlags);
    ctx.hasVP8X = true;
    int[] widthHeight = new int[6];
    for (int i = 0; i < 6; i++) {
      widthHeight[i] = params.input.readUnsignedByte();
    }
    ctx.width = widthHeight[0] | widthHeight[1] << 8 | widthHeight[2] << 16;
    ctx.height = widthHeight[3] | widthHeight[4] << 8 | widthHeight[5] << 16;
    ctx.width++;
    ctx.height++;
    if (ctx.width > 16384 || ctx.height > 16384) {
      throw new DataFilterException(
          l10n(L10N_INVALID_TITLE), l10n(L10N_INVALID_TITLE), "WebP image size is too big");
    }
    for (int i = 0; i < 6; i++) {
      params.output.writeByte(widthHeight[i]);
    }
  }

  private void handleICCP(int size, ReadFilterContext params) throws IOException {
    if (LOG.isDebugEnabled())
      LOG.debug("WebP image has ICCP block with {} bytes converted into JUNK chunk.", size);
    writeJunkChunk(params.input, params.output, size);
  }

  private void handleEXIF(int size, ReadFilterContext params) throws IOException {
    if (LOG.isDebugEnabled())
      LOG.debug("WebP image has EXIF block with {} bytes converted into JUNK chunk.", size);
    writeJunkChunk(params.input, params.output, size);
  }

  private void handleXMP(int size, ReadFilterContext params) throws IOException {
    if (LOG.isDebugEnabled())
      LOG.debug("WebP image has XMP block with {} bytes converted into JUNK chunk.", size);
    writeJunkChunk(params.input, params.output, size);
  }

  private void handleUnknown(int size, ReadFilterContext params) throws IOException {
    if (LOG.isDebugEnabled())
      LOG.debug("WebP image has Unknown block with {} bytes converted into JUNK chunk.", size);
    writeJunkChunk(params.input, params.output, size);
  }
}
