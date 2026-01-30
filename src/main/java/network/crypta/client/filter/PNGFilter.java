package network.crypta.client.filter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.zip.CRC32;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters PNG images to a safe, standards‑conforming byte stream.
 *
 * <p>This filter parses the PNG container, validates chunk structure and ordering, and forwards
 * only content that is known to be safe for delivery to user agents. It performs a positive
 * (allow‑list) validation of well‑formed chunks and, when configured by the caller, can remove
 * human‑readable metadata such as {@code tEXt}/{@code iTXt}/{@code zTXt} as well as the optional
 * {@code tIME} timestamp. The filter may also verify per‑chunk CRCs and drop chunks with invalid
 * checksums to prevent partially corrupted or deliberately malformed data from reaching clients.
 *
 * <p>The implementation enforces core PNG invariants, including a single {@code IHDR} at the start
 * of the stream, zero or more consecutive {@code IDAT} chunks, and a single {@code IEND} at the
 * end. Chunk ordering rules are respected (for example, {@code PLTE} must precede {@code IDAT}),
 * and unknown chunks are treated conservatively: they are skipped unless explicitly recognized as
 * harmless. As a result, callers can forward the output to web browsers or other decoders with a
 * high degree of confidence that no active content or parser confusion will be triggered.
 *
 * <p>Thread‑safety: instances are immutable after construction and may be reused across threads.
 * The filter operates in a streaming manner and does not assume that {@link InputStream#available}
 * signals end‑of‑stream. It writes only validated bytes to the destination and raises a descriptive
 * {@code IOException} on structural errors.
 *
 * <ul>
 *   <li>Validates header and critical chunk order; rejects invalid combinations.
 *   <li>Optionally strips textual metadata and timestamps when policy requires.
 *   <li>Optionally verifies CRCs and drops chunks with mismatches.
 *   <li>Skips unknown or unexpected chunks to reduce attack surface.
 * </ul>
 *
 * @see ContentDataFilter
 * @see <a href="https://www.w3.org/TR/png/">PNG Specification</a>
 */
public class PNGFilter implements ContentDataFilter {
  private static final Logger LOG = LoggerFactory.getLogger(PNGFilter.class);
  private static final String ERROR_MDCV_REQUIRES_CICP = "mDCV requires cICP";

  private final boolean deleteText;
  private final boolean deleteTimestamp;
  private final boolean checkCRCs;
  static final byte[] PNG_HEADER = {
    (byte) 137, (byte) 80, (byte) 78, (byte) 71, (byte) 13, (byte) 10, (byte) 26, (byte) 10
  };
  // https://www.w3.org/TR/png/#5ChunkOrdering, these chunks must appear before PLTE and IDAT
  static final String[] HARMLESS_CHUNK_TYPES_BEFORE_PLTE = {
    // http://www.w3.org/TR/PNG/
    "cHRM",
    "iCCP", // Embedded ICC profile: could this conceivably cause a web lookup?
    "sBIT", // https://www.w3.org/TR/png/#11sBIT
    "gAMA", // https://www.w3.org/TR/png/#11gAMA
    "cLLI", // https://www.w3.org/TR/png/#cLLI-chunk
    "sRGB"
  };
  static final String[] HARMLESS_CHUNK_TYPES_OTHER_ORDER = {
    "pHYs",
    "sPLT",
    "tRNS",
    "bKGD",
    "hIST",
    // APNG chunks (Firefox 3 will support APNG)
    // http://wiki.mozilla.org/APNG_Specification
    "acTL",
    "fcTL",
    "fdAT"
    // MNG isn't supported by Firefox and IE because of lack of market demand. Big surprise
    // given nobody supports it! It is supported by Konqueror though. Complex standard,
    // not worth it for the time being.

    // This might be a useful source of info too (e.g. on private chunks):
    // http://fresh.t-systems-sfr.com/unix/privat/pngcheck-2.3.0.tar.gz:a/pngcheck-2.3.0/pngcheck.c
  };

  PNGFilter(boolean deleteText, boolean deleteTimestamp, boolean checkCRCs) {
    this.deleteText = deleteText;
    this.deleteTimestamp = deleteTimestamp;
    this.checkCRCs = checkCRCs;
  }

  /**
   * Reads a PNG stream, validates its structure, and writes a sanitized PNG to {@code output}.
   *
   * <p>The method consumes exactly one PNG from {@code input}. It preserves the PNG signature and
   * all validated, policy‑permitted chunks while omitting or skipping chunks that violate ordering
   * or fail CRC checks when CRC verification is enabled. When configured by the constructor, it can
   * remove textual metadata chunks and the optional {@code tIME} chunk. The operation is idempotent
   * for already well‑formed inputs: safe files pass through unchanged apart from the optional
   * removals.
   *
   * <pre>{@code
   * // Example: filter a PNG in a streaming pipeline
   * var filter = new PNGFilter(true, true, true);
   * filter.readFilter(inStream, outStream, null, Map.of(), null, null);
   * }</pre>
   *
   * @param input the source PNG byte stream to validate and sanitize; may be network‑backed and is
   *     read sequentially without relying on {@code available()} for termination; must begin with a
   *     valid 8‑byte PNG signature.
   * @param output the destination for the filtered PNG; receives only validated bytes; the method
   *     flushes on completion but does not close the stream.
   * @param charset ignored for PNG (a binary format); callers may pass {@code null} or any value;
   *     kept for {@link ContentDataFilter} API uniformity.
   * @param otherParams optional media‑type parameters; unused by this implementation but accepted
   *     for interface compatibility; callers may pass an empty map.
   * @param schemeHostAndPort optional externally visible endpoint (e.g., {@code http://host:port});
   *     unused by this filter; non‑null values are safely ignored.
   * @param cb optional callback for structure‑specific decisions; not used for PNG; callers may
   *     pass {@code null}.
   * @throws IOException if an I/O error occurs while reading or writing, or if validation fails and
   *     no safe output can be produced. Validation failures are reported as a descriptive {@code
   *     DataFilterException}.
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
    readFilter(input, output, deleteText, deleteTimestamp, checkCRCs);
    output.flush();
  }

  private void readFilter(
      InputStream input,
      OutputStream output,
      boolean deleteText,
      boolean deleteTimestamp,
      boolean checkCRCs)
      throws IOException {
    DataInputStream dis;
    final PngState state = new PngState();
    try {
      dis = new DataInputStream(input);
      validateHeader(dis);

      // Emit header
      output.write(PNG_HEADER);
      if (LOG.isDebugEnabled()) LOG.debug("Writing the PNG header to the output bucket");

      processChunks(dis, output, checkCRCs, deleteText, deleteTimestamp, state);

      if (!state.hasSeenIEND) throwError("Missing IEND", "Missing IEND");
      if (!state.hasSeenIHDR) throwError("Missing IHDR", "Missing IHDR");
    } catch (ArrayIndexOutOfBoundsException _) {
      throwError(
          "ArrayIndexOutOfBoundsException while filtering",
          "ArrayIndexOutOfBoundsException while filtering");
    } catch (NegativeArraySizeException _) {
      throwError(
          "NegativeArraySizeException while filtering",
          "NegativeArraySizeException while filtering");
    } catch (EOFException _) {
      if (state.hasSeenIEND && state.hasSeenIHDR) return;
      throwError("EOF Exception while filtering", "EOF Exception while filtering");
    }
  }

  private void validateHeader(DataInputStream dis) throws IOException {
    byte[] headerCheck = new byte[PNG_HEADER.length];
    dis.readFully(headerCheck);
    if (!Arrays.equals(headerCheck, PNG_HEADER)) {
      String message = l10n("invalidHeader");
      String title = l10n("invalidHeaderTitle");
      throw new DataFilterException(title, title, message);
    }
  }

  private void processChunks(
      DataInputStream dis,
      OutputStream output,
      boolean checkCRCs,
      boolean deleteText,
      boolean deleteTimestamp,
      PngState state)
      throws IOException {
    long offset = PNG_HEADER.length;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    while (!state.hasSeenIEND) {
      baos.reset();
      ChunkData chunk = readChunk(dis);
      offset += 4L + 4L + chunk.length + 4L; // len + type + data + crc
      writeChunkToBuffer(dos, chunk, offset);

      Handling h = determineHandling(state, chunk, deleteText, deleteTimestamp, checkCRCs);
      if (h.write && output != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Writing {} ({}) to the output bucket", chunk.type, baos.size());
        baos.writeTo(output);
        baos.flush();
      }
      state.lastChunkType = chunk.type;
    }
  }

  private static boolean isTextChunk(String type) {
    return "text".equalsIgnoreCase(type)
        || "itxt".equalsIgnoreCase(type)
        || "ztxt".equalsIgnoreCase(type);
  }

  private boolean handleHarmlessChunks(PngState state, String type) throws DataFilterException {
    for (String s : HARMLESS_CHUNK_TYPES_BEFORE_PLTE) {
      if (s.equals(type)) {
        if (!state.hasSeenPLTE && !state.hasSeenIDAT) {
          return true;
        } else {
          throwError(
              "The chunk appeared in an unexpected order!",
              "The chunk \"" + type + "\" appeared in an unexpected order!");
        }
      }
    }
    for (String s : HARMLESS_CHUNK_TYPES_OTHER_ORDER) {
      if (s.equals(type)) {
        return true;
      }
    }
    return false;
  }

  private boolean handleKnownChunkTypes(
      PngState state, String type, int length, byte[] data, boolean skip)
      throws DataFilterException {
    if (!skip && "IHDR".equals(type)) {
      return handleIHDR(state, length, data);
    }
    if (!state.hasSeenIHDR) throwError("No IHDR chunk!", "No IHDR chunk!");
    if (!skip && "IEND".equals(type)) {
      return handleIEND(state);
    }
    if (!skip && "PLTE".equalsIgnoreCase(type)) {
      return handlePLTE(state);
    }
    if (!skip && "IDAT".equalsIgnoreCase(type)) {
      return handleIDAT(state);
    }
    if (!skip && "cICP".equals(type)) {
      return handleCICP(state, length, data);
    }
    if (!skip && "mDCV".equals(type)) {
      return handleMDCV(state);
    }
    return false;
  }

  private boolean handleIHDR(PngState state, int length, byte[] data) throws DataFilterException {
    if (state.hasSeenIHDR) throwError("Duplicate IHDR", "Two IHDR chunks detected!!");
    if (length != 13) throwError("IHDR length!= 13", "The length of the IHDR file is not 13");
    long width =
        ((long) (data[0] & 0xff) << 24)
            + ((data[1] & 0xff) << 16)
            + ((data[2] & 0xff) << 8)
            + (data[3] & 0xff);
    long height =
        ((long) (data[4] & 0xff) << 24)
            + ((data[5] & 0xff) << 16)
            + ((data[6] & 0xff) << 8)
            + (data[7] & 0xff);
    if (width < 1 || height < 1)
      throwError("Width or Height is invalid", "Width or Height is invalid (<1)");
    int bitDepth = data[8];
    int colourType = data[9];
    throwOnInvalidColour(bitDepth, colourType);
    int compressionMethod = data[10];
    if (compressionMethod != 0)
      throwError("Invalid CompressionMethod", "Invalid CompressionMethod! " + compressionMethod);
    int filterMethod = data[11];
    if (filterMethod != 0)
      throwError("Invalid FilterMethod", "Invalid FilterMethod! " + filterMethod);
    int interlaceMethod = data[12];
    if (interlaceMethod < 0 || interlaceMethod > 1)
      throwError("Invalid InterlaceMethod", "Invalid InterlaceMethod! " + interlaceMethod);

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Info from IHDR: width={}px height={}px bitDepth={} colourType={}"
              + " compressionMethod={} filterMethod={} interlaceMethod={}",
          width,
          height,
          bitDepth,
          colourType,
          compressionMethod,
          filterMethod,
          interlaceMethod);
    state.hasSeenIHDR = true;
    return true;
  }

  private boolean handleIEND(PngState state) throws DataFilterException {
    if (state.hasSeenIEND) throwError("Two IEND chunks detected!!", "Two IEND chunks detected!!");
    state.hasSeenIEND = true;
    return true;
  }

  private boolean handlePLTE(PngState state) throws DataFilterException {
    if (state.hasSeenIDAT) throwError("PLTE must be before IDAT", "PLTE must be before IDAT");
    if (state.hasSeenMDCV && !state.hasSeenCICP) {
      throwError(ERROR_MDCV_REQUIRES_CICP, ERROR_MDCV_REQUIRES_CICP);
    }
    state.hasSeenPLTE = true;
    return true;
  }

  private boolean handleIDAT(PngState state) throws DataFilterException {
    if (state.hasSeenIDAT && !"IDAT".equalsIgnoreCase(state.lastChunkType))
      throwError(
          "Multiple IDAT chunks must be consecutive!", "Multiple IDAT chunks must be consecutive!");
    if (state.hasSeenMDCV && !state.hasSeenCICP) {
      throwError(ERROR_MDCV_REQUIRES_CICP, ERROR_MDCV_REQUIRES_CICP);
    }
    state.hasSeenIDAT = true;
    return true;
  }

  private boolean handleCICP(PngState state, int length, byte[] data) throws DataFilterException {
    if (length != 4) throwError("cICP chunks invalid!", "cICP chunks must be 4 bytes long!");
    if (data[2] != 0)
      throwError(
          "cICP chunks invalid!", "Unsupported color model other than RGB is specified in PNG!");
    state.hasSeenCICP = true;
    return !(state.hasSeenPLTE || state.hasSeenIDAT);
  }

  private boolean handleMDCV(PngState state) {
    state.hasSeenMDCV = true;
    return !(state.hasSeenPLTE || state.hasSeenIDAT);
  }

  private String validateAndDecodeChunkType(byte[] raw) throws DataFilterException {
    StringBuilder sb = new StringBuilder(4);
    for (int i = 0; i < 4; i++) {
      char val = (char) raw[i];
      if ((val >= 65 && val <= 90) || (val >= 97 && val <= 122)) {
        sb.append(val);
      } else {
        String chunkName = HexUtil.bytesToHex(raw, 0, 4);
        throwError("Unknown Chunk", "The name of the chunk is invalid! (" + chunkName + ")");
      }
    }
    return sb.toString();
  }

  private boolean crcMatches(byte[] type, byte[] data, byte[] crcBytes) {
    long readCRC =
        (((long) (crcBytes[0] & 0xff) << 24)
                + ((crcBytes[1] & 0xff) << 16)
                + ((crcBytes[2] & 0xff) << 8)
                + (crcBytes[3] & 0xff))
            & 0x00000000ffffffffL;
    CRC32 crc = new CRC32();
    crc.update(type);
    if (data.length > 0) crc.update(data);
    long computedCRC = crc.getValue();
    if (readCRC != computedCRC && LOG.isDebugEnabled()) {
      LOG.debug(
          "CRC of the chunk {} doesn't match ({} but should be {})!",
          new String(type),
          Long.toHexString(readCRC),
          Long.toHexString(computedCRC));
    }
    return readCRC == computedCRC;
  }

  private ChunkData readChunk(DataInputStream dis) throws IOException {
    byte[] lenBytes = new byte[4];
    dis.readFully(lenBytes);
    int length =
        ((lenBytes[0] & 0xff) << 24)
            + ((lenBytes[1] & 0xff) << 16)
            + ((lenBytes[2] & 0xff) << 8)
            + (lenBytes[3] & 0xff);

    byte[] typeRaw = new byte[4];
    dis.readFully(typeRaw);
    String type = validateAndDecodeChunkType(typeRaw);

    byte[] data = new byte[length];
    if (length > 0) {
      dis.readFully(data, 0, length);
    }

    byte[] crc = new byte[4];
    dis.readFully(crc);

    return new ChunkData(length, type, typeRaw, data, crc);
  }

  private void writeChunkToBuffer(DataOutputStream dos, ChunkData chunk, long offset)
      throws IOException {
    // length
    dos.writeInt(chunk.length);
    // type
    dos.write(chunk.typeRaw);
    // data
    if (chunk.length > 0) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "data (offset=0x{}) {}",
            Long.toHexString(offset),
            chunk.data.length == 0 ? "null" : HexUtil.bytesToHex(chunk.data));
      }
      dos.write(chunk.data);
    }
    // crc
    dos.write(chunk.crcBytes);
  }

  private static final class ChunkData {
    final int length;
    final String type;
    final byte[] typeRaw;
    final byte[] data;
    final byte[] crcBytes;

    ChunkData(int length, String type, byte[] typeRaw, byte[] data, byte[] crcBytes) {
      this.length = length;
      this.type = type;
      this.typeRaw = typeRaw;
      this.data = data;
      this.crcBytes = crcBytes;
    }
  }

  private Handling determineHandling(
      PngState state,
      ChunkData chunk,
      boolean deleteText,
      boolean deleteTimestamp,
      boolean checkCRCs)
      throws DataFilterException {
    boolean skip = checkCRCs && !crcMatches(chunk.typeRaw, chunk.data, chunk.crcBytes);
    boolean valid = handleKnownChunkTypes(state, chunk.type, chunk.length, chunk.data, skip);
    if (!valid) valid = handleHarmlessChunks(state, chunk.type);
    if (!valid) return policyHandling(chunk, deleteText, deleteTimestamp, skip);
    return new Handling(!skip, skip);
  }

  private Handling policyHandling(
      ChunkData chunk, boolean deleteText, boolean deleteTimestamp, boolean skip) {
    if (isTextChunk(chunk.type)) {
      return new Handling(!deleteText && !skip, deleteText || skip);
    }
    if ("time".equalsIgnoreCase(chunk.type)) {
      return new Handling(!deleteTimestamp && !skip, deleteTimestamp || skip);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Skipping unknown chunk type {}", chunk.type);
    return new Handling(false, true);
  }

  private record Handling(boolean write, boolean skip) {}

  private static final class PngState {
    boolean hasSeenIHDR;
    boolean hasSeenIEND;
    boolean hasSeenIDAT;
    boolean hasSeenPLTE;
    boolean hasSeenCICP;
    boolean hasSeenMDCV;
    String lastChunkType = "";
  }

  private static final String ERROR_INVALID_COLOUR_COMBO =
      "Invalid colourType/bitDepth combination!";

  private void throwOnInvalidColour(int bitDepth, int colourType) throws DataFilterException {
    switch (bitDepth) {
      case 1, 2, 4:
        if (colourType != 0 && colourType != 3) invalidColourCombo(colourType, bitDepth);
        break;
      case 16:
        if (colourType == 3) invalidColourCombo(colourType, bitDepth);
        if (isValidColourType8(colourType)) break;
        invalidColourCombo(colourType, bitDepth);
        break;
      case 8:
        if (isValidColourType8(colourType)) break;
        invalidColourCombo(colourType, bitDepth);
        break;
      default:
        invalidColourCombo(colourType, bitDepth);
        break;
    }
  }

  private boolean isValidColourType8(int colourType) {
    return colourType == 0
        || colourType == 2
        || colourType == 3
        || colourType == 4
        || colourType == 6;
  }

  private void invalidColourCombo(int colourType, int bitDepth) throws DataFilterException {
    throwError(
        ERROR_INVALID_COLOUR_COMBO,
        ERROR_INVALID_COLOUR_COMBO + " (" + colourType + '|' + bitDepth + ')');
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("PNGFilter." + key);
  }

  private void throwError(String shortReason, String reason) throws DataFilterException {
    // Throw an exception
    String message = "Invalid PNG";
    if (reason != null) message += ' ' + reason;
    if (shortReason != null) message += " - " + shortReason;
    DataFilterException e = new DataFilterException(shortReason, shortReason, message);
    LOG.info("Throwing {}", e.getMessage(), e);
    throw e;
  }
}
