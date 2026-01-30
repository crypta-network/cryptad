package network.crypta.client.filter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.io.CountedInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters JPEG byte streams by validating structural markers and optionally stripping metadata.
 *
 * <p>This implementation performs a disciplined, marker-by-marker reconstruction of a JPEG image,
 * copying only segments whose headers, lengths, and marker ordering comply with the JFIF and EXIF
 * specifications. It enforces that every frame it forwards begins with the canonical start-of-image
 * prefix, carries well-formed scan headers, and advertises lengths that match the bytes actually
 * observed on the wire. When the constructor flags request it, application comments and EXIF blocks
 * are omitted entirely so operator policies about privacy or payload size can be upheld without
 * touching downstream components.
 *
 * <p>The filter operates in a streaming fashion: {@link #readFilter(InputStream, OutputStream,
 * String, Map, String, FilterCallback)} consumes data incrementally, writes sanitized frames as
 * soon as they are proven safe, and terminates precisely at the end-of-image marker. Instances are
 * thread-safe and reusable because their configuration is immutable and all parsing state lives on
 * the stack for the duration of a call. Validation failures raise {@link DataFilterException} with
 * a localized explanation obtained through {@link NodeL10n}, allowing callers to surface actionable
 * error text to requesters.
 *
 * <p>Key behaviors include:
 *
 * <ul>
 *   <li>Verifies the start-of-image header and every advertised frame length before copying.
 *   <li>Optionally removes APP1 (EXIF) and COM frames while retaining structural metadata.
 *   <li>Logs marker transitions at debug level to aid diagnosis of corrupt or malicious files.
 * </ul>
 *
 * <p>Reference material: <a href="http://www.obrador.com/essentialjpeg/headerinfo.htm">Essential
 * JPEG header info</a>, the JFIF 1.02 specification, and the EXIF 2.2 specification.
 *
 * @see ContentDataFilter
 * @see FilterCallback
 */
public class JPEGFilter implements ContentDataFilter {
  private static final Logger LOG = LoggerFactory.getLogger(JPEGFilter.class);

  private final boolean deleteComments;
  private final boolean deleteExif;

  private static final int MARKER_EOI = 0xD9; // End of image
  // private static final int MARKER_SOI = 0xD8; // Start of image
  private static final int MARKER_RST0 = 0xD0; // First reset marker
  private static final int MARKER_RST7 = 0xD7; // Last reset marker

  JPEGFilter(boolean deleteComments, boolean deleteExif) {
    this.deleteComments = deleteComments;
    this.deleteExif = deleteExif;
  }

  private static final String INVALID_HEADER = "Invalid header";

  static final byte[] soi =
      new byte[] {
        (byte) 0xFF, (byte) 0xD8 // Start of Image
      };

  /**
   * Streams a JPEG payload through the sanitizing pipeline, emitting only validated segments.
   *
   * <p>The method asserts the canonical start-of-image prefix, rewrites essential frames exactly as
   * received, and conditionally strips comments or EXIF blocks according to the configuration
   * passed to the constructor. It stops at the end-of-image marker, flushes the destination {@link
   * OutputStream}, and raises {@link DataFilterException} whenever marker ordering, lengths, or
   * encodings diverge from the JFIF profile. The callback parameter is accepted for interface
   * completeness but is not currently invoked because JPEG filtering offers no interactive choices.
   *
   * <p>Typical usage wires the filter into the client proxy, allowing JPEG uploads to be validated
   * before reaching storage:
   *
   * <pre>{@code
   * ContentDataFilter filter = new JPEGFilter(false, true);
   * filter.readFilter(input, output, null, Map.of(), hostHint, null);
   * }</pre>
   *
   * @param input stream providing JPEG bytes; must begin with an SOI marker and deliver ordered
   *     marker data without rewinds.
   * @param output destination for sanitized JPEG bytes; receives only frames that already passed
   *     validation and is flushed after completion.
   * @param charset declared charset for the resource; ignored for binary JPEG but preserved for
   *     interface compatibility with other media types.
   * @param otherParams media-type parameters such as {@code boundary}; unused for JPEG yet required
   *     for {@link ContentDataFilter} interoperability.
   * @param schemeHostAndPort externally visible endpoint string (for example, {@code
   *     https://example:7777}); currently unused but accepted for uniform signatures.
   * @param cb optional callback for per-node filtering choices; ignored because JPEG sanitation is
   *     fully deterministic.
   * @throws IOException if reading from the source or writing to the sink fails before completion.
   * @throws DataFilterException if structural validation fails, including malformed markers,
   *     truncated frames, or forbidden metadata blocks.
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
    readFilter(input, output, deleteComments, deleteExif);
    output.flush();
  }

  private void readFilter(
      InputStream input, OutputStream output, boolean deleteComments, boolean deleteExif)
      throws IOException {
    CountedInputStream cis = new CountedInputStream(input);
    DataInputStream dis = new DataInputStream(cis);
    assertHeader(dis);
    output.write(soi);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    StreamContext streamContext = new StreamContext(cis, dis, dos, baos, output);

    int forceMarkerType = -1;
    while (true) {
      baos.reset();
      MarkerReadResult marker = readNextMarker(dis, baos, forceMarkerType);
      if (!marker.hasMarker()) {
        return;
      }

      if (LOG.isDebugEnabled()) {
        LOG.debug("Marker type: {}", Integer.toHexString(marker.markerType()));
      }

      long countAtStart = cis.count();
      int blockLength = readBlockLength(marker.markerType(), dis, dos);

      FrameAction action =
          processFrame(
              marker.markerType(),
              blockLength,
              countAtStart,
              streamContext,
              deleteComments,
              deleteExif);

      forceMarkerType = action.nextForceMarkerType();

      if (writeFrameIfNeeded(
              action,
              marker.markerType(),
              blockLength,
              countAtStart,
              streamContext.cis,
              streamContext.baos,
              streamContext.output)
          && action.finished()) {
        return;
      }
    }
  }

  private MarkerReadResult readNextMarker(
      DataInputStream dis, ByteArrayOutputStream baos, int forceMarkerType) throws IOException {
    if (forceMarkerType != -1) {
      baos.write(0xFF);
      baos.write(forceMarkerType);
      return new MarkerReadResult(true, forceMarkerType);
    }
    int markerStart = dis.read();
    if (markerStart == -1) {
      return MarkerReadResult.none();
    }
    if (markerStart != 0xFF) {
      throwError(
          "Invalid marker",
          "The file includes an invalid marker start "
              + Integer.toHexString(markerStart)
              + " and cannot be parsed further.");
    }
    baos.write(0xFF);
    int markerType = dis.readUnsignedByte();
    baos.write(markerType);
    return new MarkerReadResult(true, markerType);
  }

  private int readBlockLength(int markerType, DataInputStream dis, DataOutputStream dos)
      throws IOException {
    if (markerType == MARKER_EOI || markerType >= MARKER_RST0 && markerType <= MARKER_RST7) {
      return 0;
    }
    int blockLength = dis.readUnsignedShort();
    dos.writeShort(blockLength);
    return blockLength;
  }

  private int processStartOfScan(int blockLength, StreamContext ctx) throws IOException {
    validateScanBlockLength(blockLength);
    copyScanHeader(blockLength, ctx);
    ctx.baos.writeTo(ctx.output);
    return forwardScanData(ctx);
  }

  private void validateScanBlockLength(int blockLength) throws IOException {
    if (blockLength < 2) {
      throwError(
          "Invalid frame length",
          "The file includes an invalid frame (length " + blockLength + ").");
    }
  }

  private void copyScanHeader(int blockLength, StreamContext ctx) throws IOException {
    byte[] buf = new byte[blockLength - 2];
    ctx.dis.readFully(buf);
    ctx.dos.write(buf);
    LOG.debug("Copied start-of-frame marker length {}", blockLength - 2);
  }

  private int forwardScanData(StreamContext ctx) throws IOException {
    int prevChar = -1;
    while (true) {
      int x = ctx.dis.read();
      if (x == -1) {
        if (prevChar != -1 && ctx.output != null) {
          ctx.output.write(prevChar);
        }
        break;
      }
      if (prevChar == 0xFF && x != 0 && !(x >= MARKER_RST0 && x <= MARKER_RST7)) {
        logScanMarker(ctx, x);
        return x;
      }
      if (prevChar != -1 && ctx.output != null) {
        ctx.output.write(prevChar);
      }
      prevChar = x;
    }
    return -1;
  }

  private void logScanMarker(StreamContext ctx, int marker) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Moved scan at {}, found a marker type {}", ctx.cis.count(), Integer.toHexString(marker));
    }
  }

  private FrameAction processFrame(
      int markerType,
      int blockLength,
      long countAtStart,
      StreamContext ctx,
      boolean deleteComments,
      boolean deleteExif)
      throws IOException {
    if (markerType == 0xDA) {
      int nextMarker = processStartOfScan(blockLength, ctx);
      return FrameAction.startOfScan(nextMarker);
    }
    if (markerType == 0xE0) {
      return handleApp0Frame(blockLength, countAtStart, ctx);
    }
    if (markerType == 0xE1) {
      return handleExifFrame(blockLength, countAtStart, ctx, deleteExif);
    }
    if (markerType == 0xFE) {
      return handleCommentFrame(blockLength, countAtStart, ctx, deleteComments);
    }
    if (markerType == MARKER_EOI) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("End of image");
      }
      return FrameAction.writeAndFinish();
    }
    return handleGeneralFrame(markerType, blockLength, ctx);
  }

  private FrameAction handleApp0Frame(int blockLength, long countAtStart, StreamContext ctx)
      throws IOException {
    if (LOG.isDebugEnabled()) {
      LOG.debug("APP0");
    }
    String type = readNullTerminatedAsciiString(ctx.dis);
    writeNullTerminatedString(ctx.baos, type);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Type: {} length {}", type, type.length());
    }
    if (type.equals("JFIF")) {
      return copyJfifHeader(ctx);
    }
    if (type.equals("JFXX")) {
      return copyJfxxHeader(blockLength, countAtStart, ctx);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Dropping application-specific APP0 chunk named {}", type);
    }
    skipRest(blockLength, countAtStart, ctx.cis, ctx.dis, ctx.dos, "application-specific frame");
    return FrameAction.skip();
  }

  private FrameAction copyJfifHeader(StreamContext ctx) throws IOException {
    LOG.debug("JFIF Header");
    int majorVersion = ctx.dis.readUnsignedByte();
    if (majorVersion != 1) {
      throwError(INVALID_HEADER, "Unrecognized major version " + majorVersion + ".");
    }
    ctx.dos.write(majorVersion);
    int minorVersion = ctx.dis.readUnsignedByte();
    if (minorVersion > 2) {
      throwError(INVALID_HEADER, "Unrecognized version 1." + minorVersion + ".");
    }
    ctx.dos.write(minorVersion);
    int units = ctx.dis.readUnsignedByte();
    if (units > 2) {
      throwError(INVALID_HEADER, "Unrecognized units type " + units + ".");
    }
    ctx.dos.write(units);
    ctx.dos.writeShort(ctx.dis.readShort());
    ctx.dos.writeShort(ctx.dis.readShort());
    int thumbX = ctx.dis.readUnsignedByte();
    ctx.dos.writeByte(thumbX);
    int thumbY = ctx.dis.readUnsignedByte();
    ctx.dos.writeByte(thumbY);
    int thumbLen = thumbX * thumbY * 3;
    byte[] buf = new byte[thumbLen];
    ctx.dis.readFully(buf);
    ctx.dos.write(buf);
    return FrameAction.writeAndContinue();
  }

  private FrameAction copyJfxxHeader(int blockLength, long countAtStart, StreamContext ctx)
      throws IOException {
    int extensionCode = ctx.dis.readUnsignedByte();
    if (extensionCode == 0x10 || extensionCode == 0x11 || extensionCode == 0x13) {
      ctx.dos.write(extensionCode);
      skipRest(blockLength, countAtStart, ctx.cis, ctx.dis, ctx.dos, "thumbnail frame");
      LOG.debug("Thumbnail frame");
      return FrameAction.writeAndContinue();
    }
    throwError(
        "Unknown JFXX extension " + extensionCode, "The file contains an unknown JFXX extension.");
    return FrameAction.skip();
  }

  private FrameAction handleExifFrame(
      int blockLength, long countAtStart, StreamContext ctx, boolean deleteExif)
      throws IOException {
    if (deleteExif) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Dropping EXIF data");
      }
      skipBytes(ctx.dis, blockLength - 2);
      return FrameAction.skip();
    }
    skipRest(blockLength, countAtStart, ctx.cis, ctx.dis, ctx.dos, "EXIF frame");
    return FrameAction.writeAndContinue();
  }

  private FrameAction handleCommentFrame(
      int blockLength, long countAtStart, StreamContext ctx, boolean deleteComments)
      throws IOException {
    if (deleteComments) {
      skipBytes(ctx.dis, blockLength - 2);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Dropping comment length {}.", blockLength - 2);
      }
      return FrameAction.skip();
    }
    skipRest(blockLength, countAtStart, ctx.cis, ctx.dis, ctx.dos, "comment");
    return FrameAction.writeAndContinue();
  }

  private FrameAction handleGeneralFrame(int markerType, int blockLength, StreamContext ctx)
      throws IOException {
    if (isValidEssentialMarker(markerType)) {
      copyEssentialFrame(markerType, blockLength, ctx);
      return FrameAction.writeAndContinue();
    }
    dropFrame(markerType, blockLength, ctx.dis);
    return FrameAction.skip();
  }

  private boolean isValidEssentialMarker(int markerType) {
    return switch (markerType) {
      case 0xC0, // start of frame
          0xC1,
          0xC2,
          0xC3,
          0xC5,
          0xC6,
          0xC7,
          0xC9,
          0xCA,
          0xCB,
          0xCD,
          0xCF,
          0xC4,
          0xCC,
          0xD0,
          0xD1,
          0xD2,
          0xD3,
          0xD4,
          0xD5,
          0xD6,
          0xD7,
          0xD8,
          0xD9,
          0xDA,
          0xDB,
          0xDC,
          0xDD,
          0xDE,
          0xDF ->
          true;
      default -> false;
    };
  }

  private void copyEssentialFrame(int markerType, int blockLength, StreamContext ctx)
      throws IOException {
    if (blockLength < 2) {
      throwError(
          "Invalid frame length",
          "The file includes an invalid frame (length " + blockLength + ").");
    }
    byte[] buf = new byte[blockLength - 2];
    ctx.dis.readFully(buf);
    ctx.dos.write(buf);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Essential frame type {} length {} offset at end {}",
          Integer.toHexString(markerType),
          blockLength - 2,
          ctx.cis.count());
    }
  }

  private void dropFrame(int markerType, int blockLength, DataInputStream dis) throws IOException {
    if (markerType >= 0xE0 && markerType <= 0xEF) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Dropping application marker type {} length {}",
            Integer.toHexString(markerType),
            blockLength);
      }
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Dropping unknown frame type {} blockLength", Integer.toHexString(markerType));
    }
    skipBytes(dis, blockLength - 2);
  }

  private void validateFrameLength(
      int markerType, int blockLength, long countAtStart, CountedInputStream cis)
      throws IOException {
    if (cis.count() != countAtStart + blockLength) {
      throwError(
          "Invalid frame",
          "The length of the frame is incorrect (read "
              + (cis.count() - countAtStart)
              + " bytes, frame length "
              + blockLength
              + " for type "
              + Integer.toHexString(markerType)
              + ").");
    }
  }

  private boolean writeFrameIfNeeded(
      FrameAction action,
      int markerType,
      int blockLength,
      long countAtStart,
      CountedInputStream cis,
      ByteArrayOutputStream baos,
      OutputStream output)
      throws IOException {
    if (action.skipFrame()) {
      return false;
    }
    validateFrameLength(markerType, blockLength, countAtStart, cis);
    baos.writeTo(output);
    return true;
  }

  private record StreamContext(
      CountedInputStream cis,
      DataInputStream dis,
      DataOutputStream dos,
      ByteArrayOutputStream baos,
      OutputStream output) {}

  private record MarkerReadResult(boolean hasMarker, int markerType) {
    static MarkerReadResult none() {
      return new MarkerReadResult(false, -1);
    }
  }

  private record FrameAction(boolean skipFrame, boolean finished, int nextForceMarkerType) {
    static FrameAction skip() {
      return new FrameAction(true, false, -1);
    }

    static FrameAction writeAndContinue() {
      return new FrameAction(false, false, -1);
    }

    static FrameAction writeAndFinish() {
      return new FrameAction(false, true, -1);
    }

    static FrameAction startOfScan(int nextForceMarkerType) {
      return new FrameAction(true, false, nextForceMarkerType);
    }
  }

  private static String notJpegMessage() {
    return NodeL10n.getBase().getString("JPEGFilter.notJpeg");
  }

  private void writeNullTerminatedString(ByteArrayOutputStream baos, String type)
      throws IOException {
    byte[] data = type.getBytes(StandardCharsets.ISO_8859_1); // ascii, near enough
    baos.write(data);
    baos.write(0);
  }

  private String readNullTerminatedAsciiString(DataInputStream dis) throws IOException {
    StringBuilder sb = new StringBuilder();
    while (true) {
      int x = dis.read();
      if (x == -1) throwError("Invalid extension frame", "Could not read an extension frame name.");
      if (x == 0) break;
      char c = (char) x; // ASCII
      if (x > 128 || (c < 32 && c != 10 && c != 13))
        throwError("Invalid extension frame name", "Non-ASCII character in extension frame name");
      sb.append(c);
    }
    return sb.toString();
  }

  private void skipRest(
      int blockLength,
      long countAtStart,
      CountedInputStream cis,
      DataInputStream dis,
      DataOutputStream dos,
      String thing)
      throws IOException {
    // Skip the rest of the data
    int skip = (int) (blockLength - (cis.count() - countAtStart));
    if (skip < 0) throwError("Invalid " + thing, "The file includes an invalid " + thing + '.');
    if (skip == 0) return;
    byte[] buf = new byte[skip];
    dis.readFully(buf);
    dos.write(buf);
  }

  // Helper that tolerates short skips and falls back to bounded reads.
  private void skipBytes(DataInputStream dis, int skip) throws IOException {
    int skipped = 0;
    while (skipped < skip) {
      long remaining = (long) skip - skipped;
      long x = dis.skip(remaining);
      if (x <= 0) {
        byte[] buf = new byte[Math.min(4096, skip - skipped)];
        dis.readFully(buf);
        skipped += buf.length;
      } else skipped += (int) x;
    }
  }

  private void assertHeader(DataInputStream dis) throws IOException {
    byte[] read = new byte[soi.length];
    dis.readFully(read);
    if (!Arrays.equals(read, soi))
      throwError(INVALID_HEADER, "The file does not start with a valid JPEG (JFIF) header.");
  }

  private void throwError(String shortReason, String reason) throws DataFilterException {
    // Throw an exception
    String message = notJpegMessage();
    if (reason != null) message += ' ' + reason;
    if (shortReason != null) message += " - " + shortReason;
    DataFilterException e = new DataFilterException(shortReason, shortReason, message);
    if (LOG.isDebugEnabled()) LOG.info("Throwing {}", e.getMessage(), e);
    throw e;
  }
}
