package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.io.FileUtil;

/**
 * Validates and transparently forwards Windows/OS2 BMP image data.
 *
 * <p>This filter parses the bitmap header at the start of the stream and performs a set of
 * structural checks that are typical for {@code image/bmp}. It verifies the magic word ("BM" and
 * related OS/2 signatures), header and DIB sizes, image dimensions, bit depth, compression type,
 * per-axis resolution, the total file size relationship, and—when the image is uncompressed—the
 * expected payload size after row alignment. If validation succeeds, the original bytes are copied
 * verbatim to the destination stream; otherwise a {@link DataFilterException} is thrown to signal
 * rejection of the content.
 *
 * <p>Use this filter when accepting or relaying BMP files from untrusted sources and a minimal
 * structural sanity check is required before handing the data to downstream consumers (such as
 * image decoders or browsers). The implementation operates in a streaming fashion and does not
 * retain the full image in memory. Instances keep no shared mutable state and are safe to reuse
 * across requests as long as a new stream pair is supplied for each invocation.
 *
 * <ul>
 *   <li>Checks signature, header/DIB sizes, and dimensions.
 *   <li>Validates bit depth and supported compression codes (0–3).
 *   <li>Confirms file-size consistency and, for uncompressed images, row-aligned payload size.
 *   <li>Copies input to output unchanged when all checks pass.
 * </ul>
 *
 * <p>References: <a
 * href="http://www.fastgraph.com/help/bmp_header_format.html">http://www.fastgraph.com/help/bmp_header_format.html</a>
 * and <a
 * href="http://en.wikipedia.org/wiki/BMP_file_format">http://en.wikipedia.org/wiki/BMP_file_format</a>
 *
 * @see ContentDataFilter
 * @see #readFilter(InputStream, OutputStream, String, Map, String, FilterCallback)
 * @author kurmiashish
 * @since 1
 */
public class BMPFilter implements ContentDataFilter {

  static final byte[] bmpHeaderwindows = {(byte) 'B', (byte) 'M'};

  static final byte[] bmpHeaderos2bArray = {(byte) 'B', (byte) 'A'};

  static final byte[] bmpHeaderos2cIcon = {(byte) 'C', (byte) 'I'};

  static final byte[] bmpHeaderos2cPointer = {(byte) 'C', (byte) 'P'};

  static final byte[] bmpHeaderos2Icon = {(byte) 'I', (byte) 'C'};

  static final byte[] bmpHeaderos2Pointer = {(byte) 'P', (byte) 'T'};

  private static int unsignedByte(byte b) {
    if (b >= 0) {
      return b;
    } else {
      return 256 + b;
    }
  }

  /**
   * Creates a new BMP filter instance.
   *
   * <p>Instances are stateless and may be reused across multiple validations as long as a fresh
   * input/output stream pair is provided per invocation of {@link #readFilter(InputStream,
   * OutputStream, String, Map, String, FilterCallback)}.
   */
  public BMPFilter() {
    // Intentionally empty: the filter is stateless and requires no initialization.
  }

  /**
   * Reads a 32-bit little-endian integer from the given stream.
   *
   * <p>The method attempts to read four bytes and interpret them in little-endian order (least
   * significant byte first). If the end of the stream has been reached before any byte can be read,
   * an {@link EOFException} is thrown. Callers should provide a buffered stream that can satisfy a
   * four-byte read promptly to avoid partial buffer fills.
   *
   * @param dis the data input to read from; must be positioned at the first byte of a 4-byte value
   *     encoded in little-endian order; must not be {@code null}.
   * @return the decoded signed 32-bit value constructed from four bytes in little-endian order; the
   *     value is returned as a Java {@code int}.
   * @throws IOException if an I/O error occurs while reading, including {@link EOFException} when
   *     no more data is available at the start of the integer.
   */
  public int readInt(DataInputStream dis) throws IOException {
    int result;
    byte[] data = new byte[4];

    result = dis.read(data);
    if (result < 0) { // end of file reached
      throw new EOFException();
    }

    result = (unsignedByte(data[2]) << 16) | (unsignedByte(data[1]) << 8) | unsignedByte(data[0]);
    result |= (unsignedByte(data[3]) << 24);

    return result;
  }

  /**
   * Reads a 16-bit little-endian integer from the given stream.
   *
   * <p>The method reads two consecutive bytes and combines them in little-endian order into a
   * 16-bit value promoted to {@code int}. It throws {@link EOFException} if the stream ends before
   * either byte can be read.
   *
   * @param dis the data input to read from; must be positioned at the first byte of a 2-byte value
   *     encoded in little-endian order; must not be {@code null}.
   * @return the decoded 16-bit value (as a positive {@code int} in the range 0–65535) assembled
   *     from two bytes in little-endian order.
   * @throws IOException if an I/O error occurs while reading or when the end of stream is reached
   *     before the value is complete.
   */
  public int readShort(DataInputStream dis) throws IOException {
    int result = dis.read();
    if (result < 0) { // end of file reached
      throw new EOFException();
    }

    int r2 = dis.read();
    if (r2 < 0) { // end of file reached
      throw new EOFException();
    }

    return result | (r2 * 256);
  }

  /**
   * Validates the BMP header and writes the original bytes to the destination stream.
   *
   * <p>The method inspects the beginning of {@code input} to validate the BMP signature and header
   * fields (file size, DIB size, width/height, planes, bit depth, compression, resolution, and
   * payload size when uncompressed). If any check fails, a {@link DataFilterException} is thrown
   * (as an {@link IOException}). On success, the content is copied verbatim to {@code output}. The
   * filter operates in a streaming manner and does not rely on {@code available()}; callers may
   * pass network-backed streams. The {@code charset}, {@code otherParams}, {@code
   * schemeHostAndPort}, and {@code cb} parameters are accepted for API symmetry and future
   * evolution but are not used by this binary format.
   *
   * <pre>{@code
   * // Example: validate and forward BMP bytes
   * var filter = new BMPFilter();
   * filter.readFilter(inStream, outStream, null, Map.of(), null, null);
   * }</pre>
   *
   * @param input source stream containing the candidate BMP; must support blocking reads and may be
   *     unbuffered or network-backed; not closed by this method.
   * @param output destination for the original bytes if validation succeeds; the method flushes the
   *     stream but does not close it upon completion.
   * @param charset declared character set (ignored for BMP as a binary format); may be {@code null}
   *     or empty without affecting validation.
   * @param otherParams additional media-type parameters (unused for BMP); callers may pass an empty
   *     map; entries are ignored by this implementation.
   * @param schemeHostAndPort externally visible endpoint information (unused for BMP); may be
   *     {@code null}.
   * @param cb optional callback for content filters that support fine-grained decisions (unused for
   *     BMP); may be {@code null}.
   * @throws IOException if an I/O failure occurs during read or write, or if validation fails and a
   *     {@link DataFilterException} is raised to reject the content.
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
    DataInputStream dis = new DataInputStream(input);
    dis.mark(54);

    byte[] startWord = new byte[2];
    dis.readFully(startWord);
    validateStartWord(startWord);

    int fileSize = readInt(dis);
    byte[] skipBytes = new byte[4];
    dis.readFully(skipBytes);
    int headerSize = readInt(dis);
    validateHeaderOffset(headerSize);

    int sizeBitmapInfoHeader = readInt(dis);
    validateBitmapInfoHeaderSize(sizeBitmapInfoHeader);

    int imageWidth = readInt(dis);
    int imageHeight = readInt(dis);
    validateDimensions(imageWidth, imageHeight);

    int noPlane = readShort(dis);
    validatePlaneCount(noPlane);

    int bitDepth = readShort(dis);
    validateBitDepth(bitDepth);

    int compressionType = readInt(dis);
    validateCompressionType(compressionType);

    int imageDataSize = readInt(dis);
    validateFileSize(fileSize, headerSize, imageDataSize);

    int horizontalResolution = readInt(dis);
    int verticalResolution = readInt(dis);
    validateResolution(horizontalResolution, verticalResolution);

    validateUncompressedImageSize(
        compressionType, bitDepth, imageWidth, imageHeight, imageDataSize);

    dis.reset();

    FileUtil.copy(dis, output, -1);
    output.flush();
  }

  private void validateUncompressedImageSize(
      int compressionType, int bitDepth, int imageWidth, int imageHeight, int imageDataSize)
      throws DataFilterException {
    if (compressionType == 0) {
      int bitsPerLine = imageWidth * bitDepth;
      if (bitsPerLine % 32 != 0) {
        bitsPerLine += 32 - bitsPerLine % 32;
      }
      int bytesPerLine = bitsPerLine / 8;
      int calculatedSize = bytesPerLine * imageHeight;
      if (calculatedSize != imageDataSize) {
        throwHeaderError(l10n("InvalidImageDataSizeT"), l10n("InvalidImageDataSizeD"));
      }
    }
  }

  private void validateResolution(int horizontalResolution, int verticalResolution)
      throws DataFilterException {
    if (horizontalResolution < 0 || verticalResolution < 0) {
      throwHeaderError(l10n("InvalidResolutionT"), l10n("InvalidResolutionD"));
    }
  }

  private void validateFileSize(int fileSize, int headerSize, int imageDataSize)
      throws DataFilterException {
    if (fileSize != headerSize + imageDataSize) {
      throwHeaderError(l10n("InvalidFileSizeT"), l10n("InvalidFileSizeD"));
    }
  }

  private void validateCompressionType(int compressionType) throws DataFilterException {
    if (!(compressionType >= 0 && compressionType <= 3)) {
      throwHeaderError(
          l10n("Invalid Compression type"),
          l10n("Compression type field is set to " + compressionType + " instead of 0-3"));
    }
  }

  private void validateBitDepth(int bitDepth) throws DataFilterException {
    if (bitDepth != 1
        && bitDepth != 2
        && bitDepth != 4
        && bitDepth != 8
        && bitDepth != 16
        && bitDepth != 24
        && bitDepth != 32) {
      throwHeaderError(l10n("InvalidBitDepthT"), l10n("InvalidBitDepthD"));
    }
  }

  private void validatePlaneCount(int noPlane) throws DataFilterException {
    if (noPlane != 1) { // No of planes should be 1
      throwHeaderError(l10n("InvalidNoOfPlanesT"), l10n("InvalidNoOfPlanesD"));
    }
  }

  private void validateDimensions(int imageWidth, int imageHeight) throws DataFilterException {
    if (imageWidth < 0 || imageHeight < 0) {
      throwHeaderError(l10n("InvalidDimensionT"), l10n("InvalidDimensionD"));
    }
  }

  private void validateBitmapInfoHeaderSize(int sizeBitmapInfoHeader) throws DataFilterException {
    if (sizeBitmapInfoHeader != 40) {
      throwHeaderError(l10n("InvalidBitMapInfoHeaderSizeT"), l10n("InvalidBitMapInfoHeaderSizeD"));
    }
  }

  private void validateHeaderOffset(int headerSize) throws DataFilterException {
    if (headerSize < 0) {
      throwHeaderError(l10n("InvalidOffsetT"), l10n("InvalidOffsetD"));
    }
  }

  private void validateStartWord(byte[] startWord) throws DataFilterException {
    if ((!Arrays.equals(startWord, bmpHeaderwindows))
        && (!Arrays.equals(startWord, bmpHeaderos2bArray))
        && (!Arrays.equals(startWord, bmpHeaderos2cIcon))
        && (!Arrays.equals(startWord, bmpHeaderos2cPointer))
        && (!Arrays.equals(startWord, bmpHeaderos2Icon))
        && (!Arrays.equals(startWord, bmpHeaderos2Pointer))) { // Checking the first word
      throwHeaderError(l10n("InvalidStartWordT"), l10n("InvalidStartWordD"));
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("BMPFilter." + key);
  }

  private void throwHeaderError(String shortReason, String reason) throws DataFilterException {
    // Throw an exception
    String message = l10n("notBMP");
    if (reason != null) message += ' ' + reason;
    if (shortReason != null) message += " - (" + shortReason + ')';
    throw new DataFilterException(shortReason, shortReason, message);
  }
}
