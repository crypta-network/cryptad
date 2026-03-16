package network.crypta.runtime.spi;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Detached upload payload for darknet file offers.
 *
 * <p>This value carries only the metadata and stream-opening behavior that the runtime bridge needs
 * to replay an HTTP upload into the daemon's existing file-offer APIs. It intentionally avoids HTTP
 * request objects, bucket implementations, and daemon-specific types so that {@code runtime-spi}
 * stays JDK-only while still representing uploaded content without an additional byte-array or
 * temp-file hop.
 *
 * <p>Instances are immutable after construction. The contained {@link StreamSource} must reopen the
 * upload from the beginning on every call because one compose/send request may offer the same
 * uploaded file to more than one peer.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class DarknetUploadedFile {
  /**
   * JDK-only stream source for detached uploaded-file contents.
   *
   * <p>Implementations must return a new readable stream positioned at the beginning of the upload
   * every time this method is called. Callers may invoke it more than once during one HTTP request
   * when the same upload is offered to multiple peers.
   */
  @FunctionalInterface
  public interface StreamSource {
    /**
     * Opens a fresh stream for reading the upload contents.
     *
     * <p>The returned stream should expose the exact uploaded bytes from offset {@code 0}. The
     * caller is responsible for closing it after each sending attempt.
     *
     * @return new readable stream positioned at the first byte of the detached upload
     * @throws IOException if the upload contents cannot be reopened for reading
     */
    InputStream openStream() throws IOException;
  }

  private final String filename;
  private final String contentType;
  private final long size;
  private final StreamSource streamSource;

  /**
   * Creates a detached uploaded-file payload.
   *
   * <p>The constructor records the caller-supplied metadata and validates only the detached shape
   * of the object. It does not read from the underlying upload stream, sniff content types, or
   * verify that the declared size matches the number of bytes later returned by the stream source.
   *
   * @param filename client-supplied filename that comes with the detached upload and may be empty
   *     but never {@code null}
   * @param contentType client-supplied MIME type, or {@code null} when the request did not supply
   *     one
   * @param size declared upload size in bytes; must be zero or greater
   * @param streamSource source that can reopen the upload contents from the beginning on demand
   * @throws NullPointerException if {@code filename} or {@code streamSource} is {@code null}
   * @throws IllegalArgumentException if {@code size} is negative
   */
  public DarknetUploadedFile(
      String filename, String contentType, long size, StreamSource streamSource) {
    if (size < 0) {
      throw new IllegalArgumentException("size");
    }
    this.filename = Objects.requireNonNull(filename, "filename");
    this.contentType = contentType;
    this.size = size;
    this.streamSource = Objects.requireNonNull(streamSource, "streamSource");
  }

  /**
   * Returns the client-supplied filename.
   *
   * <p>This is opaque metadata preserved from the original HTTP upload. Callers should treat it as
   * presentation data, not as a trusted filesystem path.
   *
   * @return detached filename string; never {@code null}
   */
  public String filename() {
    return filename;
  }

  /**
   * Returns the client-supplied MIME type.
   *
   * <p>The value is passed through unchanged from the original upload metadata and may be absent or
   * inaccurate.
   *
   * @return detached MIME type, or {@code null} when the upload had no declared content type
   */
  public String contentType() {
    return contentType;
  }

  /**
   * Returns the declared upload size.
   *
   * <p>The size is the detached byte count captured by the HTTP layer before the upload enters the
   * runtime SPI boundary.
   *
   * @return upload size in bytes; guaranteed to be zero or greater
   */
  public long size() {
    return size;
  }

  /**
   * Opens a fresh stream for reading the detached upload contents.
   *
   * <p>Each call delegates to the stored {@link StreamSource}. Repeated calls are expected to yield
   * independent streams, so callers can retry or send the same upload to multiple peers without
   * caching the content in memory.
   *
   * @return readable stream positioned at the first byte of the detached upload
   * @throws IOException if the detached upload contents cannot be reopened for reading
   */
  public InputStream openStream() throws IOException {
    return streamSource.openStream();
  }

  @Override
  public String toString() {
    return "DarknetUploadedFile[filename="
        + filename
        + ", contentType="
        + contentType
        + ", size="
        + size
        + ']';
  }
}
