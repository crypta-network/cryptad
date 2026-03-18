package network.crypta.runtime.spi;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Detached uploaded-file payload for queue browser-upload inserts.
 *
 * <p>This value carries only the metadata and stream-opening behavior needed to replay a browser
 * upload into the daemon's persistent insert path. It intentionally avoids HTTP request objects,
 * bucket implementations, and daemon-specific insert types so {@code runtime-spi} remains JDK-only
 * while still representing uploaded data without forcing an extra byte-array copy in the HTTP
 * layer.
 *
 * <p>Callers provide a {@link StreamSource} that can reopen the uploaded bytes from the beginning.
 * That lets the runtime adapter decide when to stage the upload into persistent storage without
 * holding onto HTTP request objects or assuming the source is backed by one specific bucket type.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class QueueUploadedFile {
  /**
   * JDK-only source that reopens the uploaded bytes from the beginning on demand.
   *
   * <p>Implementations must return a fresh readable stream each time this method is called.
   */
  @FunctionalInterface
  public interface StreamSource {
    /**
     * Opens a new readable stream for the detached upload contents.
     *
     * @return readable stream positioned at the first byte of the upload
     * @throws IOException if the upload bytes cannot be reopened
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
   * @param filename client-supplied upload filename; never {@code null}
   * @param contentType client-supplied MIME type, or {@code null} when absent
   * @param size declared upload size in bytes; must be zero or greater
   * @param streamSource source that can reopen the upload bytes from the beginning of each read
   */
  public QueueUploadedFile(
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
   * Returns the client-supplied upload filename.
   *
   * @return detached filename string; never {@code null}
   */
  public String filename() {
    return filename;
  }

  /**
   * Returns the client-supplied MIME type.
   *
   * @return detached MIME type, or {@code null} when absent
   */
  public String contentType() {
    return contentType;
  }

  /**
   * Returns the declared upload size.
   *
   * @return upload size in bytes; guaranteed to be zero or greater
   */
  public long size() {
    return size;
  }

  /**
   * Opens a new readable stream for the detached upload contents.
   *
   * <p>Each invocation is expected to return a fresh stream positioned at the first byte. Callers
   * should close the returned stream promptly after copying or inspection completes.
   *
   * @return readable stream positioned at the first byte of the upload
   * @throws IOException if the upload bytes cannot be reopened
   */
  public InputStream openStream() throws IOException {
    return streamSource.openStream();
  }

  @Override
  public String toString() {
    return "QueueUploadedFile[filename="
        + filename
        + ", contentType="
        + contentType
        + ", size="
        + size
        + ']';
  }
}
