package network.crypta.support.api;

/**
 * View of a single file received via an HTTP upload.
 *
 * <p>This interface models one uploaded file (typically a part of a {@code multipart/form-data}
 * request). It exposes the associated MIME type, the client-provided file name, and the file data
 * as a {@link Bucket}. Implementations may back the data with memory, disk, or other storage and
 * may stream content on demand.
 *
 * <p>Resource management: callers are responsible for releasing resources held by the returned
 * {@link Bucket} (for example, via {@link Bucket#close()} or {@link Bucket#free()}) once the data
 * is no longer needed.
 *
 * <p>Thread-safety: unless otherwise specified by the implementation, instances are not guaranteed
 * to be safe for concurrent use.
 */
public interface HTTPUploadedFile {

  /**
   * Returns the MIME type associated with the uploaded content.
   *
   * <p>The value typically reflects the {@code Content-Type} declared for the uploaded part, but
   * callers must not rely on it for trust or validation. If content-type correctness matters,
   * validate independently (e.g., by sniffing or verifying against expected types).
   *
   * @return MIME type string (for example, {@code application/octet-stream}).
   */
  String getContentType();

  /**
   * Returns the file data as a {@link Bucket} for streaming access.
   *
   * <p>The returned bucket may hold substantial resources (temporary files, buffers, handles). The
   * caller must close or free it after use. Access patterns are implementation-defined; prefer
   * reading sequentially via {@link Bucket#getInputStream()} and obtain the size with {@link
   * Bucket#size()} when needed.
   *
   * @return container that provides the uploaded bytes.
   */
  Bucket getData();

  /**
   * Returns the client-provided file name.
   *
   * <p>This is metadata supplied by the uploading client. Treat it as untrusted input: it may be
   * missing, non-ASCII, or contain path separators. Do not use it directly as a filesystem path;
   * sanitize or replace with a server-generated name as appropriate.
   *
   * @return original file name as provided by the client.
   */
  String getFilename();
}
