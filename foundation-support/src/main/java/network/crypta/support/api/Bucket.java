package network.crypta.support.api;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.io.ResumeFailedException;

/**
 * Abstraction of a temporary data container.
 *
 * <p>A {@code Bucket} behaves like a temporary file but the underlying storage can vary: it may
 * live in memory, on disk, be encrypted, occupy a slice of another file, or be composed of a chain
 * of other buckets. Implementations are free to choose the storage strategy while exposing a simple
 * stream-based read/write API.
 *
 * <p>Serialization is not required; not all bucket implementations are {@link java.io.Serializable
 * Serializable}.
 *
 * <p>Thread-safety: unless otherwise documented by a specific implementation, instances are not
 * guaranteed to be safe for concurrent use. Coordinate access externally.
 *
 * @author oskar
 */
public interface Bucket extends AutoCloseable {

  /**
   * Opens a stream for writing the bucket's content from the beginning.
   *
   * <p>Writing always starts at offset {@code 0}; appending is not supported. If the caller needs
   * append-like behavior, it must retain and reuse the returned {@link OutputStream} while writing
   * sequentially. Implementations may return a buffered stream where appropriate (for example,
   * memory-backed buckets may not require additional buffering).
   *
   * <p>Callers must close the returned stream (preferably using try-with-resources) to ensure all
   * data is flushed and resources are released.
   *
   * @return an {@link OutputStream} for writing, positioned at the start
   * @throws IOException if the stream cannot be created or the bucket cannot be opened for write
   */
  OutputStream getOutputStream() throws IOException;

  /**
   * Opens an unbuffered stream for writing from the beginning.
   *
   * <p>Prefer this when the caller provides its own buffering or performs large block writes (for
   * example, when piping data from one bucket to another). This method does not provide stronger
   * durability guarantees than {@link #getOutputStream()}—it exists primarily to avoid redundant
   * buffering and reduce memory overhead.
   *
   * <p>Callers must close the returned stream to complete the writing.
   *
   * @return an unbuffered {@link OutputStream} for writing, positioned at the start
   * @throws IOException if the stream cannot be created or the bucket cannot be opened for write
   */
  OutputStream getOutputStreamUnbuffered() throws IOException;

  /**
   * Opens a stream for reading the bucket's current content.
   *
   * <p>If the bucket currently contains no data, this method returns {@code null}. Callers should
   * use try-with-resources or explicitly close the returned {@link InputStream} to avoid resource
   * leaks.
   *
   * @return an {@link InputStream} for reading, or {@code null} when the bucket is empty
   * @throws IOException if the stream cannot be created or the content cannot be read
   */
  InputStream getInputStream() throws IOException;

  /**
   * Opens an unbuffered stream for reading the bucket's current content.
   *
   * <p>Semantics match {@link #getInputStream()} except that the returned stream is not wrapped in
   * additional buffering layers. Use when the caller manages buffering explicitly.
   *
   * @return an unbuffered {@link InputStream} for reading, or {@code null} when the bucket is empty
   * @throws IOException if the stream cannot be created or the content cannot be read
   */
  InputStream getInputStreamUnbuffered() throws IOException;

  /**
   * Returns a human-readable identifier for the bucket.
   *
   * <p>The value is intended for diagnostics and logging only; callers must not rely on uniqueness
   * or a specific format.
   *
   * @return a descriptive name suitable for logs and debug output
   */
  String getName();

  /**
   * Returns the number of bytes currently stored in the bucket.
   *
   * @return size in bytes; {@code 0} when empty
   */
  long size();

  /**
   * Reports whether the bucket currently rejects further writes.
   *
   * @return {@code true} if the bucket is read-only; {@code false} otherwise
   */
  boolean isReadOnly();

  /**
   * Permanently marks the bucket as read-only.
   *
   * <p>After this call, attempts to obtain a writable stream are expected to fail. The operation is
   * irreversible for the lifetime of the instance.
   */
  void setReadOnly();

  /**
   * Releases the bucket and its underlying resources, if supported by the implementation.
   *
   * <p>Call this even if no streams were opened; some implementations may eagerly allocate
   * resources (for example, creating a temporary file). After freeing, further operations on the
   * instance may fail.
   */
  void free();

  /**
   * Allows use with try-with-resources by delegating to {@link #free()}.
   *
   * <p>Calling close() is equivalent to calling {@link #free()} and should be considered a terminal
   * operation for the bucket instance.
   */
  @Override
  default void close() {
    free();
  }

  /**
   * Creates a shallow, read-only view of this bucket that shares the same underlying storage.
   *
   * <p>The returned instance is logically independent but references the same external data. If the
   * original bucket is deleted or freed, the shadow may become invalid and subsequent reads can
   * throw {@link IOException} or yield truncated data. Some call sites tolerate this behavior (for
   * example, HTTP proxying scenarios).
   *
   * @return a read-only shadow bucket, or {@code null} if shadowing is not supported
   */
  Bucket createShadow();

  /**
   * Notifies the bucket that the application has resumed after a restart.
   *
   * <p>Implementations should perform any required housekeeping (for example, re-registering with a
   * persistent bucket tracker) to prevent premature garbage collection of external resources. The
   * method may be invoked more than once; implementations should handle duplicate notifications.
   *
   * @param context runtime services and helpers required to reinitialize the bucket
   * @throws ResumeFailedException if the bucket cannot reattach to its persisted state
   */
  void onResume(ResumeContext context) throws ResumeFailedException;

  /**
   * Writes the metadata necessary to reconstruct the bucket to the given stream.
   *
   * <p>Implementations that do not support persistence should throw {@link
   * UnsupportedOperationException}. When supported, the written format should be treated as an
   * internal contract and versioned as needed for forward compatibility.
   *
   * @param dos destination for serialization data
   * @throws IOException on I/O failure while writing the metadata
   */
  void storeTo(DataOutputStream dos) throws IOException;
}
