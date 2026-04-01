package network.crypta.client.async;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link java.io.InputStream InputStream} that reads from a {@link Bucket} and frees it on
 * close.
 *
 * <p>This utility wraps the bucket-provided stream and ensures the associated {@link Bucket}
 * instance is released exactly when the stream is closed. It is convenient when the bucket is a
 * short‑lived, temporary container whose storage (for example a temporary file, in‑memory buffer,
 * or encrypted slice) should be reclaimed as soon as the caller finishes reading. The class extends
 * {@link java.io.FilterInputStream}, delegating all operations to the underlying stream; it does
 * not add buffering or interpretation of the data.
 *
 * <p>Typical usage is to obtain an instance via {@link #create(Bucket)} and consume it within a
 * try‑with‑resources block so the bucket is always freed, even on error. The life‑cycle is: acquire
 * the source stream from the bucket, read until end‑of‑stream, then {@code close()} frees the
 * bucket. The instance is mutable only through the inherited {@code InputStream} state (position),
 * and it is not designed for concurrent reads by multiple threads.
 *
 * <ul>
 *   <li>Responsibility: propagate reads to the wrapped stream.
 *   <li>Responsibility: call {@link Bucket#free()} after the stream is closed.
 *   <li>No additional buffering, framing, or decoding is performed.
 * </ul>
 *
 * @see Bucket
 * @see java.io.FilterInputStream
 * @see java.io.InputStream
 */
public class ReadBucketAndFreeInputStream extends FilterInputStream {

  private final Bucket data;

  /**
   * Creates a stream over the bucket that frees the bucket when closed.
   *
   * <p>The returned stream reads the bucket's current content and, upon {@link #close()}, invokes
   * {@link Bucket#free()} to release the bucket and its underlying resources. The supplied bucket
   * is expected to provide a non‑{@code null} {@link InputStream}; callers should only pass buckets
   * that currently expose readable content.
   *
   * <p>Use try‑with‑resources to guarantee freeing the bucket under both normal and exceptional
   * control flow.
   *
   * <pre>{@code
   * try (InputStream in = ReadBucketAndFreeInputStream.create(bucket)) {
   *   // consume 'in'; bucket is freed when the block exits
   * }
   * }</pre>
   *
   * @param data the source {@link Bucket}; must remain valid until the returned stream is closed
   * @return an input stream that delegates to the bucket and frees it when closed
   * @throws IOException if the bucket cannot provide its input stream for reading
   */
  public static InputStream create(Bucket data) throws IOException {
    return new ReadBucketAndFreeInputStream(data.getInputStream(), data);
  }

  private ReadBucketAndFreeInputStream(InputStream in, Bucket data) {
    super(in);
    this.data = data;
  }

  /**
   * Reads bytes into a portion of the array from the wrapped stream.
   *
   * <p>This override forwards directly to the underlying stream to avoid the default single‑byte
   * read loop in {@link FilterInputStream}, which can be inefficient for larger transfers.
   * Semantics match those of {@link InputStream#read(byte[], int, int)}.
   *
   * @param buf destination byte array which receives data; must not be {@code null}
   * @param offset start offset within {@code buf}; must be between {@code 0} and {@code buf.length}
   * @param length maximum number of bytes to read; clamped by remaining space in {@code buf}
   * @return the number of bytes read, or {@code -1} when the end of the stream is reached
   * @throws IOException if an I/O error occurs while reading from the underlying stream
   */
  @Override
  public int read(byte @NotNull [] buf, int offset, int length) throws IOException {
    // Necessary for efficiency, FilterInputStream pipes everything through "int read()".
    return in.read(buf, offset, length);
  }

  /**
   * Reads bytes into the entire array from the wrapped stream.
   *
   * <p>Equivalent to calling {@code read(buf, 0, buf.length)}. This method exists for convenience
   * and follows the standard {@link InputStream} contract regarding return values and exceptions.
   *
   * @param buf destination byte array to fill with data; must not be {@code null}
   * @return the number of bytes read, or {@code -1} when no more data is available
   * @throws IOException if an I/O error occurs while reading from the underlying stream
   */
  @Override
  public int read(byte @NotNull [] buf) throws IOException {
    return read(buf, 0, buf.length);
  }

  /**
   * Closes the wrapped stream and frees the associated bucket.
   *
   * <p>This method first closes the underlying {@link InputStream} and then calls {@link
   * Bucket#free()} on the source bucket to release any storage it owns. After this method returns,
   * the instance should be considered unusable for further I/O operations.
   *
   * @throws IOException if closing the underlying stream fails; freeing the bucket is still
   *     attempted
   */
  @Override
  public void close() throws IOException {
    in.close();
    data.free();
  }
}
