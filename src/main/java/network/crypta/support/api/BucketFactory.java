package network.crypta.support.api;

import java.io.IOException;

/**
 * Factory for creating {@link RandomAccessBucket} instances.
 *
 * <p>Implementations may choose different storage backends (memory, disk, encrypted, etc.) and may
 * apply limits, buffering, or other policies internally. Unless otherwise documented, this
 * interface and the created buckets are not guaranteed to be thread-safe; coordinate access
 * externally.
 */
public interface BucketFactory {
  /**
   * Creates a new, empty random-access bucket.
   *
   * <p>The returned {@link RandomAccessBucket} supports reading and writing by position. The {@code
   * size} parameter acts as a hint or limit on the maximum number of bytes that may be written:
   *
   * <ul>
   *   <li>{@code size >= 0}: Implementations may enforce this as a hard limit and throw an {@link
   *       IOException} if writes would exceed it.
   *   <li>{@code size == -1} or {@code size == Long.MAX_VALUE}: Size is unknown/unspecified; the
   *       implementation may grow as needed within its own constraints.
   * </ul>
   *
   * <p>Callers are responsible for releasing resources by invoking {@link Bucket#free()} or closing
   * the bucket when finished.
   *
   * @param size maximum expected size in bytes, or {@code -1}/{@code Long.MAX_VALUE} if unknown
   * @return a new {@link RandomAccessBucket}, never {@code null}
   * @throws IOException if storage cannot be allocated, a limit is violated, or an I/O error occurs
   */
  RandomAccessBucket makeBucket(long size) throws IOException;
}
