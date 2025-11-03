package network.crypta.client.async;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An abstraction for producing a sequential byte stream from an underlying data structure.
 *
 * <p>Implementations encapsulate how content is serialized and written, allowing callers to request
 * the bytes via {@link #writeTo(OutputStream, ClientContext)} without coupling to the storage
 * layout or generation strategy. Typical usage is to obtain a concrete {@code StreamGenerator} from
 * a client component and then write it to a destination stream such as a network socket, file, or
 * in-memory buffer. The generator can represent a single file, a stitched set of segments, or other
 * logical content.
 *
 * <p>Lifecycle and concurrency: instances are generally single-use and not required to be
 * thread-safe. Callers should not invoke {@code writeTo} concurrently from multiple threads. The
 * {@link #size()} is intended for progress reporting and integrity checks and should match the
 * number of bytes emitted on a successful write.
 *
 * <p>Stream ownership: whether {@code writeTo} closes the provided {@link OutputStream} is
 * implementation-defined. Some implementations close the stream when finished while others leave it
 * open; callers must not assume either behavior and should manage the stream lifecycle accordingly
 * (for example, by using try-with-resources around the destination when appropriate).
 *
 * @see SingleFileStreamGenerator
 * @see ClientContext
 */
public interface StreamGenerator {

  /**
   * Writes the serialized content to the supplied {@link OutputStream} using the given context.
   *
   * <p>The method writes exactly {@link #size()} bytes when it completes successfully. It may
   * buffer internally and can block until all data is produced. Implementations may or may not
   * close the provided stream on completion; callers must not rely on a particular closing policy
   * and should ensure the destination is eventually flushed and closed as appropriate for their use
   * case. This operation is not guaranteed to be idempotent.
   *
   * <pre>{@code
   * // Example: write to a byte array
   * var baos = new java.io.ByteArrayOutputStream();
   * generator.writeTo(baos, clientContext);
   * byte[] bytes = baos.toByteArray();
   * }</pre>
   *
   * @param os the destination stream to receive bytes; must be writable and non-null; bytes are
   *     written starting at its current position; implementation may or may not close it
   * @param context the non-null execution context used by implementations to access shared client
   *     services, accounting, or configuration relevant to generation
   * @throws IOException if an I/O error occurs while writing; the destination may contain partially
   *     written data and should be treated as incomplete
   */
  void writeTo(OutputStream os, ClientContext context) throws IOException;

  /**
   * Returns the total number of bytes this generator will emit when written successfully.
   *
   * <p>The value represents the logical content length of the underlying structure that {@link
   * #writeTo(OutputStream, ClientContext)} will produce. Callers typically use it for capacity
   * planning or progress reporting and may validate that the number of bytes observed on output
   * matches this value after a successful write.
   *
   * @return the exact content length in bytes expected to be produced by {@code writeTo} on a
   *     successful run; always non-negative
   */
  long size();
}
