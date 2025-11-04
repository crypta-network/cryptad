package network.crypta.client.async;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Streams the content of a {@link Bucket} to a caller-provided {@link OutputStream}.
 *
 * <p>This generator adapts a single {@link Bucket} into a sequential byte stream written to an
 * external sink. Typical usage is to serialize a temporary file or in-memory buffer to a network
 * socket, HTTP response, or another file without loading the entire payload into memory. The class
 * holds a reference to the source bucket and performs a straight copy from the bucket's input
 * stream to the destination output stream.
 *
 * <p>Resource management is explicit and deterministic: both the provided output stream and the
 * underlying bucket are closed via try-with-resources when streaming finishes or an error occurs.
 * This behavior makes the generator suitable for large files since copying is forward-only and does
 * not require additional buffering beyond what the underlying streams perform. The total number of
 * bytes available is exposed via {@link #size()}, which mirrors {@link Bucket#size()}.
 *
 * <ul>
 *   <li><strong>Thread-safety:</strong> instances are not guaranteed to be thread-safe; use them
 *       from a single thread or provide external synchronization.
 *   <li><strong>Mutability:</strong> the referenced bucket is final; its lifecycle ends when {@link
 *       #writeTo(OutputStream, ClientContext)} closes it, unless callers keep their own handle that
 *       outlives this generator.
 *   <li><strong>Error handling:</strong> {@link IOException} values are propagated; other
 *       exceptions are wrapped into an {@code IOException} with a stable message.
 * </ul>
 *
 * @see StreamGenerator
 * @see Bucket
 * @see FileUtil
 */
public class SingleFileStreamGenerator implements StreamGenerator {
  private static final Logger LOG = LoggerFactory.getLogger(SingleFileStreamGenerator.class);

  private final Bucket bucket;

  /**
   * Creates a generator that streams from the given bucket.
   *
   * <p>The {@code persistent} argument is informational and may be useful to calling code for
   * diagnostics or policy decisions; it does not alter this class's behavior.
   *
   * @param bucket the source of bytes to stream; must remain valid until {@link
   *     #writeTo(OutputStream, ClientContext)} completes
   * @param persistent indicates whether the bucket originates from a persistence-aware context;
   *     used for logging only
   */
  SingleFileStreamGenerator(Bucket bucket, boolean persistent) {
    this.bucket = bucket;
    // Parameter is currently informational; include in debug logs to preserve intent.
    if (LOG.isDebugEnabled()) {
      LOG.debug("SingleFileStreamGenerator created (persistent={})", persistent);
    }
  }

  /**
   * Writes the bucket's content to the specified output stream and closes both.
   *
   * <p>The method obtains an {@link InputStream} from the underlying {@link Bucket} and copies all
   * bytes to the provided {@link OutputStream} using {@link FileUtil#copy(InputStream,
   * OutputStream, long)}. On normal completion or on failure, it closes the output stream and the
   * bucket via try-with-resources. If the bucket yields a {@code null} input stream (indicating no
   * data), an {@link IOException} is thrown. The operation is not idempotent with respect to the
   * destination; callers should ensure the target can be written exactly once or can tolerate
   * partial data if an error occurs mid-stream.
   *
   * <pre>{@code
   * // Example: write bucket to an HTTP response output stream
   * StreamGenerator gen = new SingleFileStreamGenerator(bucket, false);
   * gen.writeTo(responseOutputStream, clientContext);
   * }</pre>
   *
   * @param os destination that receives the streamed bytes; not {@code null}; closed by this method
   * @param context execution context available to higher layers; not {@code null}; not directly
   *     used by this implementation
   * @throws IOException if opening the bucket stream fails, if copying fails, or when the bucket
   *     provides no data and the stream cannot be produced
   */
  @Override
  public void writeTo(OutputStream os, ClientContext context) throws IOException {
    // Close the provided OutputStream and this bucket when done.
    // Java's try-with-resources requires local variables or parameters; reference the field via a
    // local resource to ensure it is closed.
    try (OutputStream managedOs = os;
        Bucket managedBucket = this.bucket) {
      if (LOG.isDebugEnabled()) LOG.debug("Generating Stream");
      try (InputStream data = managedBucket.getInputStream()) {
        FileUtil.copy(data, managedOs, -1);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Stream completely generated");
    } catch (Exception e) {
      if (e instanceof IOException exception) {
        throw exception;
      } else {
        throw new IOException("Error during stream generation", e);
      }
    }
  }

  /**
   * Returns the number of bytes currently available to stream from the bucket.
   *
   * <p>This value is delegated from {@link Bucket#size()} and reflects the bucket's size at the
   * time of invocation. Implementations may compute the size eagerly or lazily; callers should
   * treat it as advisory when the bucket's content can change concurrently from outside this
   * generator. The result is suitable for progress reporting, pre-allocation, or content-length
   * metadata.
   *
   * @return the byte length reported by the underlying bucket; {@code 0} when the bucket is empty
   */
  @Override
  public long size() {
    return bucket.size();
  }
}
