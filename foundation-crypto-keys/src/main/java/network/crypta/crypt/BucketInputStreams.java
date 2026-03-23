package network.crypta.crypt;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * Creates input-stream views over {@link Bucket} instances for crypt-layer consumers.
 *
 * <p>The helper mirrors the long-lived client-side bucket wrapper, but keeps the ownership and
 * cleanup behavior inside {@code network.crypta.crypt}. Callers obtain a conventional {@link
 * InputStream} over bucket contents while the wrapper takes responsibility for releasing the bucket
 * when the stream is closed, which reduces leak-prone manual cleanup at checksum and decryption
 * call sites.
 *
 * <p>This class does not change bucket semantics. It only centralizes a common lifecycle pattern:
 * open the bucket stream once, read through the wrapper, then close the wrapper so the underlying
 * bucket is freed exactly at the point the caller is done with the bytes.
 */
public final class BucketInputStreams {

  /** Prevents instantiation of this stream-wrapping utility. */
  private BucketInputStreams() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Opens the bucket's input stream and frees the bucket when the returned stream is closed.
   *
   * <p>The returned wrapper reads directly from {@link Bucket#getInputStream()} and adds only the
   * cleanup policy. Callers should use the wrapper in a try-with-resources block and should not
   * attempt to free the bucket separately after the stream has been handed off here.
   *
   * @param bucket source bucket whose contents should be exposed as a stream
   * @return stream over the bucket contents that frees the bucket on successful close
   * @throws IOException if the bucket cannot provide an input stream for reading
   */
  public static InputStream openAndFreeOnClose(Bucket bucket) throws IOException {
    return new ReadBucketAndFreeInputStream(bucket.getInputStream(), bucket);
  }

  /** Stream wrapper that couples bucket reads with bucket cleanup on close. */
  private static final class ReadBucketAndFreeInputStream extends FilterInputStream {

    /** Bucket to free after the wrapped stream closes successfully. */
    private final Bucket bucket;

    /**
     * Creates a wrapper around an already-open bucket stream.
     *
     * @param in underlying stream returned by the bucket
     * @param bucket bucket that owns the underlying stream contents
     */
    private ReadBucketAndFreeInputStream(InputStream in, Bucket bucket) {
      super(in);
      this.bucket = bucket;
    }

    /**
     * Reads bytes into a portion of the array from the wrapped stream.
     *
     * <p>This override forwards directly to the underlying stream to avoid the default single-byte
     * read loop in {@link FilterInputStream}, which can be inefficient for larger transfers.
     *
     * @param buf destination byte array which receives data; must not be {@code null}
     * @param offset start offset within {@code buf}
     * @param length maximum number of bytes to read
     * @return the number of bytes read, or {@code -1} at end of stream
     * @throws IOException if an I/O error occurs while reading from the underlying stream
     */
    @Override
    public int read(byte @NotNull [] buf, int offset, int length) throws IOException {
      return in.read(buf, offset, length);
    }

    /**
     * Reads bytes into the entire array from the wrapped stream.
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
     * <p>The implementation closes the underlying stream first and frees the bucket only after that
     * close succeeds. If stream closure fails, the {@link IOException} is propagated and the bucket
     * is left untouched so callers do not silently lose the original close failure.
     *
     * @throws IOException if closing the underlying stream fails
     */
    @Override
    public void close() throws IOException {
      in.close();
      bucket.free();
    }
  }
}
