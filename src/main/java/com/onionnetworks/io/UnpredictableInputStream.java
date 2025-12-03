package com.onionnetworks.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Logger;
import org.jetbrains.annotations.NotNull;

/**
 * Input stream wrapper that deliberately returns fewer bytes than requested to emulate unstable
 * network or disk behavior.
 *
 * <p>This stream randomizes the size of each read or skip operation so client code experiences
 * partial progress, zero-length reads, and short skips in a controlled yet repeatable manner. It is
 * intended for test harnesses and integration scenarios where consumer logic must tolerate
 * incomplete transfers, retry loops, or other real-world I/O quirks instead of relying on idealized
 * blocking semantics. The wrapped stream remains the single source of data; this class only
 * perturbs how much of that data is exposed at a time.
 *
 * <p>Usage guidance:
 *
 * <ul>
 *   <li>Wrap any {@link InputStream} used in tests to validate incremental buffering logic.
 *   <li>Expect occasional zero-byte reads or skips; callers should handle them as transient.
 *   <li>Closing this stream closes the underlying source and halts further randomization.
 * </ul>
 *
 * <p>Instances are mutable and not thread-safe; coordinate access externally when sharing across
 * threads to avoid interleaved randomness. Randomness is provided by a {@link SecureRandom}
 * instance and therefore does not repeat across JVM runs unless externally seeded.
 *
 * @author Justin F. Chapweske
 */
public class UnpredictableInputStream extends FilterInputStream {

  private static final Logger LOGGER = Logger.getLogger(UnpredictableInputStream.class.getName());

  Random rand = new SecureRandom();
  private boolean closed;

  /**
   * Creates a new unpredictable wrapper around the provided source stream.
   *
   * <p>The wrapper does not buffer or transform data; it only randomizes how many bytes are made
   * visible per operation. Callers remain responsible for closing the stream when finished.
   *
   * @param is the underlying {@link InputStream} that supplies bytes without internal buffering;
   *     must not be {@code null} and remains owned by the caller.
   */
  public UnpredictableInputStream(InputStream is) {
    super(is);
  }

  /**
   * Closes this stream and its wrapped source, preventing further randomized I/O operations.
   *
   * <p>Subsequent read or skip requests will fail with an {@link IOException}. The close request is
   * idempotent with respect to the {@link FilterInputStream} contract; multiple calls delegate to
   * the underlying stream only once.
   *
   * @throws IOException if the underlying stream reports an error while closing resources.
   */
  @Override
  public void close() throws IOException {
    closed = true;
    super.close();
  }

  /**
   * Attempts to skip a randomized number of bytes up to the caller-supplied limit.
   *
   * <p>The method may legitimately return zero even when the stream is open to mimic slow or
   * stalled transports. When a positive value is returned, it will not exceed {@code n} and is
   * chosen to bias toward shorter skips, exposing caller logic that assumes large forward progress.
   *
   * @param n maximum number of bytes the caller is willing to skip; negative values are rejected by
   *     the superclass implementation.
   * @return number of bytes actually skipped; may be zero without indicating end-of-stream
   *     exhaustion.
   * @throws IOException if the stream has been closed or if the underlying skip operation fails.
   */
  @Override
  public long skip(long n) throws IOException {
    if (closed) {
      throw new IOException("Stream closed");
    }
    // We use nextInt rather than nextLong to ensure equal distribution
    // across the possible bytes so that we're consistently skipping
    // less than n bytes.
    // (int) cast is safe due to min(int,long)
    if (rand.nextInt(5) == 0) {
      // Return 0 length skips quite often for testing implementations.
      return 0;
    }
    LOGGER.fine("skip!");
    return super.skip(rand.nextInt((int) Math.min(Integer.MAX_VALUE, n + 1)));
  }

  /**
   * Reads into the provided buffer, looping until at least one byte is produced or the stream
   * closes.
   *
   * <p>This method respects the {@link InputStream#read(byte[])} contract by blocking until data is
   * available. It delegates to the three-argument {@link #read(byte[], int, int)} method and
   * transparently retries zero-length results to surface only meaningful progress to callers.
   *
   * @param b destination buffer that receives bytes; length must be non-negative and determines the
   *     maximum read size.
   * @return number of bytes read, guaranteed to be greater than zero unless {@code b.length == 0}
   *     or the end of the stream is reached.
   * @throws IOException if an I/O error occurs while reading from the wrapped stream.
   */
  @Override
  public int read(byte @NotNull [] b) throws IOException {
    if (closed) {
      throw new IOException("Stream closed");
    }
    // This method must block until data is available, thus we will
    // keep reading on a 0 byte result.
    if (b.length == 0) {
      return 0;
    }
    int c;
    do {
      c = read(b, 0, b.length);
      // keep trying until data is available
    } while (c == 0);
    return c;
  }

  /**
   * Performs a single randomized read into a caller-provided slice of the buffer.
   *
   * <p>Each invocation chooses a length between zero and {@code len} (inclusive) to stress client
   * code that assumes full-length reads. A zero result indicates that no bytes were produced yet
   * and does not signal end-of-stream. The method honors the specified offset and length without
   * expanding the accessible region of the destination array.
   *
   * @param b byte array that receives data starting at {@code off}; must be non-null and large
   *     enough for {@code len} bytes.
   * @param off zero-based index inside {@code b} where writing begins; must satisfy standard {@link
   *     InputStream} bounds rules.
   * @param len maximum number of bytes to attempt to read; values above the buffer remainder are
   *     invalid and result in {@link IndexOutOfBoundsException} from the superclass.
   * @return number of bytes read, which may legitimately be zero without indicating end-of-stream.
   * @throws IOException if the underlying stream fails or if it rejects the provided bounds.
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    if (closed) {
      throw new IOException("Stream closed");
    }
    // Even though FilterInputStream's JavaDoc claims that this method
    // must block until data is available, the current FilterInputStream
    // implementation doesn't even enforce that.
    if (rand.nextInt(5) == 0) {
      // Return 0 length reads quite often for testing implementations.
      return super.read(b, off, 0);
    }
    return super.read(b, off, rand.nextInt(len + 1));
  }
}
