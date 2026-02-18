package com.onionnetworks.io;

import java.io.*;

import org.jetbrains.annotations.NotNull;

/**
 * InputStream that concatenates two source streams, exposing them as one continuous sequence of
 * bytes. This wrapper first consumes the {@code first} stream until it reaches end of stream and
 * then transparently continues reading from the {@code second} stream. It is useful when callers
 * want to prepend small headers, trailers, or sentinel data without copying bytes into a temporary
 * buffer.
 *
 * <p>The class maintains a simple lifecycle: bytes are read from the first delegate, once an end of
 * stream is observed the internal delegate switches permanently to the second stream, and all
 * subsequent reads target that second stream. No buffering or background threads are introduced, so
 * performance and blocking semantics mirror the underlying sources.
 *
 * <p>Thread safety is not provided; callers should confine instances to a single thread or add
 * external synchronization when coordinating across threads. Closing this stream closes both
 * delegates, even if only partially consumed.
 *
 * <ul>
 *   <li>Reads occur strictly in the order provided: {@code first} then {@code second}.
 *   <li>No automatic rewind or reset is performed on either delegate.
 *   <li>Exceptions from either delegate propagate unchanged to the caller.
 * </ul>
 *
 * @see FilterInputStream
 * @see InputStream
 */
public final class JoiningInputStream extends FilterInputStream {

  InputStream first;
  InputStream second;

  /**
   * Creates a stream that sequentially exposes two underlying streams as a single, readable source.
   * The {@code first} stream is consumed entirely before the {@code second} stream is consulted.
   * Passing {@code null} for either argument is not permitted; doing so results in a {@link
   * NullPointerException}. The constructor does not wrap or buffer the delegates, so their original
   * blocking characteristics remain visible to callers.
   *
   * @param first the initial delegate stream to consume in full before switching; must be non-null
   *     and positioned at the desired starting offset when handed in
   * @param second the fallback delegate used once {@code first} signals end of stream; must be
   *     non-null and ready to read without further initialization
   */
  public JoiningInputStream(InputStream first, InputStream second) {
    super(first);
    if (first == null || second == null) {
      throw new NullPointerException();
    }
    this.first = first;
    this.second = second;
  }

  /**
   * Reads a single unsigned byte from the composite stream, advancing from {@code first} to {@code
   * second} automatically when the first stream is exhausted.
   *
   * <p>If both streams have no remaining data, {@code -1} is returned. This method allocates a
   * temporary one-byte buffer on each call; callers needing higher throughput should prefer the
   * array-based overload.
   *
   * @return the next byte value in the range {@code 0-255}, or {@code -1} when both streams are
   *     fully consumed
   * @throws IOException if an I/O error occurs while reading from either delegate stream
   */
  @Override
  public int read() throws IOException {
    byte[] b = new byte[1];
    if (read(b, 0, 1) == -1) {
      return -1;
    }
    return b[0] & 0xFF;
  }

  /**
   * Reads up to {@code len} bytes into the supplied buffer, switching from {@code first} to {@code
   * second} if the first stream reports end of stream for the current read operation.
   *
   * <p>The method may return fewer bytes than requested if the first stream ends mid-call or if the
   * second stream cannot immediately fill the request. Once {@code first} reports {@code -1}, all
   * later invocations target {@code second} exclusively. Partial reads follow the standard {@link
   * InputStream} contract and do not guarantee that {@code len} bytes are obtained.
   *
   * <pre>{@code
   * byte[] buffer = new byte[1024];
   * try (var joined = new JoiningInputStream(headStream, bodyStream)) {
   *   int read = joined.read(buffer, 0, buffer.length);
   * }
   * }</pre>
   *
   * @param b the destination array that receives bytes; must be non-null and large enough to hold
   *     the requested range
   * @param off the zero-based offset in {@code b} where bytes begin to be written; must be within
   *     the array bounds
   * @param len the maximum number of bytes to attempt to read; must be non-negative and not exceed
   *     the remaining space in {@code b}
   * @return number of bytes read (may be {@code 0} if {@code len} is zero) or {@code -1} when both
   *     underlying streams are fully consumed
   * @throws IOException if either delegate stream signals an I/O failure while servicing the read
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    int c = in.read(b, off, len);
    if (c == -1 && in == first) {
      in = second;
      return in.read(b, off, len);
    } else {
      return c;
    }
  }

  /**
   * Closes both delegate streams in declaration order. Once invoked, subsequent read operations on
   * this instance or the underlying streams are expected to fail per the standard {@link
   * InputStream} contract. This method propagates any {@link IOException} thrown by either close
   * operation.
   *
   * @throws IOException if closing the first or second delegate reports an error condition
   */
  @Override
  public void close() throws IOException {
    first.close();
    second.close();
  }
}
