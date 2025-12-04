package org.sevenzip.compression.lz;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Sliding output buffer used by the LZ decoder to materialize decompressed bytes while reusing a
 * fixed-size window.
 *
 * <p>The window maintains an in-memory ring buffer that mirrors LZ77-style back-references. Clients
 * typically call {@link #create(int)} to size the buffer, {@link #setStream(OutputStream)} to
 * attach a destination, and then interleave {@link #putByte(byte)}, {@link #copyBlock(int, int)},
 * and {@link #flush()} as decoded symbols arrive. The window advances automatically, wrapping at
 * the configured size so distance references resolve correctly even across flush boundaries.
 *
 * <p>State is mutable and not thread-safe; callers should confine each instance to a single
 * decoding pipeline. Reusing the same instance across streams is supported through {@link
 * #init(boolean)} and {@link #releaseStream()}, enabling long-running decoders to amortize buffer
 * allocation while still emitting bytes promptly to the underlying {@link OutputStream}.
 *
 * <ul>
 *   <li>Maintains positional invariants for distance-based copies.
 *   <li>Flushes lazily when the window fills to minimize write calls.
 *   <li>Requires explicit lifecycle coordination by the decoder that drives it.
 * </ul>
 */
public class OutWindow {
  byte[] buffer;
  int pos;
  int windowSize = 0;
  int streamPos;
  OutputStream stream;

  /**
   * Creates a new out window with no stream attached and zeroed cursors.
   *
   * <p>The constructor leaves allocation deferred until {@link #create(int)} is called, ensuring
   * that callers can select an appropriate window size before any buffer is allocated. The initial
   * state has all indices at zero and {@code stream} set to {@code null}, making the instance ready
   * for configuration within a decoder pipeline.
   */
  public OutWindow() {
    // No-op: buffer allocation and cursor resets are deferred to create(int) to let callers choose
    // the correct window size for their decoding parameters.
  }

  /**
   * Allocates or reuses the backing buffer and resets write positions to the start of the window.
   *
   * <p>If the existing buffer size differs from {@code windowSize}, a new array is allocated;
   * otherwise the current buffer is reused. After calling this method, both the current position
   * and the last-flushed pointer are set to zero so the next writes begin at the start of the ring.
   * The caller is responsible for ensuring a compatible size with any subsequent distance
   * references.
   *
   * @param windowSize desired window capacity in bytes; must be positive and consistent with LZ
   *     distance limits.
   */
  public void create(int windowSize) {
    if (buffer == null || this.windowSize != windowSize) buffer = new byte[windowSize];
    this.windowSize = windowSize;
    pos = 0;
    streamPos = 0;
  }

  /**
   * Attaches the destination stream, flushing and detaching any previously assigned stream first.
   *
   * <p>The method preserves buffered data by invoking {@link #releaseStream()} before switching the
   * target. After a successful call the window continues writing from its current position, and
   * callers should ensure {@link #create(int)} has been invoked to define buffer capacity prior to
   * writing. The provided stream must remain open for the duration of subsequent writes.
   *
   * @param stream output target that receives flushed window contents; must not be {@code null}.
   * @throws IOException if flushing the prior stream fails while detaching it.
   */
  public void setStream(OutputStream stream) throws IOException {
    releaseStream();
    this.stream = stream;
  }

  /**
   * Flushes any pending bytes to the current stream and detaches it from this window.
   *
   * <p>The method is idempotent with respect to multiple invocations and leaves the buffer contents
   * intact so decoding can resume after a new stream is attached. No attempt is made to close the
   * underlying stream; ownership remains with the caller.
   *
   * @throws IOException if the buffered data cannot be written to the current stream.
   */
  public void releaseStream() throws IOException {
    flush();
    stream = null;
  }

  /**
   * Resets window positions optionally preserving already buffered data for solid decoding phases.
   *
   * <p>When {@code solid} is {@code false}, both the last-flushed marker and the current write
   * position are reset to zero, effectively discarding positional history for subsequent
   * back-references. When {@code solid} is {@code true}, positions remain unchanged, allowing
   * multipart compressed streams to share the same window state.
   *
   * @param solid whether to retain the current window content and positional history across calls.
   */
  public void init(boolean solid) {
    if (!solid) {
      streamPos = 0;
      pos = 0;
    }
  }

  /**
   * Writes any bytes accumulated since the last flush to the attached stream and updates pointers.
   *
   * <p>If no new bytes were written, the method returns immediately. When data is present, it
   * writes the contiguous range between {@code streamPos} and {@code pos}. If the write boundary
   * coincides with the end of the ring buffer, the current position is wrapped to zero to keep
   * subsequent inserts in range.
   *
   * @throws IOException if the write to the underlying stream fails.
   */
  public void flush() throws IOException {
    int size = pos - streamPos;
    if (size == 0) return;
    stream.write(buffer, streamPos, size);
    if (pos >= windowSize) pos = 0;
    streamPos = pos;
  }

  /**
   * Copies a previously emitted sequence from the window into the current position, flushing as
   * needed.
   *
   * <p>The method calculates a source pointer at {@code distance + 1} bytes before the current
   * position, wrapping around the ring buffer when negative. Bytes are copied one by one for {@code
   * len} iterations, flushing the window whenever the write cursor reaches the configured capacity.
   * Callers must ensure that {@code distance} does not exceed the initialized window size; no
   * explicit validation is performed here.
   *
   * @param distance zero-based distance from the byte immediately before the current position; must
   *     be less than the window size to remain valid.
   * @param len number of bytes to duplicate from the calculated source region into the window.
   * @throws IOException if a flush triggered during copying cannot write to the stream.
   */
  public void copyBlock(int distance, int len) throws IOException {
    int srcPos = pos - distance - 1;
    if (srcPos < 0) srcPos += windowSize;
    for (; len != 0; len--) {
      if (srcPos >= windowSize) srcPos = 0;
      buffer[pos++] = buffer[srcPos++];
      if (pos >= windowSize) flush();
    }
  }

  /**
   * Appends a single byte to the window and flushes automatically when the buffer fills.
   *
   * <p>The byte is written at the current cursor position and the position advances by one.
   * Reaching the end of the window triggers an implicit {@link #flush()} so the stream receives the
   * buffered data promptly while keeping the ring indices valid for future distance references.
   *
   * @param b value to store at the current position; all byte values are accepted as-is.
   * @throws IOException if the automatic flush fails to write to the underlying stream.
   */
  public void putByte(byte b) throws IOException {
    buffer[pos++] = b;
    if (pos >= windowSize) flush();
  }

  /**
   * Retrieves a previously written byte by distance without modifying window state.
   *
   * <p>The method computes a source position {@code distance + 1} bytes behind the current cursor,
   * wrapping around the ring buffer if necessary. The buffer contents are left unchanged so callers
   * can perform lookups while constructing new output without affecting subsequent writes.
   *
   * @param distance zero-based distance from the prior byte; must be within the current window.
   * @return byte value located at the resolved position; ownership remains with the internal
   *     buffer.
   */
  public byte getByte(int distance) {
    int srcPos = pos - distance - 1;
    if (srcPos < 0) srcPos += windowSize;
    return buffer[srcPos];
  }
}
