// LZ.InWindow

package org.sevenzip.compression.lz;

import java.io.IOException;
import java.io.InputStream;

/**
 * Sliding window reader that maintains an in-memory buffer backed by a sequential {@link
 * InputStream}. The window supports efficient byte lookups and backward distance comparisons needed
 * by LZ-style encoders without repeatedly reading from the underlying stream. Clients configure
 * keep-size bands around the current position, initialize the buffer, then advance with {@link
 * #movePos()} while querying bytes via {@link #getIndexByte(int)} or match lengths via {@link
 * #getMatchLen(int, int, int)}. The buffer slides forward automatically when the current position
 * approaches the end of the safe area, copying preserved bytes and fetching fresh data from the
 * stream. Instances are mutable and not thread-safe; callers should confine each instance to a
 * single encoding workflow. Typical usage: create the window with target sizes, attach an input
 * stream, call {@link #init()}, then iterate move/inspect operations until no bytes remain.
 */
public class InWindow {

  /**
   * Creates a new, uninitialized window. The buffer is allocated later via {@link #create(int, int,
   * int)} and populated by {@link #init()} once a stream has been set.
   */
  public InWindow() {
    // Intentionally empty: buffer allocation and stream wiring are deferred to create()/init().
  }

  // pointer to buffer with data
  /**
   * Backing array that stores the current sliding window contents. The buffer length is determined
   * by {@link #create(int, int, int)} and reused across moves; callers should treat its contents as
   * owned by this instance and avoid external mutations while the window is in use.
   */
  protected byte[] bufferBase;

  InputStream stream;
  int posLimit; // offset (from buffer) of first byte when new block reading must be done

  /** When true, streamPos shows real end of stream. */
  boolean streamEndWasReached;

  int pointerToLastSafePosition;

  /**
   * Offset into {@link #bufferBase} where the active window currently begins. The value shifts when
   * blocks are moved to keep headroom for future reads and remains non-negative while the buffer is
   * valid.
   */
  protected int bufferOffset;

  // Size of allocated memory block
  /**
   * Total size, in bytes, of the allocated buffer. This equals {@code keepSizeBefore +
   * keepSizeAfter + keepSizeReserv} from the most recent {@link #create(int, int, int)} call and is
   * used to cap sliding and read operations.
   */
  protected int blockSize;

  // offset (from buffer) of current byte
  /**
   * Current logical position within the sliding window, expressed relative to {@link #bufferBase}
   * and adjusted by {@link #bufferOffset}. It advances monotonically via {@link #movePos()} during
   * a read session.
   */
  protected int pos;

  int keepSizeBefore; // how many BYTEs must be kept in buffer before pos
  int keepSizeAfter; // how many BYTEs must be kept buffer after pos

  // offset (from buffer) of first not read byte from Stream
  /**
   * Index in {@link #bufferBase} where the next unread byte from the stream would be placed. The
   * value grows with successful reads and shrinks when offsets are reduced after a block move.
   */
  protected int streamPos;

  /**
   * Relocates buffered data toward the start of the array when the current position approaches the
   * end of the safe region. The method preserves {@code keepSizeBefore} bytes before the current
   * position, shifts the active window, and updates {@link #bufferOffset}. No bytes are read from
   * the stream during this operation.
   */
  public void moveBlock() {
    int offset = bufferOffset + pos - keepSizeBefore;
    // we need one additional byte, since MovePos moves on 1 byte.
    if (offset > 0) offset--;

    int numBytes = bufferOffset + streamPos - offset;

    // Copy existing data into the beginning of the buffer.
    for (int i = 0; i < numBytes; i++) bufferBase[i] = bufferBase[offset + i];
    bufferOffset -= offset;
  }

  /**
   * Fills the buffer with additional bytes from the attached {@link InputStream} until either the
   * post-position keep area is satisfied or the stream ends. The method respects the configured
   * block size, updates {@link #posLimit}, and marks {@link #streamEndWasReached} when no more data
   * is available.
   *
   * @throws IOException if the underlying stream read fails or is interrupted while populating the
   *     buffer.
   */
  public void readBlock() throws IOException {
    if (streamEndWasReached) return;
    while (true) {
      int size = -bufferOffset + blockSize - streamPos;
      if (size == 0) return;
      int numReadBytes = stream.read(bufferBase, bufferOffset + streamPos, size);
      if (numReadBytes == -1) {
        posLimit = streamPos;
        int pointerToPostion = bufferOffset + posLimit;
        if (pointerToPostion > pointerToLastSafePosition)
          posLimit = pointerToLastSafePosition - bufferOffset;

        streamEndWasReached = true;
        return;
      }
      streamPos += numReadBytes;
      if (streamPos >= pos + keepSizeAfter) posLimit = streamPos - keepSizeAfter;
    }
  }

  void free() {
    bufferBase = null;
  }

  /**
   * Allocates or reuses the internal buffer with bands sized for look-behind and look-ahead
   * preservation. Existing buffers are discarded if their size differs from the requested total.
   * The caller must subsequently provide a stream and call {@link #init()} before reading.
   *
   * @param keepSizeBefore number of bytes before the current position that must remain available
   *     for back-reference comparisons; must be non-negative.
   * @param keepSizeAfter number of bytes after the current position to retain for look-ahead during
   *     matching; must be non-negative.
   * @param keepSizeReserv additional reserved capacity to reduce frequent moves during long runs;
   *     must be non-negative.
   */
  public void create(int keepSizeBefore, int keepSizeAfter, int keepSizeReserv) {
    this.keepSizeBefore = keepSizeBefore;
    this.keepSizeAfter = keepSizeAfter;
    int newBlockSize = keepSizeBefore + keepSizeAfter + keepSizeReserv;
    if (bufferBase == null || blockSize != newBlockSize) {
      free();
      blockSize = newBlockSize;
      bufferBase = new byte[blockSize];
    }
    pointerToLastSafePosition = blockSize - keepSizeAfter;
  }

  /**
   * Assigns the input source that supplies bytes for subsequent {@link #readBlock()} operations.
   * This method does not advance or read from the stream; clients typically set the stream, then
   * call {@link #init()} to populate the buffer.
   *
   * @param stream input source providing sequential bytes; must not be {@code null} for reading to
   *     succeed.
   */
  public void setStream(InputStream stream) {
    this.stream = stream;
  }

  /**
   * Clears the reference to the current input stream. No buffering state is reset; callers can use
   * this as a cleanup step after finishing reads or before attaching a different stream instance.
   */
  public void releaseStream() {
    stream = null;
  }

  /**
   * Resets buffer pointers and populates the window with an initial read from the configured
   * stream. After initialization, {@link #pos} is zero, the stream position reflects the number of
   * bytes read, and {@link #posLimit} is set to the earliest point where further reads are needed.
   *
   * @throws IOException if reading from the configured stream fails during initialization.
   */
  public void init() throws IOException {
    bufferOffset = 0;
    pos = 0;
    streamPos = 0;
    streamEndWasReached = false;
    readBlock();
  }

  /**
   * Advances the current position by one byte, sliding the window when necessary and pulling more
   * data from the stream. If the movement approaches the last safe position, the buffer content is
   * shifted via {@link #moveBlock()} before additional bytes are read.
   *
   * @throws IOException if the underlying stream cannot supply bytes while filling the buffer after
   *     the move.
   */
  public void movePos() throws IOException {
    pos++;
    if (pos > posLimit) {
      int pointerToPostion = bufferOffset + pos;
      if (pointerToPostion > pointerToLastSafePosition) moveBlock();
      readBlock();
    }
  }

  /**
   * Returns the byte located at a relative offset from the current position within the buffer.
   * Callers should ensure the requested index remains within the available window bounds to avoid
   * undefined behavior.
   *
   * @param index zero-based offset from the current position; may be negative for look-behind
   *     access and should not exceed the number of buffered bytes ahead.
   * @return byte value stored at {@code pos + index} inside the active buffer window.
   */
  public byte getIndexByte(int index) {
    return bufferBase[bufferOffset + pos + index];
  }

  /**
   * Computes the length of the longest match between data at the current position and data at a
   * prior distance. The search respects the provided limit and clamps to the end-of-stream boundary
   * if the stream is exhausted. Matching stops on the first differing byte.
   *
   * @param index offset from the current position where comparison starts; may be zero or positive
   *     depending on caller needs.
   * @param distance backward distance, in bytes, from the comparison start to the reference
   *     position; must be non-negative.
   * @param limit maximum number of bytes to compare; adjusted internally when past the end of the
   *     stream.
   * @return number of consecutive bytes that match between the two regions, never exceeding the
   *     provided limit.
   */
  public int getMatchLen(int index, int distance, int limit) {
    if (streamEndWasReached && (pos + index) + limit > streamPos) limit = streamPos - (pos + index);
    distance++;
    int pby = bufferOffset + pos + index;

    int i;
    i = 0;
    while (i < limit && bufferBase[pby + i] == bufferBase[pby + i - distance]) {
      i++;
    }
    return i;
  }

  /**
   * Reports how many buffered bytes remain available from the current position to the end of the
   * data read so far. The count shrinks as the caller advances and grows when additional data is
   * read from the stream.
   *
   * @return non-negative number of bytes that can be consumed without triggering another stream
   *     read.
   */
  public int getNumAvailableBytes() {
    return streamPos - pos;
  }

  /**
   * Decrements all internal position trackers by the supplied value to reflect a logical shift in
   * buffer indexing. This is typically used after a move to realign absolute offsets while keeping
   * buffer contents intact.
   *
   * @param subValue number of bytes to subtract from buffer-related offsets; must be non-negative
   *     and should not exceed current pointer values.
   */
  public void reduceOffsets(int subValue) {
    bufferOffset += subValue;
    posLimit -= subValue;
    pos -= subValue;
    streamPos -= subValue;
  }
}
