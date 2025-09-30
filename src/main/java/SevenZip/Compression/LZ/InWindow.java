// LZ.InWindow

package SevenZip.Compression.LZ;

import java.io.IOException;
import java.io.InputStream;

public class InWindow {
  // pointer to buffer with data
  protected byte[] bufferBase;
  InputStream stream;
  int posLimit; // offset (from buffer) of first byte when new block reading must be done

  /** When true, streamPos shows real end of stream. */
  boolean streamEndWasReached;

  int pointerToLastSafePosition;

  protected int bufferOffset;

  // Size of allocated memory block
  protected int blockSize;
  // offset (from buffer) of current byte
  protected int pos;
  int keepSizeBefore; // how many BYTEs must be kept in buffer before pos
  int keepSizeAfter; // how many BYTEs must be kept buffer after pos
  // offset (from buffer) of first not read byte from Stream
  protected int streamPos;

  public void moveBlock() {
    int offset = bufferOffset + pos - keepSizeBefore;
    // we need one additional byte, since MovePos moves on 1 byte.
    if (offset > 0) offset--;

    int numBytes = bufferOffset + streamPos - offset;

    // Copy existing data into the beginning of the buffer.
    for (int i = 0; i < numBytes; i++) bufferBase[i] = bufferBase[offset + i];
    bufferOffset -= offset;
  }

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

  public void setStream(InputStream stream) {
    this.stream = stream;
  }

  public void releaseStream() {
    stream = null;
  }

  public void init() throws IOException {
    bufferOffset = 0;
    pos = 0;
    streamPos = 0;
    streamEndWasReached = false;
    readBlock();
  }

  public void movePos() throws IOException {
    pos++;
    if (pos > posLimit) {
      int pointerToPostion = bufferOffset + pos;
      if (pointerToPostion > pointerToLastSafePosition) moveBlock();
      readBlock();
    }
  }

  public byte getIndexByte(int index) {
    return bufferBase[bufferOffset + pos + index];
  }

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

  public int getNumAvailableBytes() {
    return streamPos - pos;
  }

  public void reduceOffsets(int subValue) {
    bufferOffset += subValue;
    posLimit -= subValue;
    pos -= subValue;
    streamPos -= subValue;
  }
}
