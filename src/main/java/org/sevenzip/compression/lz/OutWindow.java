// LZ.OutWindow

package org.sevenzip.compression.lz;

import java.io.IOException;
import java.io.OutputStream;

public class OutWindow {
  byte[] buffer;
  int pos;
  int windowSize = 0;
  int streamPos;
  OutputStream stream;

  public void create(int windowSize) {
    if (buffer == null || this.windowSize != windowSize) buffer = new byte[windowSize];
    this.windowSize = windowSize;
    pos = 0;
    streamPos = 0;
  }

  public void setStream(OutputStream stream) throws IOException {
    releaseStream();
    this.stream = stream;
  }

  public void releaseStream() throws IOException {
    flush();
    stream = null;
  }

  public void init(boolean solid) {
    if (!solid) {
      streamPos = 0;
      pos = 0;
    }
  }

  public void flush() throws IOException {
    int size = pos - streamPos;
    if (size == 0) return;
    stream.write(buffer, streamPos, size);
    if (pos >= windowSize) pos = 0;
    streamPos = pos;
  }

  public void copyBlock(int distance, int len) throws IOException {
    int srcPos = pos - distance - 1;
    if (srcPos < 0) srcPos += windowSize;
    for (; len != 0; len--) {
      if (srcPos >= windowSize) srcPos = 0;
      buffer[pos++] = buffer[srcPos++];
      if (pos >= windowSize) flush();
    }
  }

  public void putByte(byte b) throws IOException {
    buffer[pos++] = b;
    if (pos >= windowSize) flush();
  }

  public byte getByte(int distance) {
    int srcPos = pos - distance - 1;
    if (srcPos < 0) srcPos += windowSize;
    return buffer[srcPos];
  }
}
