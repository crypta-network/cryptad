package org.sevenzip;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;

public class LzmaBench {
  private LzmaBench() {}

  static final int K_ADDITIONAL_SIZE = (1 << 21);
  static final int K_COMPRESSED_ADDITIONAL_SIZE = (1 << 10);

  static class CRandomGenerator {
    int a1;
    int a2;

    public CRandomGenerator() {
      init();
    }

    public void init() {
      a1 = 362436069;
      a2 = 521288629;
    }

    public int getRnd() {
      a1 = 36969 * (a1 & 0xffff) + (a1 >>> 16);
      int left = a1 << 16;
      a2 = 18000 * (a2 & 0xffff) + (a2 >>> 16);
      int right = a2;
      return left ^ right;
    }
  }

  static class CBitRandomGenerator {
    CRandomGenerator rg = new CRandomGenerator();
    int value;
    int numBits;

    public void init() {
      value = 0;
      numBits = 0;
    }

    public int getRnd(int numBits) {
      int result;
      if (this.numBits > numBits) {
        result = value & ((1 << numBits) - 1);
        value >>>= numBits;
        this.numBits -= numBits;
        return result;
      }
      numBits -= this.numBits;
      result = (value << numBits);
      value = rg.getRnd();
      result |= value & ((1 << numBits) - 1);
      value >>>= numBits;
      this.numBits = 32 - numBits;
      return result;
    }
  }

  static class CBenchRandomGenerator {
    CBitRandomGenerator rg = new CBitRandomGenerator();
    int pos;
    int rep0;

    int bufferSize;
    byte[] buffer = null;

    public CBenchRandomGenerator() {
      // Intentionally empty: lazily configured via set(bufferSize)
    }

    public void set(int bufferSize) {
      buffer = new byte[bufferSize];
      pos = 0;
      this.bufferSize = bufferSize;
    }

    int getRndBit() {
      return rg.getRnd(1);
    }

    int getLogRandBits() {
      int len = rg.getRnd(4);
      return rg.getRnd(len);
    }

    int getOffset() {
      if (getRndBit() == 0) return getLogRandBits();
      return (getLogRandBits() << 10) | rg.getRnd(10);
    }

    int getLen1() {
      return rg.getRnd(1 + rg.getRnd(2));
    }

    int getLen2() {
      return rg.getRnd(2 + rg.getRnd(2));
    }

    public void generate() {
      rg.init();
      rep0 = 1;
      while (pos < bufferSize) writeLiteralOrMatch();
    }

    private void writeLiteralOrMatch() {
      if (getRndBit() == 0 || pos < 1) {
        buffer[pos++] = (byte) (rg.getRnd(8));
      } else {
        int len = (rg.getRnd(3) == 0) ? 1 + getLen1() : computeCopyLenAfterOffset();
        copyLoop(len);
      }
    }

    private int computeCopyLenAfterOffset() {
      do rep0 = getOffset();
      while (rep0 >= pos);
      rep0++;
      return 2 + getLen2();
    }

    private void copyLoop(int len) {
      for (int i = 0; i < len && pos < bufferSize; i++, pos++) buffer[pos] = buffer[pos - rep0];
    }
  }

  static class CrcOutStream extends OutputStream {
    private final CRC crc = new CRC();

    public void init() {
      crc.init();
    }

    public int getDigest() {
      return crc.getDigest();
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) throws IOException {
      if (off < 0 || len < 0 || off + len > b.length) throw new IndexOutOfBoundsException();
      crc.update(b, off, len);
    }

    // Use OutputStream default bulk write implementation

    @Override
    public void write(int b) {
      crc.updateByte(b);
    }
  }

  static class MyOutputStream extends OutputStream {
    byte[] buffer;
    int size;
    int pos;

    public MyOutputStream(byte[] buffer) {
      this.buffer = buffer;
      size = this.buffer.length;
    }

    public void reset() {
      pos = 0;
    }

    @Override
    public void write(int b) throws IOException {
      if (pos >= size) throw new IOException("Error");
      buffer[pos++] = (byte) b;
    }

    public int size() {
      return pos;
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) throws IOException {
      if (off < 0 || len < 0 || off + len > b.length) throw new IndexOutOfBoundsException();
      for (int i = 0; i < len; i++) write(b[off + i]);
    }
  }

  static class MyInputStream extends InputStream {
    byte[] buffer;
    int size;
    int pos;

    public MyInputStream(byte[] buffer, int size) {
      this.buffer = buffer;
      this.size = size;
    }

    @Override
    public void reset() {
      pos = 0;
    }

    @Override
    public int read() {
      if (pos >= size) return -1;
      return buffer[pos++] & 0xFF;
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) {
      if (off < 0 || len < 0 || off + len > b.length) throw new IndexOutOfBoundsException();
      if (len == 0) return 0;
      if (pos >= size) return -1;
      int remaining = size - pos;
      int toRead = Math.min(len, remaining);
      System.arraycopy(buffer, pos, b, off, toRead);
      pos += toRead;
      return toRead;
    }
  }

  static class CProgressInfo implements ICodeProgress {
    long approvedStart;
    long inSize;
    long time;

    public void init() {
      inSize = 0;
    }

    public void setProgress(long inSize, long outSize) {
      if (inSize >= approvedStart && this.inSize == 0) {
        time = System.currentTimeMillis();
        this.inSize = inSize;
      }
    }
  }

  static final int K_SUB_BITS = 8;

  static int getLogSize(int size) {
    for (int i = K_SUB_BITS; i < 32; i++)
      for (int j = 0; j < (1 << K_SUB_BITS); j++)
        if (size <= ((1) << i) + (j << (i - K_SUB_BITS))) return (i << K_SUB_BITS) + j;
    return (32 << K_SUB_BITS);
  }

  static long myMultDiv64(long value, long elapsedTime) {
    long freq = 1000; // ms
    long elTime = elapsedTime;
    if (elTime == 0) elTime = 1;
    return value * freq / elTime;
  }

  static long getCompressRating(int dictionarySize, long elapsedTime, long size) {
    long t = getLogSize(dictionarySize) - (18L << K_SUB_BITS);
    long numCommandsForOne = 1060 + ((t * t * 10) >> (2 * K_SUB_BITS));
    long numCommands = size * numCommandsForOne;
    return myMultDiv64(numCommands, elapsedTime);
  }

  static long getDecompressRating(long elapsedTime, long outSize, long inSize) {
    long numCommands = inSize * 220 + outSize * 20;
    return myMultDiv64(numCommands, elapsedTime);
  }

  static void printValue(long v) {
    String s = "";
    s += v;
    for (int i = 0; i + s.length() < 6; i++) System.out.print(" ");
    System.out.print(s);
  }

  static void printRating(long rating) {
    printValue(rating / 1000000);
    System.out.print(" MIPS");
  }

  static void printResults(
      int dictionarySize, long elapsedTime, long size, boolean decompressMode, long secondSize) {
    long speed = myMultDiv64(size, elapsedTime);
    printValue(speed / 1024);
    System.out.print(" KB/s  ");
    long rating;
    if (decompressMode) rating = getDecompressRating(elapsedTime, size, secondSize);
    else rating = getCompressRating(dictionarySize, elapsedTime, size);
    printRating(rating);
  }

  private static long decodeTwiceAndCheck(
      int outSize,
      int compressedSize,
      byte[] compressedBuffer,
      CrcOutStream crcOutStream,
      Decoder decoder,
      CRC crc)
      throws java.io.IOException {
    long decodeTime = 0;
    for (int j = 0; j < 2; j++) {
      try (MyInputStream inputCompressedStream =
          new MyInputStream(compressedBuffer, compressedSize)) {
        crcOutStream.init();
        long startTime = System.currentTimeMillis();
        if (!decoder.code(inputCompressedStream, crcOutStream, outSize))
          throw (new IllegalStateException("Decoding Error"));
        decodeTime = System.currentTimeMillis() - startTime;
        if (crcOutStream.getDigest() != crc.getDigest())
          throw (new IllegalStateException("CRC Error"));
      }
    }
    return decodeTime;
  }

  public static void lzmaBenchmark(int numIterations, int dictionarySize)
      throws java.io.IOException {
    if (numIterations <= 0) return;
    if (dictionarySize < (1 << 18)) {
      System.out.println("\nError: dictionary size for benchmark must be >= 18 (256 KB)");
      return;
    }
    System.out.print("\n       Compressing                Decompressing\n\n");

    Encoder encoder = new Encoder();
    Decoder decoder = new Decoder();

    if (!encoder.setDictionarySize(dictionarySize))
      throw new IllegalArgumentException("Incorrect dictionary size");

    int kBufferSize = dictionarySize + K_ADDITIONAL_SIZE;
    int kCompressedBufferSize = (kBufferSize / 2) + K_COMPRESSED_ADDITIONAL_SIZE;

    ByteArrayOutputStream propStream = new ByteArrayOutputStream();
    encoder.writeCoderProperties(propStream);
    byte[] propArray = propStream.toByteArray();
    decoder.setDecoderProperties(propArray);

    CBenchRandomGenerator rg = new CBenchRandomGenerator();

    rg.set(kBufferSize);
    rg.generate();
    CRC crc = new CRC();
    crc.init();
    crc.update(rg.buffer, 0, rg.bufferSize);

    CProgressInfo progressInfo = new CProgressInfo();
    progressInfo.approvedStart = dictionarySize;

    long totalBenchSize = 0;
    long totalEncodeTime = 0;
    long totalDecodeTime = 0;
    long totalCompressedSize = 0;

    byte[] compressedBuffer = new byte[kCompressedBufferSize];
    try (MyInputStream inStream = new MyInputStream(rg.buffer, rg.bufferSize);
        MyOutputStream compressedStream = new MyOutputStream(compressedBuffer);
        CrcOutStream crcOutStream = new CrcOutStream()) {
      int compressedSize = 0;
      for (int i = 0; i < numIterations; i++) {
        progressInfo.init();
        inStream.reset();
        compressedStream.reset();
        encoder.code(inStream, compressedStream, progressInfo);
        long encodeTime = System.currentTimeMillis() - progressInfo.time;

        if (i == 0) {
          compressedSize = compressedStream.size();
        } else if (compressedSize != compressedStream.size())
          throw (new IllegalStateException("Encoding error"));

        if (progressInfo.inSize == 0) throw (new IllegalStateException("Internal ERROR 1282"));

        long decodeTime =
            decodeTwiceAndCheck(
                kBufferSize, compressedSize, compressedBuffer, crcOutStream, decoder, crc);
        long benchSize = kBufferSize - progressInfo.inSize;
        printResults(dictionarySize, encodeTime, benchSize, false, 0);
        System.out.print("     ");
        printResults(dictionarySize, decodeTime, kBufferSize, true, compressedSize);
        System.out.println();

        totalBenchSize += benchSize;
        totalEncodeTime += encodeTime;
        totalDecodeTime += decodeTime;
        totalCompressedSize += compressedSize;
      }
    }
    System.out.println("---------------------------------------------------");
    printResults(dictionarySize, totalEncodeTime, totalBenchSize, false, 0);
    System.out.print("     ");
    printResults(
        dictionarySize,
        totalDecodeTime,
        kBufferSize * (long) numIterations,
        true,
        totalCompressedSize);
    System.out.println("    Average");
  }
}
