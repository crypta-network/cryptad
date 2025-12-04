package org.bitpedia.collider.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class Ed2HandlerTest {

  private static final int SEGMENT_SIZE = readSegmentSize();

  @Test
  void analyzeFinal_whenNoData_returnsMd4OfEmptyInput() {
    Ed2Handler handler = new Ed2Handler();
    handler.analyzeInit();

    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeMd4(new byte[0], 0, 0), digest);
  }

  @Test
  void analyzeFinal_whenSingleSegment_returnsMd4OfData() {
    byte[] data = generateData(1024);
    Ed2Handler handler = new Ed2Handler();
    handler.analyzeInit();

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeMd4(data, 0, data.length), digest);
  }

  @Test
  void analyzeFinal_whenExactSegmentSize_returnsMd4OfData() {
    byte[] data = generateData(SEGMENT_SIZE);
    Ed2Handler handler = new Ed2Handler();
    handler.analyzeInit();

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeMd4(data, 0, data.length), digest);
  }

  @Test
  void analyzeFinal_whenDataSpansTwoSegments_returnsMd4OfSegmentDigests() {
    int totalLength = SEGMENT_SIZE + 1234;
    byte[] data = generateData(totalLength);
    Ed2Handler handler = new Ed2Handler();
    handler.analyzeInit();

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeEd2Expected(data), digest);
  }

  @Test
  void analyzeUpdate_whenBoundaryCrossedInChunks_matchesSingleUpdate() {
    int totalLength = SEGMENT_SIZE + 4321;
    byte[] data = generateData(totalLength);

    Ed2Handler singleUpdate = new Ed2Handler();
    singleUpdate.analyzeInit();
    singleUpdate.analyzeUpdate(data, data.length);
    byte[] singleDigest = singleUpdate.analyzeFinal();

    Ed2Handler chunked = new Ed2Handler();
    chunked.analyzeInit();
    int firstChunk = SEGMENT_SIZE - 10;
    chunked.analyzeUpdate(data, 0, firstChunk);
    chunked.analyzeUpdate(data, firstChunk, totalLength - firstChunk);
    byte[] chunkedDigest = chunked.analyzeFinal();

    assertArrayEquals(singleDigest, chunkedDigest);
  }

  @Test
  void analyzeUpdate_whenZeroLengthInputProvided_digestUnaffected() {
    byte[] data = generateData(4096);

    Ed2Handler baseline = new Ed2Handler();
    baseline.analyzeInit();
    baseline.analyzeUpdate(data, data.length);
    byte[] expected = baseline.analyzeFinal();

    Ed2Handler withZeroUpdate = new Ed2Handler();
    withZeroUpdate.analyzeInit();
    withZeroUpdate.analyzeUpdate(data, 0, 2048);
    withZeroUpdate.analyzeUpdate(new byte[0], 0);
    withZeroUpdate.analyzeUpdate(data, 2048, data.length - 2048);
    byte[] actual = withZeroUpdate.analyzeFinal();

    assertArrayEquals(expected, actual);
  }

  private static int readSegmentSize() {
    try {
      Field field = Ed2Handler.class.getDeclaredField("EDSEG_SIZE");
      field.setAccessible(true);
      return field.getInt(null);
    } catch (ReflectiveOperationException ex) {
      throw new IllegalStateException("Unable to read segment size", ex);
    }
  }

  private static byte[] computeEd2Expected(byte[] data) {
    if (data.length <= SEGMENT_SIZE) {
      return computeMd4(data, 0, data.length);
    }

    Md4Handler top = new Md4Handler();
    top.analyzeInit();

    int offset = 0;
    while (offset < data.length) {
      int len = Math.min(SEGMENT_SIZE, data.length - offset);
      byte[] segmentDigest = computeMd4(data, offset, len);
      top.analyzeUpdate(segmentDigest, segmentDigest.length);
      offset += len;
    }

    return top.analyzeFinal();
  }

  private static byte[] computeMd4(byte[] data, int offset, int length) {
    Md4Handler md4 = new Md4Handler();
    md4.analyzeInit();
    if (length > 0) {
      md4.analyzeUpdate(data, offset, length);
    }
    return md4.analyzeFinal();
  }

  private static byte[] generateData(int length) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) {
      data[i] = (byte) (i % 256);
    }
    return data;
  }
}
