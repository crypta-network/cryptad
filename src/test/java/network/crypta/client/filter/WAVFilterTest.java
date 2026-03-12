package network.crypta.client.filter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import org.junit.jupiter.api.Test;

import static network.crypta.client.filter.ResourceFileUtil.resourceToBucket;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // test method names use given_when_then with underscores
class WAVFilterTest {

  @Test
  void readFilter_whenValidWAV_expectPassThrough() throws IOException {
    Bucket input = resourceToBucket("./wav/test.wav");
    Bucket output = filterWAV(input, null);

    // Filter should return the original
    assertEquals(input.size(), output.size(), "Input and output should be the same length");
    assertArrayEquals(
        BucketTools.toByteArray(input),
        BucketTools.toByteArray(output),
        "Input and output are not identical");
  }

  // This file is WebP, not WAV!
  @Test
  void readFilter_whenContainerIsNotWAVE_expectException() throws IOException {
    Bucket input = resourceToBucket("./webp/test.webp");
    filterWAV(input, DataFilterException.class);
  }

  // There is just a JUNK chunk in the file
  @Test
  void readFilter_whenFirstChunkIsNotFmt_expectException() throws IOException {
    ByteBuffer buf =
        ByteBuffer.allocate(28)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(20 /* file size */)
            .put(new byte[] {'W', 'A', 'V', 'E'})
            .put(new byte[] {'J', 'U', 'N', 'K'})
            .putInt(7 /* chunk size */)
            .putLong(0);

    Bucket input = new ArrayBucket(buf.array());
    filterWAV(input, DataFilterException.class);
  }

  // There is just a fmt chunk in the file, but no audio data
  @Test
  void readFilter_whenMissingDataChunk_expectException() throws IOException {
    ByteBuffer buf =
        ByteBuffer.allocate(36)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(28 /* file size */)
            .put(new byte[] {'W', 'A', 'V', 'E'})
            .put(new byte[] {'f', 'm', 't', ' '})
            .putInt(16 /* chunk size */)
            .put(new byte[] {1, 0, 2, 0}) // format, nChannels
            .putInt(44100) // nSamplesPerSec
            .putInt(44100 * 4) // nAvgBytesPerSec
            .put(new byte[] {4, 0, 16, 0}); // nBlockAlign, wBitsPerSample

    Bucket input = new ArrayBucket(buf.array());
    filterWAV(input, DataFilterException.class);
  }

  @Test
  void readFilter_whenFmtChunkDuplicated_expectException() throws IOException {
    byte[] fmt = buildFmtBasic(1, 1, 8000, 8000, 1, 8);
    byte[] riff =
        buildWaveFile(
            chunk("fmt ", fmt),
            // duplicate fmt before any data
            chunk("fmt ", fmt));
    Bucket input = new ArrayBucket(riff);
    filterWAV(input, DataFilterException.class);
  }

  @Test
  void readFilter_whenFmtChunkSizeInvalid_expectException() throws IOException {
    byte[] payload = new byte[10];
    Arrays.fill(payload, (byte) 0xCC);
    byte[] riff = buildWaveFile(chunk("fmt ", payload));
    Bucket input = new ArrayBucket(riff);
    filterWAV(input, DataFilterException.class);
  }

  @Test
  void readFilter_whenUnsupportedFormat_expectException() throws IOException {
    byte[] fmt = buildFmtBasic(2, 1, 8000, 8000, 1, 8);
    byte[] riff = buildWaveFile(chunk("fmt ", fmt));
    Bucket input = new ArrayBucket(riff);
    filterWAV(input, DataFilterException.class);
  }

  @Test
  void readFilter_whenALawWithNon8Bit_expectException() throws IOException {
    // A-Law requires 8 bits per sample; here we use 16 to trigger rejection
    byte[] fmt = buildFmtBasic(6, 1, 8000, 8000, 2, 16);
    byte[] riff = buildWaveFile(chunk("fmt ", fmt));
    Bucket input = new ArrayBucket(riff);
    filterWAV(input, DataFilterException.class);
  }

  @Test
  void readFilter_whenFactSizeIsFour_expectPassThrough() throws IOException {
    byte[] fmt = buildFmtBasic(1, 2, 44100, 44100 * 4, 4, 16);
    byte[] factPayload = new byte[] {1, 2, 3, 4}; // dwSampleLength
    byte[] data = new byte[] {10, 11, 12, 13};
    byte[] riff =
        buildWaveFile(chunk("fmt ", fmt), chunk("fact", factPayload), chunk("data", data));

    Bucket input = new ArrayBucket(riff);
    Bucket output = filterWAV(input, null);
    assertArrayEquals(
        BucketTools.toByteArray(new ArrayBucket(riff)), BucketTools.toByteArray(output));
  }

  @Test
  void readFilter_whenUnknownChunk_expectRewrittenAsJunk() throws IOException {
    byte[] fmt = buildFmtBasic(1, 1, 8000, 8000, 1, 8);
    byte[] unknown = new byte[] {9, 8, 7, 6, 5, 4}; // 6 bytes
    byte[] data = new byte[] {1, 2};
    byte[] riffInput =
        buildWaveFile(chunk("fmt ", fmt), chunk("ABCD", unknown), chunk("data", data));

    // Expected output: unknown chunk replaced with JUNK of even size (6), filled with zeros
    byte[] riffExpected =
        buildWaveFile(
            chunk("fmt ", fmt), chunk("JUNK", new byte[] {0, 0, 0, 0, 0, 0}), chunk("data", data));

    Bucket input = new ArrayBucket(riffInput);
    Bucket output = filterWAV(input, null);
    assertArrayEquals(
        BucketTools.toByteArray(new ArrayBucket(riffExpected)), BucketTools.toByteArray(output));
  }

  @Test
  void readFilter_whenDataSizeIsOdd_expectPadByteCopied() throws IOException {
    byte[] fmt = buildFmtBasic(1, 1, 8000, 8000, 1, 8);
    byte[] dataPayload = new byte[] {0x11, 0x22, 0x33};
    byte pad = (byte) 0xAB; // explicit alignment byte after payload
    byte[] riffInput = buildWaveFile(chunk("fmt ", fmt), chunkWithPad(dataPayload, pad));

    // Build expected with the same explicit pad copied through
    byte[] riffExpected = buildWaveFile(chunk("fmt ", fmt), chunkWithPad(dataPayload, pad));

    Bucket input = new ArrayBucket(riffInput);
    Bucket output = filterWAV(input, null);
    assertArrayEquals(
        BucketTools.toByteArray(new ArrayBucket(riffExpected)), BucketTools.toByteArray(output));
  }

  @Test
  void readFilter_whenFmtHasCbSizeZero_expectPassThrough() throws IOException {
    byte[] fmt18 = buildFmtWithExtensions(1, 1, 8000, 8000, 1, 8, new byte[0]);
    byte[] data = new byte[] {1, 2};
    byte[] riff = buildWaveFile(chunk("fmt ", fmt18), chunk("data", data));
    Bucket input = new ArrayBucket(riff);
    Bucket output = filterWAV(input, null);
    assertArrayEquals(
        BucketTools.toByteArray(new ArrayBucket(riff)), BucketTools.toByteArray(output));
  }

  @Test
  void readFilter_whenFmtHasExtensions_expectPassThrough() throws IOException {
    byte[] ext = new byte[22];
    for (int i = 0; i < ext.length; i++) ext[i] = (byte) i;
    byte[] fmt40 = buildFmtWithExtensions(1, 2, 44100, 44100 * 4, 4, 16, ext);
    byte[] data = new byte[] {1, 2, 3, 4};
    byte[] riff = buildWaveFile(chunk("fmt ", fmt40), chunk("data", data));
    Bucket input = new ArrayBucket(riff);
    Bucket output = filterWAV(input, null);
    assertArrayEquals(
        BucketTools.toByteArray(new ArrayBucket(riff)), BucketTools.toByteArray(output));
  }

  @Test
  void readFilter_whenIEEEFloatFmtWithExtensions_expectPassThrough() throws IOException {
    // Use supported IEEE float format (3) with extensions and a small data chunk
    byte[] ext = new byte[22];
    for (int i = 0; i < ext.length; i++) ext[i] = (byte) (255 - i);
    byte[] fmt40 = buildFmtWithExtensions(3, 1, 16000, 16000 * 4, 4, 16, ext);
    byte[] data = new byte[] {5, 4, 3, 2};
    byte[] riff = buildWaveFile(chunk("fmt ", fmt40), chunk("data", data));
    Bucket input = new ArrayBucket(riff);
    Bucket output = filterWAV(input, null);
    assertArrayEquals(
        BucketTools.toByteArray(new ArrayBucket(riff)), BucketTools.toByteArray(output));
  }

  @Test
  void readFilter_whenFmtCbSizeMismatch_expectException() throws IOException {
    // size=18 but cbSize=1 is invalid (must be 0 when size==18)
    ByteBuffer b = ByteBuffer.allocate(18).order(ByteOrder.LITTLE_ENDIAN);
    b.putShort((short) 1); // PCM
    b.putShort((short) 1);
    b.putInt(8000);
    b.putInt(8000);
    b.putShort((short) 1);
    b.putShort((short) 8);
    b.putShort((short) 1); // cbSize=1 (invalid)
    byte[] riff = buildWaveFile(chunk("fmt ", b.array()));
    Bucket input = new ArrayBucket(riff);
    filterWAV(input, DataFilterException.class);
  }

  private Bucket filterWAV(Bucket input, Class<? extends Exception> expected) throws IOException {
    WAVFilter objWAVFilter = new WAVFilter();
    Bucket output = new ArrayBucket();
    try (InputStream inStream = input.getInputStream();
        OutputStream outStream = output.getOutputStream()) {
      if (expected != null) {
        assertThrows(
            expected, () -> objWAVFilter.readFilter(inStream, outStream, "", null, null, null));
      } else {
        objWAVFilter.readFilter(inStream, outStream, "", null, null, null);
      }
    }
    return output;
  }

  // --- helpers --------------------------------------------------------------

  private static class Chunk {
    final byte[] id; // 4 bytes
    final byte[] payload;
    final Byte padByte; // optional explicit pad for odd payload sizes

    Chunk(String id, byte[] payload, Byte padByte) {
      if (id == null || id.length() != 4) throw new IllegalArgumentException("id must be 4 chars");
      this.id = id.getBytes(StandardCharsets.US_ASCII);
      this.payload = payload;
      this.padByte = padByte;
    }
  }

  private static Chunk chunk(String id, byte[] payload) {
    return new Chunk(id, payload, null);
  }

  private static Chunk chunkWithPad(byte[] payload, byte pad) {
    return new Chunk("data", payload, pad);
  }

  private static byte[] buildWaveFile(Chunk... chunks) {
    int contentSize = 4; // 'WAVE'
    for (Chunk c : chunks) {
      int pad = (c.payload.length & 1);
      contentSize += 8 + c.payload.length + pad; // header + payload + possible pad byte
    }
    int totalSize = 8 + contentSize; // 'RIFF' + size + content

    ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);
    buf.put(new byte[] {'R', 'I', 'F', 'F'});
    buf.putInt(contentSize);
    buf.put(new byte[] {'W', 'A', 'V', 'E'});
    for (Chunk c : chunks) {
      buf.put(c.id);
      buf.putInt(c.payload.length);
      buf.put(c.payload);
      if ((c.payload.length & 1) != 0) {
        buf.put(c.padByte != null ? c.padByte : (byte) 0);
      }
    }
    return buf.array();
  }

  private static byte[] buildFmtBasic(
      int format, int channels, int rate, int avgBytesPerSec, int blockAlign, int bitsPerSample) {
    ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    b.putShort((short) format);
    b.putShort((short) channels);
    b.putInt(rate);
    b.putInt(avgBytesPerSec);
    b.putShort((short) blockAlign);
    b.putShort((short) bitsPerSample);
    return b.array();
  }

  private static byte[] buildFmtWithExtensions(
      int format,
      int channels,
      int rate,
      int avgBytesPerSec,
      int blockAlign,
      int bitsPerSample,
      byte[] extension) {
    ByteBuffer b = ByteBuffer.allocate(18 + extension.length).order(ByteOrder.LITTLE_ENDIAN);
    b.putShort((short) format);
    b.putShort((short) channels);
    b.putInt(rate);
    b.putInt(avgBytesPerSec);
    b.putShort((short) blockAlign);
    b.putShort((short) bitsPerSample);
    b.putShort((short) extension.length);
    b.put(extension);
    return b.array();
  }
}
