package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RIFFFilterTest {

  /**
   * Minimal concrete RIFF filter for tests. Uses a fixed form type of "TEST" and reads each chunk
   * by consuming {@code size} bytes plus the optional pad byte when {@code size} is odd.
   */
  static final class TestRiffFilter extends RIFFFilter {
    private static final byte[] FORM = new byte[] {'T', 'E', 'S', 'T'};

    @Override
    protected byte[] getChunkMagicNumber() {
      return FORM;
    }

    @Override
    protected Object createContext() {
      return new Object();
    }

    @Override
    protected void readFilterChunk(byte[] id, int size, Object context, ReadFilterContext params)
        throws IOException {
      // Consume the chunk payload
      byte[] data = new byte[size];
      params.input.readFully(data);
      // Consume the padding byte if present (RIFF chunks are word-aligned)
      if ((size & 1) == 1) {
        int pad = params.input.read();
        if (pad == -1) {
          throw new EOFException();
        }
      }
      // For tests, we do not emit chunk data back; only the RIFF header is written by the base
      // implementation. This keeps the tests focused on structural validation.
    }

    @Override
    protected void eofCheck(Object context) {
      // No-op for tests
    }
  }

  private static byte[] leInt(int v) {
    // Convenience helper to encode a 32-bit little-endian integer into 4 bytes.
    ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
    bb.putInt(v);
    return bb.array();
  }

  private static byte[] riffHeader(int fileSize, byte[] form) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(new byte[] {'R', 'I', 'F', 'F'});
    bos.write(leInt(fileSize));
    bos.write(form);
    return bos.toByteArray();
  }

  @Test
  void readFilter_happyPath_evenAndOddChunks_noException() throws Exception {
    // Arrange: RIFF(TEST) with two chunks: one empty, one odd-sized 3 bytes (with pad)
    TestRiffFilter filter = new TestRiffFilter();

    byte[] form = filter.getChunkMagicNumber();

    // Chunk 1: id="abcd", size=0, no data
    byte[] c1 = new byte[] {'a', 'b', 'c', 'd', 0, 0, 0, 0};

    // Chunk 2: id="data", size=3, payload=3 bytes, plus 1 pad byte
    ByteArrayOutputStream c2 = new ByteArrayOutputStream();
    c2.write(new byte[] {'d', 'a', 't', 'a'});
    c2.write(leInt(3));
    c2.write(new byte[] {1, 2, 3});
    c2.write(0); // pad to even size

    int remaining = c1.length + c2.size(); // == (8 + 12)
    int fileSize = 4 + remaining; // 4 bytes form type + chunks

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(riffHeader(fileSize, form));
    bos.write(c1);
    bos.write(c2.toByteArray());

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert: should parse without throwing
    assertDoesNotThrow(
        () -> filter.readFilter(in, out, null, Map.of(), "http://example:1234", /* cb= */ null));

    // And the output must start with the same RIFF header
    byte[] outBytes = out.toByteArray();
    byte[] expectedHeader = riffHeader(fileSize, form);
    assertArrayEquals(expectedHeader, Arrays.copyOfRange(outBytes, 0, expectedHeader.length));
  }

  @Test
  void readFilter_whenMagicMismatch_expectDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] form = filter.getChunkMagicNumber();

    // Corrupt the first byte of the RIFF magic
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(new byte[] {'X', 'I', 'F', 'F'});
    bos.write(leInt(12));
    bos.write(form);

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void readFilter_whenFormTypeMismatch_expectDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();

    // Correct RIFF header and size but wrong form type
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(new byte[] {'R', 'I', 'F', 'F'});
    bos.write(leInt(12));
    bos.write(new byte[] {'B', 'A', 'D', '!'});

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void readFilter_whenNegativeFileSize_expectDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] form = filter.getChunkMagicNumber();

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(new byte[] {'R', 'I', 'F', 'F'});
    bos.write(leInt(-1)); // negative size indicates >2GiB in unsigned terms
    bos.write(form);

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void readFilter_whenFileSizeTooSmall_expectDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] form = filter.getChunkMagicNumber();

    // fileSize < 12 means not enough room for any chunk (after 4 bytes form type)
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(new byte[] {'R', 'I', 'F', 'F'});
    bos.write(leInt(11));
    bos.write(form);

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void readFilter_whenChunkDeclTooLarge_expectDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] form = filter.getChunkMagicNumber();

    // remainingSize will be 8, but we declare a chunk with size=8 (requires 8 + header 8 = 16)
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(riffHeader(12, form)); // fileSize = 4 (form) + 8 (remaining)
    bos.write(new byte[] {'c', 'h', 'n', 'k'});
    bos.write(leInt(8));

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void readFilter_whenStreamTruncated_expectEOFDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] form = filter.getChunkMagicNumber();

    // Declare a chunk of size 4 but provide only 2 bytes of payload; readFilterChunk will
    // try to readFully(4) and trigger EOFException, which the outer reader maps to
    // DataFilterException.
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(riffHeader(4 + 8 + 4, form)); // 4 (form) + 8 (hdr) + 4 (payload)
    bos.write(new byte[] {'i', 'd', 'x', '1'});
    bos.write(leInt(4));
    bos.write(new byte[] {9, 9}); // only 2 bytes instead of 4

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void readFilter_whenExtraTrailingBytes_expectEOFDataFilterException() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] form = filter.getChunkMagicNumber();

    // Valid single empty chunk but append 1 extra byte beyond declared file size
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // remaining = one empty chunk (8)
    bos.write(riffHeader(4 + 8, form));
    bos.write(new byte[] {'n', 'u', 'l', 'l'});
    bos.write(leInt(0));
    bos.write(0x7F); // extra byte beyond expected EOF

    ByteArrayInputStream in = new ByteArrayInputStream(bos.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        DataFilterException.class, () -> filter.readFilter(in, out, null, Map.of(), null, null));
  }

  @Test
  void passthroughBytes_whenNegativeSize_expectDataFilterException() {
    TestRiffFilter filter = new TestRiffFilter();
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(new byte[] {1, 2, 3}));
    DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStream());
    assertThrows(DataFilterException.class, () -> filter.passthroughBytes(dis, dos, -5));
  }

  @Test
  void passthroughBytes_copiesExactNumberOfBytes() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    byte[] payload = new byte[1024 + 3]; // not a multiple of the copy chunk size
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (i & 0xFF);
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    filter.passthroughBytes(
        new DataInputStream(new ByteArrayInputStream(payload)),
        new DataOutputStream(out),
        payload.length);
    assertArrayEquals(payload, out.toByteArray());
  }

  @Test
  void writeJunkChunk_writesEvenSizedZeroBlock() throws Exception {
    TestRiffFilter filter = new TestRiffFilter();
    // size=3 -> becomes 4 due to padding; provide 4 bytes to skip
    byte[] skipSrc = new byte[] {10, 20, 30, 40};
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    filter.writeJunkChunk(
        new DataInputStream(new ByteArrayInputStream(skipSrc)), new DataOutputStream(out), 3);

    byte[] bytes = out.toByteArray();
    // Expect: 'JUNK' + LE(4) + 4 zero bytes
    ByteArrayOutputStream expected = new ByteArrayOutputStream();
    expected.write(new byte[] {'J', 'U', 'N', 'K'});
    expected.write(leInt(4));
    expected.write(new byte[] {0, 0, 0, 0});

    assertArrayEquals(expected.toByteArray(), bytes);
  }

  @Test
  void writeJunkChunk_whenNegativeSize_expectDataFilterException() {
    TestRiffFilter filter = new TestRiffFilter();
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {1, 2, 3});
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertThrows(
        DataFilterException.class,
        () -> filter.writeJunkChunk(new DataInputStream(in), new DataOutputStream(out), -1));
  }

  @Test
  void littleEndianInt_readAndWrite_roundTrip() throws Exception {
    // Arrange: write a known value in little-endian and read it back
    int value = 0x78563412; // 2018915346
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(out);
    RIFFFilter.writeLittleEndianInt(dos, value);

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(out.toByteArray()));
    int read = RIFFFilter.readLittleEndianInt(dis);
    assertEquals(value, read);
  }
}
