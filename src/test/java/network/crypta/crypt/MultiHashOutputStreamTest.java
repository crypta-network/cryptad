package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MultiHashOutputStreamTest {
  private static final byte[] MESSAGE = "Hello, World!".getBytes(StandardCharsets.UTF_8);
  private static final String MESSAGE_MD5 = "65a8e27d8879283831b664bd8b7f0ad4";

  private static String digestHex(HashType type, byte[] data) {
    MessageDigest d = type.get();
    d.update(data, 0, data.length);
    return network.crypta.support.HexUtil.bytesToHex(d.digest());
  }

  @Test
  void write_whenIntThenArray_expectForwardingAndMd5Match() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    MultiHashOutputStream hash = new MultiHashOutputStream(output, HashType.MD5.bitmask);

    hash.write(MESSAGE[0]);
    hash.write(MESSAGE, 1, MESSAGE.length - 1);

    assertArrayEquals(MESSAGE, output.toByteArray());

    HashResult[] results = hash.getResults();
    assertEquals(1, results.length);
    assertEquals(HashType.MD5, results[0].type);
    assertEquals(MESSAGE_MD5, results[0].hashAsHex());
  }

  @Test
  void write_whenZeroLength_expectNoChangeAndEmptyDigest() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    MultiHashOutputStream hash = new MultiHashOutputStream(output, HashType.SHA1.bitmask);

    byte[] buf = "ignored".getBytes(StandardCharsets.UTF_8);
    hash.write(buf, 0, 0); // zero-length write

    assertEquals(0, output.size());

    HashResult[] results = hash.getResults();
    assertEquals(1, results.length);
    assertEquals(HashType.SHA1, results[0].type);

    String emptySha1 = digestHex(HashType.SHA1, new byte[0]);
    assertEquals(emptySha1, results[0].hashAsHex());
  }

  @Test
  void getResults_whenNoHashSelected_returnsEmptyArray() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    MultiHashOutputStream hash = new MultiHashOutputStream(output, 0L);

    hash.write(MESSAGE);
    assertArrayEquals(MESSAGE, output.toByteArray());

    HashResult[] results = hash.getResults();
    assertEquals(0, results.length);
  }

  @Test
  void write_whenOffsetAndLengthUsed_onlySliceIsProcessed() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    MultiHashOutputStream hash = new MultiHashOutputStream(output, HashType.SHA256.bitmask);

    byte[] data = "abcde".getBytes(StandardCharsets.UTF_8);
    hash.write(data, 1, 3); // "bcd"

    assertArrayEquals("bcd".getBytes(StandardCharsets.UTF_8), output.toByteArray());

    HashResult[] results = hash.getResults();
    assertEquals(1, results.length);
    assertEquals(HashType.SHA256, results[0].type);

    String expected = digestHex(HashType.SHA256, "bcd".getBytes(StandardCharsets.UTF_8));
    assertEquals(expected, results[0].hashAsHex());
  }

  @Test
  void write_whenUnderlyingThrows_noDigestUpdateAndExceptionPropagates() throws IOException {
    OutputStream failing =
        new OutputStream() {
          @Override
          public void write(int b) throws IOException {
            throw new IOException("boom");
          }

          @Override
          public void write(byte @NotNull [] b, int off, int len) throws IOException {
            throw new IOException("boom");
          }
        };

    byte[] data = "data".getBytes(StandardCharsets.UTF_8);
    try (MultiHashOutputStream hash = new MultiHashOutputStream(failing, HashType.MD5.bitmask)) {
      IOException ex = assertThrows(IOException.class, () -> hash.write(data, 0, data.length));
      assertTrue(ex.getMessage().contains("boom"));

      // Since underlying write failed before digester.update(), the digest should be for empty
      // input.
      HashResult[] results = hash.getResults();
      assertEquals(1, results.length);
      assertEquals(HashType.MD5, results[0].type);
      assertEquals(digestHex(HashType.MD5, new byte[0]), results[0].hashAsHex());
    }
  }

  @Test
  void getResults_whenCalledTwice_resetsDigests() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    MultiHashOutputStream hash = new MultiHashOutputStream(output, HashType.SHA384.bitmask);

    hash.write(MESSAGE);
    String first = hash.getResults()[0].hashAsHex();

    // Second call without updates returns digest of empty input (due to reset on digest()).
    String second = hash.getResults()[0].hashAsHex();
    assertEquals(digestHex(HashType.SHA384, new byte[0]), second);

    // Writing the same message again should reproduce the first digest value.
    hash.write(MESSAGE);
    String third = hash.getResults()[0].hashAsHex();
    assertEquals(first, third);
  }

  @Test
  void writeInt_whenNegativeByte_expectCorrectHash() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    MultiHashOutputStream hash = new MultiHashOutputStream(output, HashType.SHA512.bitmask);

    hash.write(0xFF); // -1 as signed byte
    assertArrayEquals(new byte[] {(byte) 0xFF}, output.toByteArray());

    HashResult[] results = hash.getResults();
    assertEquals(1, results.length);
    assertEquals(HashType.SHA512, results[0].type);

    String expected = digestHex(HashType.SHA512, new byte[] {(byte) 0xFF});
    assertEquals(expected, results[0].hashAsHex());
  }

  @Test
  void multipleHashes_whenSelected_expectOrderedResults() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    long mask = HashType.MD5.bitmask | HashType.SHA1.bitmask | HashType.SHA256.bitmask;
    MultiHashOutputStream hash = new MultiHashOutputStream(output, mask);

    hash.write(MESSAGE);
    HashResult[] results = hash.getResults();

    // Order must follow HashType.values(): SHA1, MD5, SHA256, ...
    assertEquals(3, results.length);
    assertEquals(HashType.SHA1, results[0].type);
    assertEquals(HashType.MD5, results[1].type);
    assertEquals(HashType.SHA256, results[2].type);

    assertEquals(digestHex(HashType.SHA1, MESSAGE), results[0].hashAsHex());
    assertEquals(digestHex(HashType.MD5, MESSAGE), results[1].hashAsHex());
    assertEquals(digestHex(HashType.SHA256, MESSAGE), results[2].hashAsHex());
  }

  @Test
  void write_withMockitoSpy_verifiesUnderlyingWriteParameters() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ByteArrayOutputStream spyOut = spy(baos);
    try (MultiHashOutputStream hash = new MultiHashOutputStream(spyOut, HashType.MD5.bitmask)) {
      byte[] buf = "0123456789".getBytes(StandardCharsets.UTF_8);
      hash.write(buf, 2, 5);

      // Verify underlying stream was called once with the exact offset/length.
      verify(spyOut, times(1)).write(buf, 2, 5);

      // And the content forwarded matches the slice
      assertArrayEquals("23456".getBytes(StandardCharsets.UTF_8), spyOut.toByteArray());
    }
  }
}
