package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test name style: method_whenCondition_expectOutcome
class AEADInputStreamTest {

  // -------- helpers --------

  private static byte[] encrypt(byte[] plaintext, byte[] key, long seed) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (AEADOutputStream cos = AEADOutputStream.innerCreateAES(bos, key, new Random(seed))) {
      cos.write(plaintext);
    }
    return bos.toByteArray();
  }

  private static byte[] readAll(InputStream is) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    byte[] buf = new byte[8192];
    while (true) {
      int r = is.read(buf);
      if (r < 0) break;
      if (r == 0) continue;
      bos.write(buf, 0, r);
    }
    return bos.toByteArray();
  }

  // -------- tests --------

  @Test
  @DisplayName("read(): single-byte reads match plaintext")
  void read_whenReadingOneByteAtATime_matchesOriginal() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    new Random(0xA1B2C3D4).nextBytes(key);
    byte[] plain = new byte[256];
    for (int i = 0; i < plain.length; i++) plain[i] = (byte) i;
    byte[] cipher = encrypt(plain, key, 0x1111_2222L);
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act
    byte[] out = new byte[plain.length];
    for (int i = 0; i < out.length; i++) {
      int b = cis.read();
      out[i] = (byte) b;
    }
    cis.close();

    // Assert
    assertArrayEquals(plain, out);
  }

  @Test
  void read_whenLengthZero_returnsZeroAndDoesNotAdvance() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    new Random(0x12345678).nextBytes(key);
    byte[] plain = "hello world".getBytes(StandardCharsets.UTF_8);
    byte[] cipher = encrypt(plain, key, 0x5555AAAAL);
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act
    byte[] buf = new byte[8];
    int r0 = cis.read(buf, 0, 0);
    int r1 = cis.read(buf, 0, 5);
    cis.close();

    // Assert
    assertEquals(0, r0, "zero-length read must return 0");
    assertEquals(5, r1, "subsequent read should deliver data");
    assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), java.util.Arrays.copyOf(buf, 5));
  }

  @Test
  void read_whenNegativeLength_returnsMinusOne() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    new Random(42).nextBytes(key);
    byte[] plain = new byte[] {1, 2, 3, 4, 5};
    byte[] cipher = encrypt(plain, key, 7L);
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act
    int v = cis.read(new byte[8], 0, -1);
    cis.close();

    // Assert
    assertEquals(-1, v, "negative length should return -1 per implementation");
  }

  @Test
  void skip_whenSkippingPartOfPlaintext_remainingBytesMatch() throws Exception {
    // Arrange
    byte[] key = new byte[24];
    new Random(0xCAFE_BABEL).nextBytes(key);
    byte[] plain = new byte[4096];
    new Random(0x7777_8888L).nextBytes(plain);
    byte[] cipher = encrypt(plain, key, 0xDEADBEEFL);
    int skip = 1000;
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act
    long skipped = cis.skip(skip);
    byte[] remainder = readAll(cis);
    cis.close();

    // Assert
    assertEquals(skip, skipped);
    byte[] expected = java.util.Arrays.copyOfRange(plain, skip, plain.length);
    assertArrayEquals(expected, remainder);
  }

  @Test
  void skip_whenSkippingPastEnd_returnsTotalLengthAndFinishes() throws Exception {
    // Arrange
    byte[] key = new byte[32];
    new Random(123).nextBytes(key);
    byte[] plain = new byte[2048];
    new Random(987654321L).nextBytes(plain);
    byte[] cipher = encrypt(plain, key, 3141592653L);
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act
    long skipped = cis.skip(plain.length + 100L);
    int after = cis.read(); // should be EOF now
    cis.close();

    // Assert
    assertEquals(plain.length, skipped);
    assertEquals(-1, after);
  }

  @Test
  void available_whenFinished_returnsZero() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    new Random(9).nextBytes(key);
    ArrayBucket src = new ArrayBucket();
    try (OutputStream os = src.getOutputStreamUnbuffered()) {
      os.write(new byte[512]);
    }
    ArrayBucket enc = new ArrayBucket();
    try (AEADOutputStream cos =
        AEADOutputStream.innerCreateAES(enc.getOutputStream(), key, new Random(1))) {
      BucketTools.copyTo(src, cos, -1);
    }
    AEADInputStream cis = AEADInputStream.createAES(enc.getInputStream(), key);
    // drain completely
    BucketTools.copyFrom(new ArrayBucket(), cis, -1);

    // Act
    int avail = cis.available();
    cis.close();

    // Assert
    assertEquals(0, avail);
  }

  @Test
  void close_whenCalled_invokesUnderlyingClose() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    new Random(1234).nextBytes(key);
    byte[] plain = new byte[128];
    new Random(4321).nextBytes(plain);
    byte[] cipher = encrypt(plain, key, 111L);
    ByteArrayInputStream underlying = new ByteArrayInputStream(cipher);
    InputStream spy = Mockito.spy(underlying);
    AEADInputStream cis = AEADInputStream.createAES(spy, key);

    // Act
    cis.close();

    // Assert
    Mockito.verify(spy, Mockito.times(1)).close();
  }

  @Test
  void getIVSize_whenAESGCM_returns12Bytes() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    byte[] cipher = encrypt(new byte[] {1, 2, 3}, key, 1L);
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act / Assert
    assertEquals(12, cis.getIVSize());
    cis.close();
  }

  @Test
  void markReset_whenCalled_behavesAsDocumented() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    byte[] cipher = encrypt(new byte[] {10, 20, 30}, key, 2L);
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act & Assert
    assertFalse(cis.markSupported());
    assertThrows(UnsupportedOperationException.class, () -> cis.mark(1));
    assertThrows(IOException.class, cis::reset);
    cis.close();
  }

  @Test
  void close_whenTagCorrupted_throwsAEADVerificationFailedException() throws Exception {
    // Arrange
    byte[] key = new byte[16];
    new Random(2468).nextBytes(key);
    byte[] plain = new byte[1024];
    new Random(8642).nextBytes(plain);
    byte[] cipher = encrypt(plain, key, 0x0FF1CE);
    // Flip last byte to corrupt the tag/ciphertext
    cipher[cipher.length - 1] ^= 0x01;
    AEADInputStream cis = AEADInputStream.createAES(new ByteArrayInputStream(cipher), key);

    // Act & Assert: reading to the end or closing should surface the error.
    assertThrows(AEADVerificationFailedException.class, () -> readAll(cis));
    assertThrows(AEADVerificationFailedException.class, cis::close);
  }
}
