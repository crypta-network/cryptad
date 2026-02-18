package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;
import org.bouncycastle.crypto.BlockCipher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@SuppressWarnings({"java:S100", "java:S2245"}) // naming; deterministic Random acceptable in tests
@ExtendWith(MockitoExtension.class)
class AEADOutputStreamTest {

  @ParameterizedTest
  @ValueSource(ints = {16, 24, 32})
  void roundTrip_whenValidAESKey_expectExactOverheadAndPlaintextRestored(int keySize)
      throws IOException {
    byte[] key = new byte[keySize];
    // Deterministic key
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i + 1);

    // Deterministic random for nonce generation inside innerCreateAES
    long seed = 0xC0FFEE_F00DL;
    Random rForStream = new Random(seed);
    Random rForExpectation = new Random(seed);

    // Plaintext pattern: deterministic and non-random
    byte[] plaintext = new byte[8192];
    for (int i = 0; i < plaintext.length; i++) plaintext[i] = (byte) i;

    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    try (AEADOutputStream aos = AEADOutputStream.innerCreateAES(underlying, key, rForStream)) {
      // Exercise write variants to cover all public write methods
      aos.write(plaintext[0]);
      aos.write(plaintext, 1, 100);
      aos.write(plaintext, 101, plaintext.length - 101);
    }

    byte[] ciphertext = underlying.toByteArray();

    // Assert exact overhead (prefix + GCM tag)
    assertEquals(
        plaintext.length + AEADOutputStream.AES_OVERHEAD,
        ciphertext.length,
        "AES-GCM overhead must be 32 bytes (16 prefix + 16 tag)");

    // Assert the written 16-byte prefix equals the first 16 bytes produced by our deterministic
    // PRNG
    byte[] expectedPrefix = new byte[AEADOutputStream.WRITTEN_NONCE_SIZE];
    rForExpectation.nextBytes(expectedPrefix);
    byte[] actualPrefix = new byte[AEADOutputStream.WRITTEN_NONCE_SIZE];
    System.arraycopy(ciphertext, 0, actualPrefix, 0, actualPrefix.length);
    assertArrayEquals(expectedPrefix, actualPrefix, "Persisted prefix must match written nonce");

    // Decrypt and verify round-trip
    try (AEADInputStream ais =
        AEADInputStream.createAES(new ByteArrayInputStream(ciphertext), key)) {
      byte[] recovered = ais.readAllBytes();
      assertArrayEquals(plaintext, recovered, "Decrypted bytes must equal original plaintext");
    }
  }

  @Test
  void write_whenZeroLength_expectOnlyOverheadWritten() throws IOException {
    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 3 + 1);

    Random deterministic = new Random(0xABCD_1234L);
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    AEADOutputStream aos = AEADOutputStream.innerCreateAES(underlying, key, deterministic);
    aos.write(new byte[0]);
    aos.write(new byte[128], 64, 0); // zero-length write with offset
    aos.close();

    byte[] out = underlying.toByteArray();
    assertEquals(
        AEADOutputStream.AES_OVERHEAD,
        out.length,
        "Empty plaintext should still produce only prefix + tag");

    // Round-trip decrypt yields empty payload
    try (AEADInputStream ais = AEADInputStream.createAES(new ByteArrayInputStream(out), key)) {
      byte[] recovered = ais.readAllBytes();
      assertEquals(0, recovered.length, "Recovered plaintext must be empty");
    }
  }

  @Test
  void close_whenCalled_expectUnderlyingStreamClosed() throws IOException {
    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i + 7);

    Random deterministic = new Random(12345L);
    ByteArrayOutputStream real = new ByteArrayOutputStream();
    ByteArrayOutputStream spyOut = spy(real);
    try (AEADOutputStream aos = AEADOutputStream.innerCreateAES(spyOut, key, deterministic)) {
      aos.write(new byte[] {1, 2, 3, 4});
    }

    // Verify close is delegated
    verify(spyOut).close();
    // Prefix must be present; update bytes may or may not flush before close depending on provider
    int written = spyOut.toByteArray().length;
    assertTrue(written >= AEADOutputStream.WRITTEN_NONCE_SIZE);
    verify(spyOut, atLeastOnce()).write(org.mockito.ArgumentMatchers.any(byte[].class));
  }

  @Test
  @DisplayName("Constructor throws on invalid AES key length and still writes the prefix")
  void constructor_whenInvalidKeyLength_expectExceptionAndPrefixWritten() {
    // Prepare an underlying buffer to observe writes
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // Invalid AES key size: 15 bytes
    byte[] badKey = new byte[15];
    for (int i = 0; i < badKey.length; i++) badKey[i] = (byte) (0xF0 + i);

    // Provide explicit nonces so we can validate the exact bytes written to the stream
    byte[] writtenNonce = new byte[AEADOutputStream.WRITTEN_NONCE_SIZE];
    for (int i = 0; i < writtenNonce.length; i++) writtenNonce[i] = (byte) (i + 1);
    byte[] gcmNonce = new byte[AEADOutputStream.GCM_NONCE_SIZE];
    System.arraycopy(writtenNonce, 0, gcmNonce, 0, gcmNonce.length);

    // The constructor writes the 16-byte prefix before initializing the cipher. With an invalid
    // key length, cipher.init() throws (IllegalArgumentException from the AES engine).
    // Pre-create ciphers so the lambda contains a single invocation that may throw
    BlockCipher mainCipher = BlockCiphers.aes();
    assertThrows(
        IllegalArgumentException.class,
        () -> new AEADOutputStream(os, badKey, writtenNonce, gcmNonce, mainCipher));

    // Verify the prefix was written to the underlying stream even though initialization failed
    byte[] observed = os.toByteArray();
    assertEquals(AEADOutputStream.WRITTEN_NONCE_SIZE, observed.length);
    assertArrayEquals(writtenNonce, observed);
  }

  @Test
  void writeVariants_whenMixed_expectCorrectPlaintextAfterDecrypt() throws IOException {
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i ^ 0x5A);
    Random r = new Random(0xDEADBEEFL);

    byte[] data = new byte[257];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (255 - i);

    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    try (AEADOutputStream aos = AEADOutputStream.innerCreateAES(buf, key, r)) {
      // Single byte
      aos.write(data[0]);
      // Some chunk
      aos.write(data, 1, 100);
      // Remainder as whole array
      byte[] tail = new byte[data.length - 101];
      System.arraycopy(data, 101, tail, 0, tail.length);
      aos.write(tail);
    }

    byte[] encrypted = buf.toByteArray();
    try (AEADInputStream ais =
        AEADInputStream.createAES(new ByteArrayInputStream(encrypted), key)) {
      byte[] recovered = ais.readAllBytes();
      assertArrayEquals(data, recovered);
    }
  }

  @Test
  void constants_whenRead_expectGCMDefaultsAndOverheadConsistency() {
    assertEquals(12, AEADOutputStream.GCM_NONCE_SIZE);
    assertEquals(16, AEADOutputStream.WRITTEN_NONCE_SIZE);
    assertEquals(32, AEADOutputStream.AES_OVERHEAD);
  }
}
