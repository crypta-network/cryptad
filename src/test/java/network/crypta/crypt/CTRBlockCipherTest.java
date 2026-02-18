package network.crypta.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.HexUtil;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings({
  "java:S100", // test method naming style
  "java:S116", // constants naming (keep NIST_* names for clarity)
  "java:S1192" // intentional reuse of hex constants (addressed where high)
})
@ExtendWith(MockitoExtension.class)
class CTRBlockCipherTest {

  /** Whether to assume JCA is available, and non-crippled. */
  static final boolean TEST_JCA = network.crypta.crypt.TestJca.AES_CTR_AVAILABLE;

  // Helper to satisfy static analysis when the provider may be null at compile time.
  private static Cipher newAesCtrCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    java.security.Provider p = Rijndael.getAesCtrProvider();
    return (p != null)
        ? Cipher.getInstance("AES/CTR/NOPADDING", p)
        : Cipher.getInstance("AES/CTR/NOPADDING");
  }

  /*
   * Additional deterministic tests for CTRBlockCipher focusing on API contracts and
   * boundary conditions. These complement the NIST-vector and randomized tests below.
   */

  @Test
  void constructor_andGetters_whenProvidedCipher_expectSameInstanceAndBlockSize() {
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128);

    CTRBlockCipher ctr = new CTRBlockCipher(cipher);

    assertEquals(
        cipher, ctr.getUnderlyingCipher(), "Underlying cipher should be the same instance");
    assertEquals(128, ctr.getBlockSize(), "Block size must be reported in bits from the cipher");
  }

  @Test
  void init_whenIvLengthMismatch_expectIllegalArgumentException() {
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128); // 16 bytes IV expected
    CTRBlockCipher ctr = new CTRBlockCipher(cipher);

    byte[] ivWrong = new byte[15];
    assertThrows(
        IllegalArgumentException.class, () -> ctr.init(ivWrong), "Invalid IV length must throw");
  }

  @Test
  void init_withOffsetBeyondArray_expectArrayIndexOutOfBoundsException() {
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128); // 16 bytes IV expected
    CTRBlockCipher ctr = new CTRBlockCipher(cipher);

    byte[] ivExact = new byte[16];
    // Pass offset=1 and length=16 → offset+length exceeds ivExact length
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> ctr.init(ivExact, 1, 16),
        "Offset+length beyond array must propagate AIOOBE from arraycopy");
  }

  @Test
  void processByte_whenCrossingBlockBoundary_expectKeystreamAdvances() {
    // Configure cipher to "reverse" the input block into the result.
    // With IV of all-zeros, the first block keystream is all zeros (reverse of zeros),
    // the next block's first byte becomes the last byte of the incremented counter (== 1).
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128);
    Mockito.doAnswer(
            invocation -> {
              byte[] in = invocation.getArgument(0);
              byte[] out = invocation.getArgument(1);
              byte[] tmp = java.util.Arrays.copyOf(in, in.length);
              for (int i = 0; i < tmp.length; i++) out[i] = tmp[tmp.length - 1 - i];
              return null;
            })
        .when(cipher)
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));

    CTRBlockCipher ctr = new CTRBlockCipher(cipher);
    byte[] iv = new byte[16]; // all zeros
    ctr.init(iv);

    byte[] input = new byte[33];
    for (int i = 0; i < input.length; i++) input[i] = (byte) i;

    byte[] output = new byte[input.length];
    for (int i = 0; i < input.length; i++) output[i] = ctr.processByte(input[i]);

    // First 16 bytes XOR with 0x00
    for (int i = 0; i < 16; i++)
      assertEquals(input[i], output[i], "First block should be unchanged");
    // Byte 16 (start of second block) XORs with 0x01 due to reversed counter placing LSB first
    assertEquals(
        (byte) (input[16] ^ 0x01), output[16], "First byte after boundary should flip by 1");
    // The rest of the second block except last byte still XOR with 0x00
    for (int i = 17; i < 31; i++)
      assertEquals(input[i], output[i], "Middle bytes of second block unchanged");
    // Byte 31 (last in second block) XORs with 0x00 as reversed MSB is 0; byte 32 (start of third)
    // flips by 1 again
    assertEquals(input[31], output[31], "Last byte of second block unchanged");
    assertEquals(
        (byte) (input[32] ^ 0x02), output[32], "First byte of third block reflects counter == 2");

    // Verify keystream block generation count: ceil(33/16) == 3 blocks → 3 encipher calls total
    Mockito.verify(cipher, Mockito.times(3))
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));
  }

  @Test
  void processBytes_whenFirstBlockPartiallyConsumed_expectSameAsByteWise() {
    // Same reversing cipher as above
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128);
    Mockito.doAnswer(
            invocation -> {
              byte[] in = invocation.getArgument(0);
              byte[] out = invocation.getArgument(1);
              byte[] tmp = java.util.Arrays.copyOf(in, in.length);
              for (int i = 0; i < tmp.length; i++) out[i] = tmp[tmp.length - 1 - i];
              return null;
            })
        .when(cipher)
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));

    byte[] iv = new byte[16];

    byte[] plaintext = new byte[40];
    for (int i = 0; i < plaintext.length; i++) plaintext[i] = (byte) (i * 3 + 7);

    CTRBlockCipher ctrA = new CTRBlockCipher(cipher);
    ctrA.init(iv);
    byte[] outA = new byte[plaintext.length];
    // Consume 5 bytes via processByte() to put us mid-block
    for (int i = 0; i < 5; i++) outA[i] = ctrA.processByte(plaintext[i]);
    // Then bulk-process the remainder
    ctrA.processBytes(plaintext, 5, plaintext.length - 5, outA, 5);

    // Control: process the whole buffer in one go on a fresh instance
    CTRBlockCipher ctrB = new CTRBlockCipher(cipher);
    ctrB.init(iv);
    byte[] outB = new byte[plaintext.length];
    ctrB.processBytes(plaintext, 0, plaintext.length, outB, 0);

    assertArrayEquals(
        outB, outA, "Mixing byte-wise and bulk processing must match bulk-only result");
  }

  @Test
  void processBytes_whenZeroLength_expectNoAdditionalCipherInvocation() {
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128);
    Mockito.doAnswer(
            invocation -> {
              byte[] in = invocation.getArgument(0);
              byte[] out = invocation.getArgument(1);
              // reverse for determinism; handle in==out by copying first
              byte[] tmp = java.util.Arrays.copyOf(in, in.length);
              for (int i = 0; i < tmp.length; i++) out[i] = tmp[tmp.length - 1 - i];
              return null;
            })
        .when(cipher)
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));

    CTRBlockCipher ctr = new CTRBlockCipher(cipher);
    ctr.init(new byte[16]);

    byte[] in = new byte[0];
    byte[] out = new byte[0];
    ctr.processBytes(in, 0, 0, out, 0);

    // Only the init()-triggered block generation should have occurred
    Mockito.verify(cipher, Mockito.times(1))
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));
  }

  @Test
  void processBytes_whenMultipleBlocks_expectExpectedEncipherCalls() {
    BlockCipher cipher = Mockito.mock(BlockCipher.class);
    Mockito.when(cipher.getBlockSize()).thenReturn(128);
    Mockito.doAnswer(
            invocation -> {
              byte[] in = invocation.getArgument(0);
              byte[] out = invocation.getArgument(1);
              // reverse for determinism; handle in==out by copying first
              byte[] tmp = java.util.Arrays.copyOf(in, in.length);
              for (int i = 0; i < tmp.length; i++) out[i] = tmp[tmp.length - 1 - i];
              return null;
            })
        .when(cipher)
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));

    CTRBlockCipher ctr = new CTRBlockCipher(cipher);
    ctr.init(new byte[16]);

    byte[] input = new byte[16 * 3 + 5]; // spans 4 keystream blocks
    byte[] output = new byte[input.length];
    ctr.processBytes(input, 0, input.length, output, 0);

    // ceil((16*3+5)/16) == 4 total blocks → 4 encipher calls in total (including the one in init())
    Mockito.verify(cipher, Mockito.times(4))
        .encipher(Mockito.any(byte[].class), Mockito.any(byte[].class));
  }

  @Test
  void processBytes_whenUsingNistCtrVectors_expectMatchesReferenceCiphertexts()
      throws UnsupportedCipherException,
          NoSuchAlgorithmException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException,
          IllegalBlockSizeException,
          BadPaddingException {
    // AES-128 Encrypt
    // Arrange
    int bits = 128;
    byte[] key = NIST_128_ENCRYPT_KEY;
    byte[] iv = NIST_128_ENCRYPT_IV;
    byte[] plaintext = NIST_128_ENCRYPT_PLAINTEXT;
    byte[] expected = NIST_128_ENCRYPT_CIPHERTEXT;
    // Act
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] jcaOut = c.doFinal(plaintext);
      // Assert
      assertThat(jcaOut, equalTo(expected));
    }
    Rijndael rij128 = new Rijndael(bits, 128);
    rij128.initialize(key);
    CTRBlockCipher ctr128 = new CTRBlockCipher(rij128);
    ctr128.init(iv);
    byte[] out128 = new byte[plaintext.length];
    ctr128.processBytes(plaintext, 0, plaintext.length, out128, 0);
    assertThat(out128, equalTo(expected));

    // AES-128 Decrypt (same vectors; CTR is symmetric)
    // Arrange
    key = NIST_128_DECRYPT_KEY;
    iv = NIST_128_DECRYPT_IV;
    plaintext = NIST_128_DECRYPT_PLAINTEXT;
    expected = NIST_128_DECRYPT_CIPHERTEXT;
    // Act
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] jcaOut = c.doFinal(plaintext);
      // Assert
      assertThat(jcaOut, equalTo(expected));
    }
    Rijndael rij128d = new Rijndael(bits, 128);
    rij128d.initialize(key);
    CTRBlockCipher ctr128d = new CTRBlockCipher(rij128d);
    ctr128d.init(iv);
    byte[] out128d = new byte[plaintext.length];
    ctr128d.processBytes(plaintext, 0, plaintext.length, out128d, 0);
    assertThat(out128d, equalTo(expected));

    // AES-192 Encrypt
    // Arrange
    bits = 192;
    key = NIST_192_ENCRYPT_KEY;
    iv = NIST_192_ENCRYPT_IV;
    plaintext = NIST_192_ENCRYPT_PLAINTEXT;
    expected = NIST_192_ENCRYPT_CIPHERTEXT;
    // Act
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] jcaOut = c.doFinal(plaintext);
      // Assert
      assertThat(jcaOut, equalTo(expected));
    }
    Rijndael rij192 = new Rijndael(bits, 128);
    rij192.initialize(key);
    CTRBlockCipher ctr192 = new CTRBlockCipher(rij192);
    ctr192.init(iv);
    byte[] out192 = new byte[plaintext.length];
    ctr192.processBytes(plaintext, 0, plaintext.length, out192, 0);
    assertThat(out192, equalTo(expected));

    // AES-192 Decrypt
    // Arrange
    key = NIST_192_DECRYPT_KEY;
    iv = NIST_192_DECRYPT_IV;
    plaintext = NIST_192_DECRYPT_PLAINTEXT;
    expected = NIST_192_DECRYPT_CIPHERTEXT;
    // Act
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] jcaOut = c.doFinal(plaintext);
      // Assert
      assertThat(jcaOut, equalTo(expected));
    }
    Rijndael rij192d = new Rijndael(bits, 128);
    rij192d.initialize(key);
    CTRBlockCipher ctr192d = new CTRBlockCipher(rij192d);
    ctr192d.init(iv);
    byte[] out192d = new byte[plaintext.length];
    ctr192d.processBytes(plaintext, 0, plaintext.length, out192d, 0);
    assertThat(out192d, equalTo(expected));

    // AES-256 Encrypt
    // Arrange
    bits = 256;
    key = NIST_256_ENCRYPT_KEY;
    iv = NIST_256_ENCRYPT_IV;
    plaintext = NIST_256_ENCRYPT_PLAINTEXT;
    expected = NIST_256_ENCRYPT_CIPHERTEXT;
    // Act
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] jcaOut = c.doFinal(plaintext);
      // Assert
      assertThat(jcaOut, equalTo(expected));
    }
    Rijndael rij256 = new Rijndael(bits, 128);
    rij256.initialize(key);
    CTRBlockCipher ctr256 = new CTRBlockCipher(rij256);
    ctr256.init(iv);
    byte[] out256 = new byte[plaintext.length];
    ctr256.processBytes(plaintext, 0, plaintext.length, out256, 0);
    assertThat(out256, equalTo(expected));

    // AES-256 Decrypt
    // Arrange
    key = NIST_256_DECRYPT_KEY;
    iv = NIST_256_DECRYPT_IV;
    plaintext = NIST_256_DECRYPT_PLAINTEXT;
    expected = NIST_256_DECRYPT_CIPHERTEXT;
    // Act
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] jcaOut = c.doFinal(plaintext);
      // Assert
      assertThat(jcaOut, equalTo(expected));
    }
    Rijndael rij256d = new Rijndael(bits, 128);
    rij256d.initialize(key);
    CTRBlockCipher ctr256d = new CTRBlockCipher(rij256d);
    ctr256d.init(iv);
    byte[] out256d = new byte[plaintext.length];
    ctr256d.processBytes(plaintext, 0, plaintext.length, out256d, 0);
    assertThat(out256d, equalTo(expected));
  }

  // Note: decryptability is validated by testRandom() and checkNIST* helpers below.

  @Test
  @SuppressWarnings("java:S3776") // keep AAA clarity; inevitable loops/branches for vector sets
  void processBytes_whenChunkedAcrossRandomSizes_expectMatchesReferenceCiphertexts()
      throws UnsupportedCipherException,
          NoSuchAlgorithmException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException,
          IllegalBlockSizeException,
          BadPaddingException,
          ShortBufferException {
    // AES-128 Encrypt (random chunking)
    // Arrange
    int bits = 128;
    byte[] key = NIST_128_ENCRYPT_KEY;
    byte[] iv = NIST_128_ENCRYPT_IV;
    byte[] plaintext = NIST_128_ENCRYPT_PLAINTEXT;
    byte[] expected = NIST_128_ENCRYPT_CIPHERTEXT;
    long seed = mt.nextLong();
    // Act & Assert
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      MersenneTwister random = new MersenneTwister(seed);
      byte[] output = new byte[plaintext.length];
      int inputPtr = 0;
      int outputPtr = 0;
      while (inputPtr < plaintext.length) {
        int max = plaintext.length - inputPtr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        int moved = c.update(plaintext, inputPtr, count, output, outputPtr);
        outputPtr += moved;
        inputPtr += count;
      }
      c.doFinal(plaintext, 0, plaintext.length - inputPtr, output, outputPtr);
      assertThat(output, equalTo(expected));
    }
    Rijndael rij128 = new Rijndael(bits, 128);
    rij128.initialize(key);
    CTRBlockCipher ctr128 = new CTRBlockCipher(rij128);
    ctr128.init(iv);
    byte[] out128 = new byte[plaintext.length];
    MersenneTwister rnd128 = new MersenneTwister(seed);
    int ptr = 0;
    while (ptr < plaintext.length) {
      int max = plaintext.length - ptr;
      int count = (max == 1) ? 1 : (rnd128.nextInt(max - 1) + 1);
      ctr128.processBytes(plaintext, ptr, count, out128, ptr);
      ptr += count;
    }
    assertThat(out128, equalTo(expected));

    // AES-128 Decrypt
    key = NIST_128_DECRYPT_KEY;
    iv = NIST_128_DECRYPT_IV;
    plaintext = NIST_128_DECRYPT_PLAINTEXT;
    expected = NIST_128_DECRYPT_CIPHERTEXT;
    seed = mt.nextLong();
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      MersenneTwister random = new MersenneTwister(seed);
      byte[] output = new byte[plaintext.length];
      int inputPtr = 0;
      int outputPtr = 0;
      while (inputPtr < plaintext.length) {
        int max = plaintext.length - inputPtr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        int moved = c.update(plaintext, inputPtr, count, output, outputPtr);
        outputPtr += moved;
        inputPtr += count;
      }
      c.doFinal(plaintext, 0, plaintext.length - inputPtr, output, outputPtr);
      assertThat(output, equalTo(expected));
    }
    Rijndael rij128d = new Rijndael(bits, 128);
    rij128d.initialize(key);
    CTRBlockCipher ctr128d = new CTRBlockCipher(rij128d);
    ctr128d.init(iv);
    byte[] out128d = new byte[plaintext.length];
    MersenneTwister rnd128d = new MersenneTwister(seed);
    ptr = 0;
    while (ptr < plaintext.length) {
      int max = plaintext.length - ptr;
      int count = (max == 1) ? 1 : (rnd128d.nextInt(max - 1) + 1);
      ctr128d.processBytes(plaintext, ptr, count, out128d, ptr);
      ptr += count;
    }
    assertThat(out128d, equalTo(expected));

    // AES-192 Encrypt
    bits = 192;
    key = NIST_192_ENCRYPT_KEY;
    iv = NIST_192_ENCRYPT_IV;
    plaintext = NIST_192_ENCRYPT_PLAINTEXT;
    expected = NIST_192_ENCRYPT_CIPHERTEXT;
    seed = mt.nextLong();
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      MersenneTwister random = new MersenneTwister(seed);
      byte[] output = new byte[plaintext.length];
      int inputPtr = 0;
      int outputPtr = 0;
      while (inputPtr < plaintext.length) {
        int max = plaintext.length - inputPtr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        int moved = c.update(plaintext, inputPtr, count, output, outputPtr);
        outputPtr += moved;
        inputPtr += count;
      }
      c.doFinal(plaintext, 0, plaintext.length - inputPtr, output, outputPtr);
      assertThat(output, equalTo(expected));
    }
    Rijndael rij192 = new Rijndael(bits, 128);
    rij192.initialize(key);
    CTRBlockCipher ctr192 = new CTRBlockCipher(rij192);
    ctr192.init(iv);
    byte[] out192 = new byte[plaintext.length];
    MersenneTwister rnd192 = new MersenneTwister(seed);
    ptr = 0;
    while (ptr < plaintext.length) {
      int max = plaintext.length - ptr;
      int count = (max == 1) ? 1 : (rnd192.nextInt(max - 1) + 1);
      ctr192.processBytes(plaintext, ptr, count, out192, ptr);
      ptr += count;
    }
    assertThat(out192, equalTo(expected));

    // AES-192 Decrypt
    key = NIST_192_DECRYPT_KEY;
    iv = NIST_192_DECRYPT_IV;
    plaintext = NIST_192_DECRYPT_PLAINTEXT;
    expected = NIST_192_DECRYPT_CIPHERTEXT;
    seed = mt.nextLong();
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      MersenneTwister random = new MersenneTwister(seed);
      byte[] output = new byte[plaintext.length];
      int inputPtr = 0;
      int outputPtr = 0;
      while (inputPtr < plaintext.length) {
        int max = plaintext.length - inputPtr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        int moved = c.update(plaintext, inputPtr, count, output, outputPtr);
        outputPtr += moved;
        inputPtr += count;
      }
      c.doFinal(plaintext, 0, plaintext.length - inputPtr, output, outputPtr);
      assertThat(output, equalTo(expected));
    }
    Rijndael rij192d = new Rijndael(bits, 128);
    rij192d.initialize(key);
    CTRBlockCipher ctr192d = new CTRBlockCipher(rij192d);
    ctr192d.init(iv);
    byte[] out192d = new byte[plaintext.length];
    MersenneTwister rnd192d = new MersenneTwister(seed);
    ptr = 0;
    while (ptr < plaintext.length) {
      int max = plaintext.length - ptr;
      int count = (max == 1) ? 1 : (rnd192d.nextInt(max - 1) + 1);
      ctr192d.processBytes(plaintext, ptr, count, out192d, ptr);
      ptr += count;
    }
    assertThat(out192d, equalTo(expected));

    // AES-256 Encrypt
    bits = 256;
    key = NIST_256_ENCRYPT_KEY;
    iv = NIST_256_ENCRYPT_IV;
    plaintext = NIST_256_ENCRYPT_PLAINTEXT;
    expected = NIST_256_ENCRYPT_CIPHERTEXT;
    seed = mt.nextLong();
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      MersenneTwister random = new MersenneTwister(seed);
      byte[] output = new byte[plaintext.length];
      int inputPtr = 0;
      int outputPtr = 0;
      while (inputPtr < plaintext.length) {
        int max = plaintext.length - inputPtr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        int moved = c.update(plaintext, inputPtr, count, output, outputPtr);
        outputPtr += moved;
        inputPtr += count;
      }
      c.doFinal(plaintext, 0, plaintext.length - inputPtr, output, outputPtr);
      assertThat(output, equalTo(expected));
    }
    Rijndael rij256 = new Rijndael(bits, 128);
    rij256.initialize(key);
    CTRBlockCipher ctr256 = new CTRBlockCipher(rij256);
    ctr256.init(iv);
    byte[] out256 = new byte[plaintext.length];
    MersenneTwister rnd256 = new MersenneTwister(seed);
    ptr = 0;
    while (ptr < plaintext.length) {
      int max = plaintext.length - ptr;
      int count = (max == 1) ? 1 : (rnd256.nextInt(max - 1) + 1);
      ctr256.processBytes(plaintext, ptr, count, out256, ptr);
      ptr += count;
    }
    assertThat(out256, equalTo(expected));

    // AES-256 Decrypt
    key = NIST_256_DECRYPT_KEY;
    iv = NIST_256_DECRYPT_IV;
    plaintext = NIST_256_DECRYPT_PLAINTEXT;
    expected = NIST_256_DECRYPT_CIPHERTEXT;
    seed = mt.nextLong();
    if (TEST_JCA) {
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      MersenneTwister random = new MersenneTwister(seed);
      byte[] output = new byte[plaintext.length];
      int inputPtr = 0;
      int outputPtr = 0;
      while (inputPtr < plaintext.length) {
        int max = plaintext.length - inputPtr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        int moved = c.update(plaintext, inputPtr, count, output, outputPtr);
        outputPtr += moved;
        inputPtr += count;
      }
      c.doFinal(plaintext, 0, plaintext.length - inputPtr, output, outputPtr);
      assertThat(output, equalTo(expected));
    }
    Rijndael rij256d = new Rijndael(bits, 128);
    rij256d.initialize(key);
    CTRBlockCipher ctr256d = new CTRBlockCipher(rij256d);
    ctr256d.init(iv);
    byte[] out256d = new byte[plaintext.length];
    MersenneTwister rnd256d = new MersenneTwister(seed);
    ptr = 0;
    while (ptr < plaintext.length) {
      int max = plaintext.length - ptr;
      int count = (max == 1) ? 1 : (rnd256d.nextInt(max - 1) + 1);
      ctr256d.processBytes(plaintext, ptr, count, out256d, ptr);
      ptr += count;
    }
    assertThat(out256d, equalTo(expected));
  }

  @Test
  void jcaAesCtr_whenEncryptThenDecrypt_expectRoundTripPlaintext()
      throws NoSuchAlgorithmException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException,
          IllegalBlockSizeException,
          BadPaddingException {
    if (!TEST_JCA) {
      return;
    }
    for (int i = 0; i < 1024; i++) {
      // Arrange
      byte[] plaintext = new byte[mt.nextInt(4096) + 1];
      byte[] key = new byte[32];
      byte[] iv = new byte[16];
      mt.nextBytes(plaintext);
      mt.nextBytes(key);
      mt.nextBytes(iv);

      // Act
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher c = newAesCtrCipher();
      c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] output = c.doFinal(plaintext);
      c = newAesCtrCipher();
      c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
      byte[] decrypted = c.doFinal(output);

      // Assert
      assertThat(decrypted, equalTo(plaintext));
    }
  }

  @Test
  void processBytes_whenEncryptDecryptAndRandomChunks_expectRoundTripAndJcaParity()
      throws UnsupportedCipherException,
          NoSuchAlgorithmException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException,
          IllegalBlockSizeException,
          BadPaddingException {
    for (int i = 0; i < 1024; i++) {
      // Arrange
      byte[] plaintext = new byte[mt.nextInt(4096) + 1];
      byte[] key = new byte[32];
      byte[] iv = new byte[16];
      mt.nextBytes(plaintext);
      mt.nextBytes(key);
      mt.nextBytes(iv);

      // Act: encrypt full buffer once
      Rijndael cipher = new Rijndael(256, 128);
      cipher.initialize(key);
      CTRBlockCipher ctr = new CTRBlockCipher(cipher);
      ctr.init(iv);
      byte[] ciphertext = new byte[plaintext.length];
      ctr.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

      // Act: decrypt and re-check
      ctr = new CTRBlockCipher(cipher);
      ctr.init(iv);
      byte[] finalPlaintext = new byte[plaintext.length];
      ctr.processBytes(ciphertext, 0, ciphertext.length, finalPlaintext, 0);

      // Assert
      assertThat(finalPlaintext, equalTo(plaintext));

      // Arrange for JCA comparison
      if (TEST_JCA) {
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        Cipher c = newAesCtrCipher();
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
        byte[] jcaOut = c.doFinal(plaintext);
        assertThat(jcaOut, equalTo(ciphertext));
        c = newAesCtrCipher();
        c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
        byte[] decrypted = c.doFinal(jcaOut);
        assertThat(decrypted, equalTo(plaintext));
      }

      // Act: encrypt again in random pieces
      cipher.initialize(key);
      ctr = new CTRBlockCipher(cipher);
      ctr.init(iv);
      byte[] output = new byte[plaintext.length];
      MersenneTwister random = new MersenneTwister(mt.nextLong());
      int ptr = 0;
      while (ptr < plaintext.length) {
        int max = plaintext.length - ptr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        ctr.processBytes(plaintext, ptr, count, output, ptr);
        ptr += count;
      }
      // Assert
      assertThat(output, equalTo(ciphertext));
    }
  }

  // (No private helpers; tests use explicit AAA structure.)

  byte[] NIST_128_ENCRYPT_KEY = HexUtil.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
  private static final String NIST_IV_HEX = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
  byte[] NIST_128_ENCRYPT_IV = HexUtil.hexToBytes(NIST_IV_HEX);
  byte[] NIST_128_ENCRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  byte[] NIST_128_ENCRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "874d6191b620e3261bef6864990db6ce"
              + "9806f66b7970fdff8617187bb9fffdff"
              + "5ae4df3edbd5d35e5b4f09020db03eab"
              + "1e031dda2fbe03d1792170a0f3009cee");
  byte[] NIST_128_DECRYPT_KEY = HexUtil.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
  byte[] NIST_128_DECRYPT_IV = HexUtil.hexToBytes(NIST_IV_HEX);
  byte[] NIST_128_DECRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  byte[] NIST_128_DECRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "874d6191b620e3261bef6864990db6ce"
              + "9806f66b7970fdff8617187bb9fffdff"
              + "5ae4df3edbd5d35e5b4f09020db03eab"
              + "1e031dda2fbe03d1792170a0f3009cee");
  byte[] NIST_192_ENCRYPT_KEY =
      HexUtil.hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
  byte[] NIST_192_ENCRYPT_IV = HexUtil.hexToBytes(NIST_IV_HEX);
  byte[] NIST_192_ENCRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  byte[] NIST_192_ENCRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "1abc932417521ca24f2b0459fe7e6e0b"
              + "090339ec0aa6faefd5ccc2c6f4ce8e94"
              + "1e36b26bd1ebc670d1bd1d665620abf7"
              + "4f78a7f6d29809585a97daec58c6b050");
  byte[] NIST_192_DECRYPT_KEY =
      HexUtil.hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
  byte[] NIST_192_DECRYPT_IV = HexUtil.hexToBytes(NIST_IV_HEX);
  byte[] NIST_192_DECRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  byte[] NIST_192_DECRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "1abc932417521ca24f2b0459fe7e6e0b"
              + "090339ec0aa6faefd5ccc2c6f4ce8e94"
              + "1e36b26bd1ebc670d1bd1d665620abf7"
              + "4f78a7f6d29809585a97daec58c6b050");
  byte[] NIST_256_ENCRYPT_KEY =
      HexUtil.hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
  byte[] NIST_256_ENCRYPT_IV = HexUtil.hexToBytes(NIST_IV_HEX);
  byte[] NIST_256_ENCRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  byte[] NIST_256_ENCRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "601ec313775789a5b7a7f504bbf3d228"
              + "f443e3ca4d62b59aca84e990cacaf5c5"
              + "2b0930daa23de94ce87017ba2d84988d"
              + "dfc9c58db67aada613c2dd08457941a6");
  byte[] NIST_256_DECRYPT_KEY =
      HexUtil.hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
  byte[] NIST_256_DECRYPT_IV = HexUtil.hexToBytes(NIST_IV_HEX);
  byte[] NIST_256_DECRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  byte[] NIST_256_DECRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "601ec313775789a5b7a7f504bbf3d228"
              + "f443e3ca4d62b59aca84e990cacaf5c5"
              + "2b0930daa23de94ce87017ba2d84988d"
              + "dfc9c58db67aada613c2dd08457941a6");
  private final MersenneTwister mt = new MersenneTwister(1634);
}
