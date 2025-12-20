package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.HexUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

// 256,256 PCFB is the same as 256,256 CFB, however JCA does not support 256-bit block size, so we
// can't
// test against JCA. We will move to the standard block size, and stop using PCFB, eventually, but
// we'll
// need PCFB for a while if only for old keys, so we need to test it.
@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PCFBModeTest {

  private final Random mt = new Random(1634L);
  private static final int RIJNDAEL_BLOCK_BITS = 256;

  // FIXME I don't think there are any standard test vectors?
  private static final byte[] PCFB_256_ENCRYPT_KEY =
      HexUtil.hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
  // FIXME This IV was tailored for CTR mode and 128-bit block, maybe needs adjustment
  private static final byte[] PCFB_256_ENCRYPT_IV =
      HexUtil.hexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  // FIXME This plaintext was tailored for 128-bit block, maybe needs adjustment
  private static final byte[] PCFB_256_ENCRYPT_PLAINTEXT =
      HexUtil.hexToBytes(
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710");
  private static final byte[] PCFB_256_ENCRYPT_CIPHERTEXT =
      HexUtil.hexToBytes(
          "c964b00326e216214f1a68f5b0872608"
              + "1b403c92fe02898664a81f5bbbbf8341"
              + "fc1d04b2c1addfb826cca1eab6813127"
              + "2751b9d6cd536f78059b10b4867dbbd9");

  private static final byte[] PCFB_256_DECRYPT_KEY = PCFB_256_ENCRYPT_KEY;
  private static final byte[] PCFB_256_DECRYPT_IV = PCFB_256_ENCRYPT_IV;
  private static final byte[] PCFB_256_DECRYPT_PLAINTEXT = PCFB_256_ENCRYPT_PLAINTEXT;
  private static final byte[] PCFB_256_DECRYPT_CIPHERTEXT = PCFB_256_ENCRYPT_CIPHERTEXT;

  @Test
  void blockEncipherDecipher_withKnownVectors_expectExactMatch() throws UnsupportedCipherException {
    // Rijndael(256,256)
    checkKnownValues(
        PCFB_256_ENCRYPT_KEY,
        PCFB_256_ENCRYPT_IV,
        PCFB_256_ENCRYPT_PLAINTEXT,
        PCFB_256_ENCRYPT_CIPHERTEXT);
    checkKnownValues(
        PCFB_256_DECRYPT_KEY,
        PCFB_256_DECRYPT_IV,
        PCFB_256_DECRYPT_PLAINTEXT,
        PCFB_256_DECRYPT_CIPHERTEXT);
  }

  @Test
  void blockEncipherDecipher_withKnownVectorsRandomChunking_expectExactMatch()
      throws UnsupportedCipherException {
    // Rijndael(256,256)
    checkKnownValuesRandomLength(
        PCFB_256_ENCRYPT_KEY,
        PCFB_256_ENCRYPT_IV,
        PCFB_256_ENCRYPT_PLAINTEXT,
        PCFB_256_ENCRYPT_CIPHERTEXT);
    checkKnownValuesRandomLength(
        PCFB_256_DECRYPT_KEY,
        PCFB_256_DECRYPT_IV,
        PCFB_256_DECRYPT_PLAINTEXT,
        PCFB_256_DECRYPT_CIPHERTEXT);
  }

  private void checkKnownValues(byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext)
      throws UnsupportedCipherException {
    Rijndael cipher = new Rijndael(RIJNDAEL_BLOCK_BITS, RIJNDAEL_BLOCK_BITS);
    cipher.initialize(key);
    PCFBMode pcfb = PCFBMode.create(cipher, iv);
    pcfb.reset(iv);
    byte[] output = new byte[plaintext.length];
    System.arraycopy(plaintext, 0, output, 0, plaintext.length);
    pcfb.blockEncipher(output, 0, output.length);
    assertArrayEquals(output, ciphertext);
    pcfb.reset(iv);
    pcfb.blockDecipher(output, 0, output.length);
    assertArrayEquals(output, plaintext);
  }

  private void checkKnownValuesRandomLength(
      byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext)
      throws UnsupportedCipherException {
    for (int i = 0; i < 1024; i++) {
      long seed = mt.nextLong();

      Rijndael cipher = new Rijndael(RIJNDAEL_BLOCK_BITS, RIJNDAEL_BLOCK_BITS);
      cipher.initialize(key);
      PCFBMode pcfb = PCFBMode.create(cipher, iv);
      pcfb.reset(iv);
      byte[] output = new byte[plaintext.length];
      Random random = new Random(seed);
      int ptr = 0;
      System.arraycopy(plaintext, 0, output, 0, plaintext.length);
      while (ptr < plaintext.length) {
        int max = plaintext.length - ptr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        pcfb.blockEncipher(output, ptr, count);
        ptr += count;
      }
      assertArrayEquals(output, ciphertext);
      pcfb.reset(iv);
      ptr = 0;
      while (ptr < plaintext.length) {
        int max = plaintext.length - ptr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        pcfb.blockDecipher(output, ptr, count);
        ptr += count;
      }
      assertArrayEquals(output, plaintext);
    }
  }

  @Test
  void blockEncipherDecipher_randomRoundtrip_expectOriginalPlaintext()
      throws UnsupportedCipherException {
    for (int i = 0; i < 1024; i++) {
      byte[] plaintext = new byte[mt.nextInt(4096) + 1];
      byte[] key = new byte[32];
      byte[] iv = new byte[32];
      mt.nextBytes(plaintext);
      mt.nextBytes(key);
      mt.nextBytes(iv);
      // First encrypt as a block.
      Rijndael cipher = new Rijndael(RIJNDAEL_BLOCK_BITS, RIJNDAEL_BLOCK_BITS);
      cipher.initialize(key);
      PCFBMode pcfb = PCFBMode.create(cipher, iv);
      pcfb.reset(iv);
      byte[] ciphertext = new byte[plaintext.length];
      System.arraycopy(plaintext, 0, ciphertext, 0, ciphertext.length);
      pcfb.blockEncipher(ciphertext, 0, ciphertext.length);
      // Now decrypt.
      pcfb = PCFBMode.create(cipher, iv);
      pcfb.reset(iv);
      byte[] finalPlaintext = new byte[plaintext.length];
      System.arraycopy(ciphertext, 0, finalPlaintext, 0, ciphertext.length);
      pcfb.blockDecipher(finalPlaintext, 0, finalPlaintext.length);
      assertArrayEquals(finalPlaintext, plaintext);

      // Now encrypt again, in random pieces.
      cipher.initialize(key);
      pcfb = PCFBMode.create(cipher, iv);
      pcfb.reset(iv);
      byte[] output = new byte[plaintext.length];

      Random random = new Random(mt.nextLong());
      int ptr = 0;
      System.arraycopy(plaintext, 0, output, 0, plaintext.length);
      while (ptr < plaintext.length) {
        int max = plaintext.length - ptr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        pcfb.blockEncipher(output, ptr, count);
        ptr += count;
      }
      assertArrayEquals(output, ciphertext);
      // ... and decrypt again, in random pieces.
      ptr = 0;
      pcfb.reset(iv);
      while (ptr < plaintext.length) {
        int max = plaintext.length - ptr;
        int count = (max == 1) ? 1 : (random.nextInt(max - 1) + 1);
        pcfb.blockDecipher(output, ptr, count);
        ptr += count;
      }
      assertArrayEquals(output, plaintext);
    }
  }

  // --- Additional focused behavior tests ---

  @Test
  void lengthIV_matchesCipherBlockSizeBytes() {
    BlockCipher c = new ToyCipher(128);
    PCFBMode pcfb = createZeroIv(c);
    assertEquals(16, PCFBMode.lengthIV(c));
    assertEquals(16, pcfb.lengthIV());
  }

  @Test
  void create_withIVAndOffset_producesSameKeystreamAsDirectIV() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    for (int i = 0; i < iv.length; i++) iv[i] = (byte) (0xA0 + i);
    byte[] buf = new byte[64];
    int offset = 7;
    System.arraycopy(iv, 0, buf, offset, iv.length);
    PCFBMode a = PCFBMode.create(c, iv);
    PCFBMode b = PCFBMode.create(c, buf, offset);
    int aByte = a.encipher(0x00);
    int bByte = b.encipher(0x00);
    assertEquals(aByte, bByte);
  }

  @Test
  void reset_whenCalled_updatesIVAndPointer() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv1 = new byte[16];
    byte[] iv2 = new byte[16];
    for (int i = 0; i < 16; i++) {
      iv1[i] = (byte) i;
      iv2[i] = (byte) (0xF0 + i);
    }
    PCFBMode x = PCFBMode.create(c, iv1);
    // consume one byte so pointer advances
    x.encipher(0x00);
    // reset to iv2 and compare with a fresh instance
    x.reset(iv2);
    PCFBMode y = PCFBMode.create(c, iv2);
    assertEquals(y.encipher(0x00), x.encipher(0x00));
  }

  @Test
  void writeIV_whenCalled_writesRandomIVAndSetsState() throws IOException {
    BlockCipher c = new ToyCipher(128);
    PCFBMode p = createZeroIv(c);
    DeterministicRandom rs = new DeterministicRandom((byte) 0x5A);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    p.writeIV(rs, out);
    byte[] written = out.toByteArray();
    // Expect 16 bytes starting at 0x5A, 0x5B, ...
    byte[] expected = new byte[16];
    for (int i = 0; i < expected.length; i++) expected[i] = (byte) (0x5A + i);
    assertArrayEquals(expected, written);
    // Next keystream byte equals fresh instance with same IV
    PCFBMode q = PCFBMode.create(c, written);
    assertEquals(q.encipher(0x00), p.encipher(0x00));
  }

  @Test
  void readIV_whenCalled_readsExactIVAndSetsState() throws IOException {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    for (int i = 0; i < iv.length; i++) iv[i] = (byte) (0x20 + i);
    PCFBMode p = createZeroIv(c);
    p.readIV(new ByteArrayInputStream(iv));
    PCFBMode q = PCFBMode.create(c, iv);
    assertEquals(q.encipher(0x00), p.encipher(0x00));
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 7, 16, 17, 31, 32, 33, 64})
  void blockEncipherDecipher_variousLengths_expectRoundtrip(int len) {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    for (int i = 0; i < iv.length; i++) iv[i] = (byte) (0x40 + i);
    byte[] plain = new byte[len];
    for (int i = 0; i < len; i++) plain[i] = (byte) (i * 3 + 1);
    byte[] enc = plain.clone();
    PCFBMode encP = PCFBMode.create(c, iv);
    encP.blockEncipher(enc, 0, enc.length);
    byte[] dec = enc.clone();
    PCFBMode decP = PCFBMode.create(c, iv);
    decP.blockDecipher(dec, 0, dec.length);
    assertArrayEquals(plain, dec);
  }

  @Test
  void blockEncipher_withOffset_doesNotTouchBytesOutsideRange() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    PCFBMode p = PCFBMode.create(c, iv);
    byte[] buf = new byte[10 + 25 + 10];
    for (int i = 0; i < buf.length; i++) buf[i] = (byte) i;
    byte[] before = buf.clone();
    p.blockEncipher(buf, 10, 25);
    // untouched prefix
    for (int i = 0; i < 10; i++) assertEquals(before[i], buf[i]);
    // untouched suffix
    for (int i = 35; i < buf.length; i++) assertEquals(before[i], buf[i]);
  }

  @Test
  void encipherAndDecipher_singleByteSequence_expectInverse() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    for (int i = 0; i < iv.length; i++) iv[i] = (byte) (0x70 + i);
    PCFBMode enc = PCFBMode.create(c, iv);
    PCFBMode dec = PCFBMode.create(c, iv);
    for (int i = 0; i < 40; i++) {
      int pt = (i * 7 + 3) & 0xFF;
      int ct = enc.encipher(pt);
      int rt = dec.decipher(ct);
      assertEquals(pt, rt);
    }
  }

  @Test
  void blockEncipher_withZeroLength_isNoOpAndDoesNotRefill() {
    BlockCipher c = spy(new ToyCipher(128));
    byte[] iv = new byte[16];
    PCFBMode p = PCFBMode.create(c, iv);
    byte[] buf = new byte[8];
    p.blockEncipher(buf, 0, 0);
    verify(c, times(0)).encipher(any(byte[].class), any(byte[].class));
  }

  @Test
  void blockEncipher_callsUnderlyingCipherExpectedTimes() {
    BlockCipher c = spy(new ToyCipher(128));
    byte[] iv = new byte[16];
    PCFBMode p = PCFBMode.create(c, iv);
    byte[] buf = new byte[33]; // ceil(33/16) = 3 refills
    p.blockEncipher(buf, 0, buf.length);
    verify(c, times(3)).encipher(any(byte[].class), any(byte[].class));
  }

  @Test
  void create_withInvalidOffset_throwsArrayIndexOutOfBounds() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    byte[] bigger = new byte[31];
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> PCFBMode.create(c, bigger, 20));
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> PCFBMode.create(c, iv, -1));
  }

  @Test
  void reset_withInvalidOffset_throwsArrayIndexOutOfBounds() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    byte[] bigger = new byte[31];
    PCFBMode p = PCFBMode.create(c, iv);
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> p.reset(bigger, 20));
  }

  @Test
  @DisplayName("block methods accept zero length without throwing")
  void blockMethods_withZeroLength_doNotThrow() {
    BlockCipher c = new ToyCipher(128);
    byte[] iv = new byte[16];
    PCFBMode p = PCFBMode.create(c, iv);
    byte[] buf = new byte[0];
    assertDoesNotThrow(() -> p.blockEncipher(buf, 0, 0));
    assertDoesNotThrow(() -> p.blockDecipher(buf, 0, 0));
  }

  // --- helpers ---

  /** Simple deterministic block cipher for tests: XORs bytes with a repeating key stream. */
  private static final class ToyCipher implements BlockCipher {
    private final int blockSizeBits;
    private byte[] key = new byte[16];

    ToyCipher(int blockSizeBits) {
      this.blockSizeBits = blockSizeBits;
      for (int i = 0; i < key.length; i++) key[i] = (byte) (0xA5 ^ i);
    }

    @Override
    public void initialize(byte[] key) {
      if (key != null && key.length > 0) {
        this.key = key.clone();
      }
    }

    @Override
    public int getKeySize() {
      return 8 * key.length;
    }

    @Override
    public int getBlockSize() {
      return blockSizeBits;
    }

    @Override
    public void encipher(byte[] block, byte[] result) {
      for (int i = 0; i < blockSizeBits / 8; i++) {
        result[i] = (byte) (block[i] ^ key[i % key.length] ^ (byte) (i * 3 + 1));
      }
    }

    @Override
    public void decipher(byte[] block, byte[] result) {
      // same as encipher (XOR), not used by PCFBMode
      encipher(block, result);
    }
  }

  /** Deterministic RandomSource that emits an increasing byte sequence starting at a seed. */
  private static final class DeterministicRandom extends RandomSource {
    private byte next;

    DeterministicRandom(byte start) {
      this.next = start;
    }

    @Override
    public void nextBytes(byte[] bytes) {
      for (int i = 0; i < bytes.length; i++) bytes[i] = next++;
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // Intentionally no-op for tests: this deterministic RandomSource does not acquire resources
      // (no files, sockets, or threads) that need releasing. Keeping it empty avoids unnecessary
      // complexity in test helpers while complying with the RandomSource contract.
    }
  }

  private static PCFBMode createZeroIv(BlockCipher c) {
    return PCFBMode.create(c, new byte[PCFBMode.lengthIV(c)]);
  }
}
