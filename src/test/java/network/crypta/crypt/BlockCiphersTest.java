package network.crypta.crypt;

import java.lang.reflect.Field;
import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings({"java:S100", "java:S3011"})
class BlockCiphersTest {
  private static final byte[] PLAINTEXT_BLOCK =
      new byte[] {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        (byte) 0x88,
        (byte) 0x99,
        (byte) 0xAA,
        (byte) 0xBB,
        (byte) 0xCC,
        (byte) 0xDD,
        (byte) 0xEE,
        (byte) 0xFF
      };

  @Test
  void aes_blockSizeAndName_expectedValues() {
    BlockCipher cipher = BlockCiphers.aes();
    assertEquals(16, cipher.getBlockSize(), "AES block size must be 16 bytes");
    assertEquals("AES", cipher.getAlgorithmName(), "Algorithm name should be AES");
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 24, 32})
  void aes_roundTrip_withValidKeySizes_restoresPlaintext(int keySize) {
    BlockCipher enc = BlockCiphers.aes();
    BlockCipher dec = BlockCiphers.aes();
    byte[] key = new byte[keySize];
    for (int i = 0; i < key.length; i++) key[i] = (byte) i; // deterministic key

    enc.init(true, new KeyParameter(key));
    dec.init(false, new KeyParameter(key));

    byte[] in = Arrays.copyOf(PLAINTEXT_BLOCK, PLAINTEXT_BLOCK.length);
    byte[] ct = new byte[enc.getBlockSize()];
    byte[] pt = new byte[enc.getBlockSize()];

    int produced = enc.processBlock(in, 0, ct, 0);
    assertEquals(enc.getBlockSize(), produced);
    produced = dec.processBlock(ct, 0, pt, 0);
    assertEquals(dec.getBlockSize(), produced);
    assertArrayEquals(PLAINTEXT_BLOCK, pt);
  }

  @Test
  void aes_processBlock_allowsInPlaceOperation() {
    BlockCipher cipher = BlockCiphers.aes();
    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (0xF0 ^ i);
    cipher.init(true, new KeyParameter(key));

    byte[] buf = Arrays.copyOf(PLAINTEXT_BLOCK, PLAINTEXT_BLOCK.length);
    byte[] orig = Arrays.copyOf(buf, buf.length);
    int produced = cipher.processBlock(buf, 0, buf, 0);
    assertEquals(cipher.getBlockSize(), produced);
    assertNotEquals(
        Arrays.toString(orig), Arrays.toString(buf), "Ciphertext should differ in-place");

    cipher.init(false, new KeyParameter(key));
    produced = cipher.processBlock(buf, 0, buf, 0);
    assertEquals(cipher.getBlockSize(), produced);
    assertArrayEquals(orig, buf, "Decrypting in-place should restore original");
  }

  @Test
  void init_withInvalidKeyLength_throwsIllegalArgumentException() {
    BlockCipher cipher = BlockCiphers.aes();
    byte[] badKey = new byte[15]; // not 16/24/32
    KeyParameter bad = new KeyParameter(badKey);
    assertThrows(IllegalArgumentException.class, () -> cipher.init(true, bad));
  }

  @Test
  void processBlock_outTooShort_throwsDataLengthOrCopyBoundsDependingOnImpl() {
    BlockCipher cipher = BlockCiphers.aes();
    byte[] key = new byte[16];
    cipher.init(true, new KeyParameter(key));

    byte[] in = Arrays.copyOf(PLAINTEXT_BLOCK, PLAINTEXT_BLOCK.length);
    byte[] out = new byte[cipher.getBlockSize() - 1]; // intentionally too short

    if (cipher instanceof BlockCiphers.JceEcbBlockCipher) {
      // JCE wrapper writes to its internal buffer, then copies to 'out' → arraycopy throws
      assertThrows(IndexOutOfBoundsException.class, () -> cipher.processBlock(in, 0, out, 0));
    } else {
      // BouncyCastle engine validates sizes and throws DataLengthException
      assertThrows(DataLengthException.class, () -> cipher.processBlock(in, 0, out, 0));
    }
  }

  @Test
  void processBlock_inTooShort_throwsDataLengthOrArrayBoundsDependingOnImpl() {
    BlockCipher cipher = BlockCiphers.aes();
    byte[] key = new byte[16];
    cipher.init(true, new KeyParameter(key));

    byte[] in = new byte[cipher.getBlockSize() - 1]; // too short input
    byte[] out = new byte[cipher.getBlockSize()];

    if (cipher instanceof BlockCiphers.JceEcbBlockCipher) {
      try {
        cipher.processBlock(in, 0, out, 0);
        throw new AssertionError("Expected an exception for too-short input");
      } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException _) {
        // acceptable for various JCE providers
      }
    } else {
      assertThrows(DataLengthException.class, () -> cipher.processBlock(in, 0, out, 0));
    }
  }

  @Test
  void jce_reset_zerosInternalBuffer_whenJceAvailable() throws Exception {
    // Skip when JCE AES/ECB is unavailable on this runtime
    BlockCiphers.JceEcbBlockCipher jce;
    try {
      jce = new BlockCiphers.JceEcbBlockCipher("AES");
    } catch (Exception e) {
      Assumptions.assumeTrue(false, "JCE AES not available: " + e.getMessage());
      return;
    }

    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 3 + 1);
    jce.init(true, new KeyParameter(key));
    byte[] out = new byte[16];
    jce.processBlock(PLAINTEXT_BLOCK, 0, out, 0); // fills internal buf with ciphertext

    Field bufField = BlockCiphers.JceEcbBlockCipher.class.getDeclaredField("buf");
    bufField.setAccessible(true);
    byte[] buf = (byte[]) bufField.get(jce);
    // Sanity: buffer now contains non-zero values after encryption
    boolean hasNonZero = false;
    for (byte b : buf) {
      if (b != 0) {
        hasNonZero = true;
        break;
      }
    }
    Assumptions.assumeTrue(hasNonZero);

    jce.reset();
    for (byte b : buf) {
      assertEquals(0, b, "reset() must zero the internal buffer");
    }
  }

  @Test
  void compatibility_withBouncyCastle_encryptSingleBlock_matchesSelectedCipher() {
    BlockCipher selected = BlockCiphers.aes();
    BlockCipher bc = AESEngine.newInstance();

    byte[] key = new byte[16];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (0xA5 ^ i);
    KeyParameter kp = new KeyParameter(key);

    selected.init(true, kp);
    bc.init(true, kp);

    byte[] expected = new byte[16];
    byte[] actual = new byte[16];
    assertEquals(16, bc.processBlock(PLAINTEXT_BLOCK, 0, expected, 0));
    assertEquals(16, selected.processBlock(PLAINTEXT_BLOCK, 0, actual, 0));
    assertArrayEquals(expected, actual);
  }
}
