package network.crypta.crypt.ciphers;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.HexFormat;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // test method naming convention per project rules
class RijndaelAlgorithmTest {

  // Helpers
  private static byte[] hex(String s) {
    return HexFormat.of().parseHex(s);
  }

  @Test
  @DisplayName("blockSize returns AES default (128-bit)")
  void blockSize_whenCalled_returns16() {
    assertEquals(16, RijndaelAlgorithm.blockSize());
  }

  @Test
  @DisplayName("makeKey null/invalid length throws InvalidKeyException")
  void makeKey_whenNullOrInvalid_throws() {
    assertThrows(InvalidKeyException.class, () -> RijndaelAlgorithm.makeKey(null, 16));
    // not 16/24/32
    assertThrows(InvalidKeyException.class, () -> RijndaelAlgorithm.makeKey(new byte[15], 16));
  }

  @Test
  @DisplayName("makeKey with unsupported block size (192-bit) throws InvalidKeyException")
  void makeKey_whenUnsupportedBlockSize_throws() {
    byte[] key128 = new byte[16];
    assertThrows(InvalidKeyException.class, () -> RijndaelAlgorithm.makeKey(key128, 24));
  }

  @Test
  @DisplayName("AES-128 ECB known vector encrypt/decrypt")
  void blockEncryptDecrypt128_whenKnownVector_matchesExpected() throws Exception {
    // NIST FIPS-197 C.1 example
    byte[] key = hex("000102030405060708090A0B0C0D0E0F");
    byte[] pt = hex("00112233445566778899AABBCCDDEEFF");
    byte[] expectedCt = hex("69C4E0D86A7B0430D8CDB78070B4C55A");

    Object sessionKey = RijndaelAlgorithm.makeKey(key, 16);
    byte[] out = new byte[16];
    RijndaelAlgorithm.blockEncrypt(pt, out, 0, sessionKey, 16);
    assertArrayEquals(expectedCt, out, "AES-128 encrypt KAT");

    byte[] roundtrip = new byte[16];
    RijndaelAlgorithm.blockDecrypt(out, roundtrip, 0, sessionKey, 16);
    assertArrayEquals(pt, roundtrip, "AES-128 decrypt KAT");
  }

  @Test
  @DisplayName("AES-128 encrypt with non-zero inOffset")
  void blockEncrypt_whenNonZeroInOffset_encryptsSameBlock() throws Exception {
    byte[] key = hex("000102030405060708090A0B0C0D0E0F");
    byte[] block = hex("00112233445566778899AABBCCDDEEFF");
    Object sessionKey = RijndaelAlgorithm.makeKey(key, 16);

    byte[] direct = new byte[16];
    RijndaelAlgorithm.blockEncrypt(block, direct, 0, sessionKey, 16);

    // Place the same block at offset 5 in a larger array
    byte[] withPrefix = new byte[5 + 16 + 3];
    System.arraycopy(block, 0, withPrefix, 5, 16);
    byte[] viaOffset = new byte[16];
    RijndaelAlgorithm.blockEncrypt(withPrefix, viaOffset, 5, sessionKey, 16);

    assertArrayEquals(direct, viaOffset, "Encrypting at an offset matches direct encryption");
  }

  @ParameterizedTest(name = "AES-{0} round-trip, block 128")
  @MethodSource("keySizes128")
  void blockEncryptDecrypt128_whenRoundTrip_succeeds(int keyBytes) throws Exception {
    byte[] key = new byte[keyBytes];
    for (int i = 0; i < key.length; i++) key[i] = (byte) i; // deterministic
    byte[] pt = new byte[16];
    for (int i = 0; i < pt.length; i++) pt[i] = (byte) (i * 3 + 1);

    Object sessionKey = RijndaelAlgorithm.makeKey(key, 16);
    byte[] ct = new byte[16];
    RijndaelAlgorithm.blockEncrypt(pt, ct, 0, sessionKey, 16);
    byte[] back = new byte[16];
    RijndaelAlgorithm.blockDecrypt(ct, back, 0, sessionKey, 16);
    assertArrayEquals(pt, back);
  }

  private static Stream<Arguments> keySizes128() {
    return Stream.of(Arguments.of(16), Arguments.of(24), Arguments.of(32));
  }

  @ParameterizedTest(name = "Rijndael-{0}/block256 round-trip")
  @MethodSource("keySizes128")
  void blockEncryptDecrypt256_whenRoundTrip_succeeds(int keyBytes) throws Exception {
    byte[] key = new byte[keyBytes];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (0xA0 + i);
    byte[] pt = new byte[32];
    for (int i = 0; i < pt.length; i++) pt[i] = (byte) (i ^ 0x5A);

    Object sessionKey = RijndaelAlgorithm.makeKey(key, 32);
    byte[] ct = new byte[32];
    RijndaelAlgorithm.blockEncrypt(pt, ct, 0, sessionKey, 32);
    byte[] back = new byte[32];
    RijndaelAlgorithm.blockDecrypt(ct, back, 0, sessionKey, 32);
    assertArrayEquals(pt, back);
  }

  @Test
  @DisplayName("Decrypt with wrong key does not yield original plaintext")
  void blockDecrypt_whenWrongKey_producesDifferentPlaintext() throws Exception {
    byte[] key1 = hex("000102030405060708090A0B0C0D0E0F");
    byte[] key2 = hex("0F0E0D0C0B0A09080706050403020100");
    byte[] pt = hex("00112233445566778899AABBCCDDEEFF");
    Object sessionKey1 = RijndaelAlgorithm.makeKey(key1, 16);
    byte[] ct = new byte[16];
    RijndaelAlgorithm.blockEncrypt(pt, ct, 0, sessionKey1, 16);

    Object sessionKey2 = RijndaelAlgorithm.makeKey(key2, 16);
    byte[] wrong = new byte[16];
    RijndaelAlgorithm.blockDecrypt(ct, wrong, 0, sessionKey2, 16);

    assertNotEquals(
        new String(pt, StandardCharsets.UTF_8),
        new String(wrong, StandardCharsets.UTF_8),
        "Wrong key should not decrypt to original");
    // Ensure byte-wise inequality too
    boolean equal = true;
    for (int i = 0; i < pt.length; i++)
      if (pt[i] != wrong[i]) {
        equal = false;
        break;
      }
    assertFalse(equal);
  }

  @Test
  @DisplayName("self_test basic symmetry check")
  void selftest_whenCalled_returnsTrue() {
    assertTrue(RijndaelAlgorithm.selfTest());
  }
}
