package network.crypta.crypt;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class HMACTest {

  private static final byte[] PLAINTEXT = "Hi There".getBytes(StandardCharsets.US_ASCII);
  // RFC4868 2.7.2.1 SHA256 Authentication Test Vector
  private static final byte[] KNOWN_KEY =
      HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  private static final byte[] KNOWN_SHA256 =
      HexFormat.of().parseHex("198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7");

  @Test
  @DisplayName("mac_whenUsingAllEnumValues_returnsDigestWithoutError")
  void mac_whenUsingAllEnumValues_returnsDigestWithoutError() {
    for (HMAC hmac : HMAC.values()) {
      byte[] key = new byte[hmac.digestSize];
      byte[] result = assertDoesNotThrow(() -> HMAC.mac(hmac, key, PLAINTEXT));
      assertNotNull(result);
      assertEquals(hmac.digestSize, result.length);
    }
  }

  @Test
  @DisplayName("macWithSHA256_whenKnownVector_matchesRFC4868")
  void macWithSHA256_whenKnownVector_matchesRFC4868() {
    byte[] h = HMAC.macWithSHA256(KNOWN_KEY, PLAINTEXT);
    assertArrayEquals(KNOWN_SHA256, h);
  }

  @Test
  @DisplayName("verifyWithSHA256_whenCorrectMac_returnsTrue")
  void verifyWithSHA256_whenCorrectMac_returnsTrue() {
    byte[] mac = HMAC.macWithSHA256(KNOWN_KEY, PLAINTEXT);
    assertTrue(HMAC.verifyWithSHA256(KNOWN_KEY, PLAINTEXT, mac));
  }

  @Test
  @DisplayName("verifyWithSHA256_whenIncorrectMac_returnsFalse")
  void verifyWithSHA256_whenIncorrectMac_returnsFalse() {
    byte[] mac = HMAC.macWithSHA256(KNOWN_KEY, PLAINTEXT);
    mac[mac.length - 1] ^= 0x01; // flip last bit
    assertFalse(HMAC.verifyWithSHA256(KNOWN_KEY, PLAINTEXT, mac));
  }

  @ParameterizedTest(name = "keySize={0}")
  @CsvSource({"31", "33", "0", "1", "64"})
  @DisplayName("mac_whenWrongKeySize_throwsIllegalArgumentException")
  void mac_whenWrongKeySize_throwsIllegalArgumentException(int keySize) {
    byte[] badKey = new byte[keySize];
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> HMAC.macWithSHA256(badKey, PLAINTEXT));
    assertTrue(ex.getMessage().contains("Wrong keysize!"), "Message should mention wrong key size");
  }

  @Test
  @DisplayName("mac_whenEmptyData_returnsDigestWithExpectedLength")
  void mac_whenEmptyData_returnsDigestWithExpectedLength() {
    byte[] key = new byte[HMAC.SHA2_256.digestSize];
    byte[] result = HMAC.macWithSHA256(key, new byte[0]);
    assertNotNull(result);
    assertEquals(32, result.length);
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  @DisplayName("mac_whenNullKey_throwsNullPointerException")
  void mac_whenNullKey_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> HMAC.mac(HMAC.SHA2_256, null, PLAINTEXT));
  }

  @Test
  @DisplayName("mac_whenNullData_treatedAsEmptyAndSucceeds")
  void mac_whenNullData_treatedAsEmptyAndSucceeds() {
    byte[] key = new byte[HMAC.SHA2_256.digestSize];
    byte[] expected = HMAC.mac(HMAC.SHA2_256, key, new byte[0]);
    byte[] actual = HMAC.mac(HMAC.SHA2_256, key, null);
    assertArrayEquals(expected, actual);
  }

  @Test
  @DisplayName("verify_whenNullMac_returnsFalse")
  void verify_whenNullMac_returnsFalse() {
    byte[] key = new byte[HMAC.SHA2_256.digestSize];
    assertFalse(HMAC.verify(HMAC.SHA2_256, key, PLAINTEXT, null));
  }
}
