package network.crypta.crypt;

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class MasterSecretTest {

  private static byte[] fixedSecret;

  @BeforeAll
  static void setUpSecret() {
    // Deterministic 64-byte secret accepted by the constructor
    fixedSecret = new byte[64];
    for (int i = 0; i < fixedSecret.length; i++) {
      fixedSecret[i] = (byte) (0xA5 ^ i); // simple, deterministic pattern
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  @DisplayName("constructor_whenNull_throwsNullPointerException")
  void constructor_whenNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new MasterSecret(null));
  }

  @Test
  @DisplayName("constructor_whenWrongLength_throwsIllegalArgumentException")
  void constructor_whenWrongLength_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new MasterSecret(new byte[63]));
    assertThrows(IllegalArgumentException.class, () -> new MasterSecret(new byte[65]));
  }

  @ParameterizedTest(name = "deriveKey_matches_KDF_for_{0}")
  @EnumSource(KeyType.class)
  void deriveKey_whenTypeValid_matchesExpectedDerivation(KeyType type) throws Exception {
    // Arrange
    MasterSecret ms = new MasterSecret(fixedSecret);
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, fixedSecret);

    // Act
    SecretKey actual = ms.deriveKey(type);
    SecretKey expected =
        KeyGenUtils.deriveSecretKey(kdfKey, MasterSecret.class, type.kdfLabel + " key", type);

    // Assert
    assertNotNull(actual, "derived SecretKey must not be null");
    assertEquals(type.alg, actual.getAlgorithm(), "algorithm should match KeyType.alg");
    assertEquals(type.keySize >> 3, actual.getEncoded().length, "key length in bytes");
    assertArrayEquals(expected.getEncoded(), actual.getEncoded(), "derived key bytes");
  }

  @ParameterizedTest(name = "deriveIv_matches_KDF_for_{0}")
  @EnumSource(KeyType.class)
  void deriveIv_whenTypeValid_matchesExpectedDerivation(KeyType type) throws Exception {
    // Arrange
    MasterSecret ms = new MasterSecret(fixedSecret);
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, fixedSecret);

    // Act
    IvParameterSpec actual = ms.deriveIv(type);
    IvParameterSpec expected =
        KeyGenUtils.deriveIvParameterSpec(kdfKey, MasterSecret.class, type.kdfLabel + " iv", type);

    // Assert
    assertNotNull(actual, "derived IV must not be null");
    assertEquals(type.ivSize >> 3, actual.getIV().length, "IV length in bytes");
    assertArrayEquals(expected.getIV(), actual.getIV(), "derived IV bytes");
  }

  @Test
  @DisplayName("deriveKey_whenNullType_throwsNullPointerException")
  void deriveKey_whenNullType_throwsNullPointerException() {
    MasterSecret ms = new MasterSecret(fixedSecret);
    assertThrows(NullPointerException.class, () -> ms.deriveKey(null));
  }

  @Test
  @DisplayName("deriveIv_whenNullType_throwsNullPointerException")
  void deriveIv_whenNullType_throwsNullPointerException() {
    MasterSecret ms = new MasterSecret(fixedSecret);
    assertThrows(NullPointerException.class, () -> ms.deriveIv(null));
  }

  @Test
  @DisplayName("deriveKey_whenDifferentTypes_producesDifferentMaterial")
  void deriveKey_whenDifferentTypes_producesDifferentMaterial() {
    MasterSecret ms = new MasterSecret(fixedSecret);
    byte[] a = ms.deriveKey(KeyType.AES_128).getEncoded();
    byte[] b = ms.deriveKey(KeyType.AES_256).getEncoded();
    assertFalse(Arrays.equals(a, b), "different types should derive different keys");
  }

  @Test
  @DisplayName("deriveKey_vs_deriveIv_forSameType_produceDifferentBytes")
  void deriveKey_vs_deriveIv_forSameType_produceDifferentBytes() {
    MasterSecret ms = new MasterSecret(fixedSecret);
    byte[] key = ms.deriveKey(KeyType.HMAC_SHA512).getEncoded();
    byte[] iv = ms.deriveIv(KeyType.HMAC_SHA512).getIV();
    // Same size (64 bytes) but distinct KDF context strings → should differ
    assertFalse(Arrays.equals(key, iv), "key and iv derivations must differ");
  }

  @Test
  @DisplayName("equalsHashCode_whenSameSecret_areEqualWithSameHash")
  void equalsHashCode_whenSameSecret_areEqualWithSameHash() {
    MasterSecret a = new MasterSecret(fixedSecret);
    MasterSecret b = new MasterSecret(fixedSecret.clone());

    assertEquals(a, b, "objects with same secret must be equal");
    assertEquals(a.hashCode(), b.hashCode(), "equal objects must have same hashCode");
  }

  @Test
  @DisplayName("equals_whenDifferentSecret_areNotEqual")
  void equals_whenDifferentSecret_areNotEqual() {
    byte[] other = fixedSecret.clone();
    other[0] = (byte) (other[0] ^ (byte) 0xFF);
    MasterSecret a = new MasterSecret(fixedSecret);
    MasterSecret b = new MasterSecret(other);
    assertNotEquals(a, b, "different secrets must not be equal");
  }

  @Test
  @DisplayName("equals_whenComparedToNullOrDifferentClass_returnsFalse")
  void equals_whenComparedToNullOrDifferentClass_returnsFalse() {
    MasterSecret a = new MasterSecret(fixedSecret);
    assertNotEquals(null, a);
    assertNotEquals(new Object(), a);
  }
}
