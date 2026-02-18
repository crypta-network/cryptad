package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Test naming convention: method_whenCondition_expectOutcome
class CryptByteBufferTypeTest {
  private static final String ALG_CHACHA = "CHACHA";
  private static final String ALG_AES_CTR_NOPADDING = "AES/CTR/NOPADDING";

  @Test
  @DisplayName("hasIV returns true and ivSize > 0 for all current types")
  void hasIV_whenAllCurrentTypes_expectTrueAndPositiveIvSize() {
    for (CryptByteBufferType type : CryptByteBufferType.values()) {
      assertAll(
          type.name(),
          () -> assertTrue(type.hasIV(), "hasIV must agree with ivSize nullness"),
          () -> {
            // Current contract: all supported types require an IV/nonce and expose a non-null size.
            // Therefore, assert ivSize is non-null and positive for every enum constant.
            assertNotNull(type.ivSize, "ivSize should not be null when hasIV is true");
            assertTrue(type.ivSize > 0, "ivSize should be positive");
          });
    }
  }

  @Test
  @DisplayName("cipherName matches KeyType.alg for all types")
  void cipherName_whenComparedToKeyType_expectMatch() {
    for (CryptByteBufferType type : CryptByteBufferType.values()) {
      assertEquals(type.keyType.alg, type.cipherName, type.name());
    }
  }

  @Test
  @DisplayName("bitmasks are unique across types")
  void bitmask_whenCheckedForUniqueness_expectNoCollisions() {
    java.util.HashSet<Integer> unique = new java.util.HashSet<>();
    for (CryptByteBufferType type : CryptByteBufferType.values()) {
      boolean added = unique.add(type.bitmask);
      assertTrue(added, "Duplicate bitmask detected for: " + type.name());
    }
  }

  @ParameterizedTest(name = "{0} blockSize, algName, isStreamCipher, ivSize")
  @MethodSource("expectedProperties")
  void properties_whenUsingEnumConstants_expectDefinedValues(
      CryptByteBufferType type,
      int expectedBlockSizeBits,
      String expectedAlgName,
      boolean expectedIsStream,
      int expectedIvSizeBytes,
      KeyType expectedKeyType,
      String expectedCipherName) {
    assertAll(
        type.name(),
        () -> assertEquals(expectedBlockSizeBits, type.blockSize, "blockSize (bits)"),
        () -> assertEquals(expectedAlgName, type.algName, "algName"),
        () -> assertEquals(expectedIsStream, type.isStreamCipher, "isStreamCipher"),
        () -> assertEquals(expectedIvSizeBytes, type.ivSize, "ivSize (bytes)"),
        () -> assertEquals(expectedKeyType, type.keyType, "keyType"),
        () -> assertEquals(expectedCipherName, type.cipherName, "cipherName"));
  }

  static Stream<Arguments> expectedProperties() {
    return Stream.of(
        Arguments.of(
            CryptByteBufferType.AESCTR,
            256, // AES256 key size appears as blockSize in this type
            ALG_AES_CTR_NOPADDING,
            true,
            16,
            KeyType.AES_256,
            "AES"),
        Arguments.of(
            CryptByteBufferType.CHACHA_128,
            128,
            ALG_CHACHA,
            true,
            8,
            KeyType.CHACHA_128,
            ALG_CHACHA),
        Arguments.of(
            CryptByteBufferType.CHACHA_256,
            256,
            ALG_CHACHA,
            true,
            8,
            KeyType.CHACHA_256,
            ALG_CHACHA));
  }

  @ParameterizedTest(name = "{0} is serializable and preserves identity")
  @MethodSource("serializableTypes")
  void serialization_whenRoundTripped_expectSameEnumConstant(CryptByteBufferType type)
      throws Exception {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(bout)) {
      oos.writeObject(type);
    }
    CryptByteBufferType restored;
    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
      Object obj = ois.readObject();
      restored = (CryptByteBufferType) obj;
    }
    assertEquals(type, restored, "Enum identity must be preserved after serialization");
  }

  static Stream<CryptByteBufferType> serializableTypes() {
    return Stream.of(CryptByteBufferType.values());
  }
}
