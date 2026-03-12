package network.crypta.crypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import network.crypta.support.Fields;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class MessageAuthCodeTest {

  // Known-good test vectors (RFC 4231 for HMAC; BC vectors for Poly1305-AES)
  private static final byte[] HMAC_KEY = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  private static final byte[] HMAC_MSG = "Hi There".getBytes(StandardCharsets.UTF_8);

  private static final byte[] POLY_KEY =
      Hex.decode("e285000e6080a701a410040f4814470b568d149b821f99d41319e6410094a760");
  private static final IvParameterSpec POLY_IV =
      new IvParameterSpec(Hex.decode("166450152e2394835606a9d1dd2cdc8b"));
  private static final byte[] POLY_MSG = Hex.decode("66f75c0e0c7a406586");

  private static final byte[] HMAC256 =
      Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  private static final byte[] HMAC384 =
      Hex.decode(
          "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7"
              + "f4af152e8b2fa9cb6");
  private static final byte[] HMAC512 =
      Hex.decode(
          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a70"
              + "2038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
  private static final byte[] POLY_TAG = Hex.decode("1644272eee3b30b7f82568425e817756");

  @BeforeAll
  static void loadProviders() {
    // Ensure Poly1305-AES is available for tests that require it.
    Security.addProvider(new BouncyCastleProvider());
  }

  private static Arguments vector(
      MACType type, byte[] key, byte[] msg, IvParameterSpec iv, byte[] tag) {
    return Arguments.of(type, key, msg, iv, tag);
  }

  private static java.util.stream.Stream<Arguments> macVectors() {
    return java.util.stream.Stream.of(
        vector(MACType.HMAC_SHA256, HMAC_KEY, HMAC_MSG, null, HMAC256),
        vector(MACType.HMAC_SHA384, HMAC_KEY, HMAC_MSG, null, HMAC384),
        vector(MACType.HMAC_SHA512, HMAC_KEY, HMAC_MSG, null, HMAC512),
        vector(MACType.POLY1305_AES, POLY_KEY, POLY_MSG, POLY_IV, POLY_TAG));
  }

  private static MessageAuthCode newMac(MACType type, byte[] key, IvParameterSpec iv)
      throws InvalidKeyException {
    if (type.ivlen == -1) {
      return new MessageAuthCode(type, key);
    }
    return new MessageAuthCode(type, key, iv);
  }

  @ParameterizedTest(name = "addByte_whenFeedingOneByOne_expectKnownTag [{index}] {0}")
  @MethodSource("macVectors")
  void addByte_whenFeedingOneByOne_expectKnownTag(
      MACType type, byte[] key, byte[] msg, IvParameterSpec iv, byte[] expected)
      throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = newMac(type, key, iv);

    // Act
    for (byte b : msg) {
      mac.addByte(b);
    }
    byte[] tag = Fields.copyToArray(mac.genMac());

    // Assert
    assertArrayEquals(expected, tag);
  }

  @ParameterizedTest(name = "addBytesByteBuffer_whenConsumed_expectKnownTag [{index}] {0}")
  @MethodSource("macVectors")
  void addBytesByteBuffer_whenConsumed_expectKnownTag(
      MACType type, byte[] key, byte[] msg, IvParameterSpec iv, byte[] expected)
      throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = newMac(type, key, iv);
    ByteBuffer buf = ByteBuffer.wrap(msg);

    // Act
    mac.addBytes(buf);
    byte[] tag = Fields.copyToArray(mac.genMac());

    // Assert
    assertArrayEquals(expected, tag);
  }

  @ParameterizedTest(name = "genMacVarargs_whenReset_expectKnownTag [{index}] {0}")
  @MethodSource("macVectors")
  void genMacVarargs_whenReset_expectKnownTag(
      MACType type, byte[] key, byte[] msg, IvParameterSpec iv, byte[] expected)
      throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = newMac(type, key, iv);
    mac.addBytes(new byte[] {0x01, 0x02, 0x03}); // will be cleared by genMac(varargs)

    // Act
    byte[] tag = Fields.copyToArray(mac.genMac(msg));

    // Assert
    assertArrayEquals(expected, tag);
  }

  @Test
  void genMac_whenCalled_returnsArrayBackedBufferWithOffsetZero() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);
    mac.addBytes(HMAC_MSG);

    // Act
    ByteBuffer out = mac.genMac();

    // Assert
    assertTrue(out.hasArray());
    assertEquals(0, out.arrayOffset());
  }

  @Test
  void addBytesVarargs_whenContainsNull_expectNullPointerException() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> mac.addBytes(HMAC_MSG, null));
  }

  @Test
  void addBytesByteBuffer_whenNull_expectIllegalArgumentException() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> mac.addBytes((ByteBuffer) null));
  }

  @Test
  void addBytesArraySlice_whenOutOfBounds_expectIllegalArgumentException()
      throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> mac.addBytes(HMAC_MSG, -1, 3));
    assertThrows(
        IllegalArgumentException.class, () -> mac.addBytes(HMAC_MSG, 0, HMAC_MSG.length + 1));
  }

  @Test
  void addBytesArraySlice_whenNull_expectNullPointerException() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> mac.addBytes(null, 0, 1));
  }

  @Test
  void verifyByteArray_whenSameRefAndNulls_expectTruthiness() {
    // Arrange
    byte[] a = new byte[] {1, 2, 3};

    // Act + Assert
    assertTrue(MessageAuthCode.verify(a, a));
    assertTrue(MessageAuthCode.verify(null, (byte[]) null));
    assertFalse(MessageAuthCode.verify(null, a));
    assertFalse(MessageAuthCode.verify(a, null));
    assertFalse(MessageAuthCode.verify(new byte[] {1, 2}, new byte[] {1, 2, 3}));
  }

  @Test
  void verifyByteBuffer_whenEqual_expectTrueAndBuffersConsumed() {
    // Arrange
    ByteBuffer b1 = ByteBuffer.wrap(new byte[] {9, 8, 7});
    ByteBuffer b2 = ByteBuffer.wrap(new byte[] {9, 8, 7});

    // Act
    boolean ok = MessageAuthCode.verify(b1, b2);

    // Assert
    assertTrue(ok);
    assertEquals(0, b1.remaining());
    assertEquals(0, b2.remaining());
  }

  @Test
  @DisplayName("verifyData(byte[]) whenMatches returns true; whenNot, false")
  void verifyData_withByteArray_expectTrueThenFalse() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = newMac(MACType.HMAC_SHA256, HMAC_KEY, null);
    byte[] trueTag = Fields.copyToArray(mac.genMac(HMAC_MSG));

    // Act + Assert
    assertTrue(mac.verifyData(trueTag, HMAC_MSG));
    assertFalse(mac.verifyData(new byte[] {0, 1, 2}, HMAC_MSG));
  }

  @Test
  void verifyData_withByteBuffer_expectTrue() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = newMac(MACType.HMAC_SHA256, HMAC_KEY, null);
    ByteBuffer msg = ByteBuffer.wrap(HMAC_MSG);
    ByteBuffer tag = mac.genMac(ByteBuffer.wrap(HMAC_MSG));

    // Act
    boolean ok = mac.verifyData(tag, msg);

    // Assert
    assertTrue(ok);
  }

  @Test
  void getKey_whenConstructed_returnsSameMaterial() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act
    byte[] roundTrip = mac.getKey().getEncoded();

    // Assert
    assertArrayEquals(HMAC_KEY, roundTrip);
  }

  @Test
  void getIv_whenUnsupportedType_expectUnsupportedTypeException() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act + Assert
    assertThrows(UnsupportedTypeException.class, mac::getIv);
  }

  @Test
  void setIV_whenUnsupportedType_expectUnsupportedTypeException() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);
    IvParameterSpec dummy = new IvParameterSpec(new byte[16]);

    // Act + Assert
    assertThrows(UnsupportedTypeException.class, () -> mac.setIV(dummy));
  }

  @Test
  void genIV_whenUnsupportedType_expectUnsupportedTypeException() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.HMAC_SHA256, HMAC_KEY);

    // Act + Assert
    assertThrows(UnsupportedTypeException.class, mac::genIV);
  }

  @Test
  void setIV_whenNullForPoly1305_expectInvalidAlgorithmParameterException()
      throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.POLY1305_AES, POLY_KEY, POLY_IV);

    // Act + Assert
    assertThrows(InvalidAlgorithmParameterException.class, () -> mac.setIV(null));
  }

  @Test
  void genIV_whenPoly1305_returnsCorrectLength() throws InvalidKeyException {
    // Arrange
    MessageAuthCode mac = new MessageAuthCode(MACType.POLY1305_AES, POLY_KEY, POLY_IV);

    // Act
    byte[] iv = mac.genIV().getIV();

    // Assert
    assertNotNull(iv);
    assertEquals(MACType.POLY1305_AES.ivlen, iv.length);
  }

  @Test
  void constructor_withPoly1305AndInvalidKeyLength_expectIllegalArgumentException() {
    // Arrange: 16-byte invalid key for Poly1305-AES (must be 32 bytes)
    byte[] badKey = new byte[16];
    SecretKey key = new SecretKeySpec(badKey, "POLY1305-AES");

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> new MessageAuthCode(MACType.POLY1305_AES, key, POLY_IV));
  }

  @Test
  void constructor_withPoly1305AndNoIv_expectIllegalArgumentException() {
    // Arrange: valid key but invoking ctor without IV is not allowed for IV-requiring algos
    SecretKey key = new SecretKeySpec(POLY_KEY, "POLY1305-AES");

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> new MessageAuthCode(MACType.POLY1305_AES, key));
  }
}
