package network.crypta.crypt;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import network.crypta.support.HexUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class KeyGenUtilsTest {
  private static final int TRUE_LENGTH = 16;
  private static final int FALSE_LENGTH = -1;
  private static final KeyType[] keyTypes = KeyType.values();
  private static final byte[][] trueSecretKeys = {
    HexUtil.hexToBytes("20e86dc31ebf2c0e37670e30f8f45c57"),
    HexUtil.hexToBytes("8c6c2e0a60b3b73e9dbef076b68b686bacc9d20081e8822725d14b10b5034f48"),
    HexUtil.hexToBytes("33a4a38b71c8e350d3a98357d1bc9ecd"),
    HexUtil.hexToBytes("be56dbec20bff9f6f343800367287b48c0c28bf47f14b46aad3a32e4f24f0f5e"),
    HexUtil.hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    HexUtil.hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    HexUtil.hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    HexUtil.hexToBytes("a92e3fa63e8cbe50869fb352d883911271bf2b0e9048ad04c013b20e901f5806"),
    HexUtil.hexToBytes("45d6c9656b3b115263ba12739e90dcc1"),
    HexUtil.hexToBytes("f468986cbaeecabd4cf242607ac602b51a1adaf4f9a4fc5b298970cbda0b55c6")
  };

  private static final byte[][] trueLengthSecretKeys = {
    HexUtil.hexToBytes("20e86dc31ebf2c0e37670e30f8f45c57"),
    HexUtil.hexToBytes("8c6c2e0a60b3b73e9dbef076b68b686bacc9d20081e8822725d14b10b5034f48"),
    HexUtil.hexToBytes("33a4a38b71c8e350d3a98357d1bc9ecd"),
    HexUtil.hexToBytes("be56dbec20bff9f6f343800367287b48c0c28bf47f14b46aad3a32e4f24f0f5e"),
    HexUtil.hexToBytes("2e3e4a8f7c896ebf95fc3a59f283ca1e2808d984ad9043e710f74c4a8f4c8372"),
    HexUtil.hexToBytes(
        "c9f1731f7e996603c6e1f8f72da8a66e51dd8bbc2465f1a9f4d32f800c41ac28"
            + "f99fe0c1d811678f91300cf33e527436"),
    HexUtil.hexToBytes(
        "2ada39975c02c442e5ebc34832cde05e718acb28e15cdf80c8ab1da9c05bb53c"
            + "0b026c88a32aee65a924c9ea0b4e6cf5d2d434489d8bb82dfe7876919f690a56"),
    HexUtil.hexToBytes("a92e3fa63e8cbe50869fb352d883911271bf2b0e9048ad04c013b20e901f5806"),
    HexUtil.hexToBytes("45d6c9656b3b115263ba12739e90dcc1"),
    HexUtil.hexToBytes("f468986cbaeecabd4cf242607ac602b51a1adaf4f9a4fc5b298970cbda0b55c6")
  };

  private static final KeyPairType[] trueKeyPairTypes = {
    KeyPairType.ECP256, KeyPairType.ECP384, KeyPairType.ECP521
  };

  private static final byte[][] truePublicKeys = {
    HexUtil.hexToBytes(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200040126491fbe391419f"
            + "cdca058122a8520a816d3b7af9bc3a3af038e455b311b8234e5915ae2da11550a9f0ff9da5c65257"
            + "c95c2bd3d5c21bcf16f6c15a94a50cb"),
    HexUtil.hexToBytes(
        "3076301006072a8648ce3d020106052b81040022036200043a095518fc49cfaf6feb5af"
            + "01cf71c02ebfff4fe581d93c6e252c8c607e6568db7267e0b958c4a262a6e6fa7c18572c3af59cd1"
            + "6535a28759d04488bae6c3014bbb4b89c25cbe3b76d7b540dabb13aed5793eb3ce572811b560bb18"
            + "b00a5ac93"),
    HexUtil.hexToBytes(
        "30819b301006072a8648ce3d020106052b8104002303818600040076083359c8b0b34a9"
            + "03461e435188cb90f7501bcb7ed97e8c506c5b60ff21178a625f80f5729ed4746d8e83b28145a51b"
            + "9495880bf41b8ff0746ea0fe684832cc100ef1b01793c84abf64f31452d95bf0ef43d32440d8bc0d"
            + "67501fcffaf51ae4956e5ff22f3baffea5edddbebbeed0ec3b4af28d18568aaf97b5cd026f675388"
            + "1e0c4")
  };
  private static final PublicKey[] publicKeys = new PublicKey[truePublicKeys.length];
  private static final byte[][] truePrivateKeys = {
    HexUtil.hexToBytes(
        "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420f"
            + "8cb4b29aa51153ba811461e93fd1b2e69a127972f7100c5e246a3b2dcdd1b1c"),
    HexUtil.hexToBytes(
        "304e020100301006072a8648ce3d020106052b81040022043730350201010430b88fe05"
            + "d03b20dca95f19cb0fbabdfef1211452b29527ccac2ea37236d31ab6e7cada08315c62912b5c17cd"
            + "f2d87fa3d"),
    HexUtil.hexToBytes(
        "3060020100301006072a8648ce3d020106052b8104002304493047020101044201b4f57"
            + "3157d51f2e64a8b465fa92e52bae3529270951d448c18e4967beaa04b1f1fedb0e7a1e26f2eefb30"
            + "566a479e1194358670b044fae438d11717eb2a795c3a8")
  };
  private static final PrivateKey[] privateKeys = new PrivateKey[truePublicKeys.length];

  private static final byte[] trueIV = new byte[16];

  private static final String KDF_INPUT = "testKey";

  static {
    Security.addProvider(new BouncyCastleProvider());
    KeyPairType type;
    KeyFactory kf;
    X509EncodedKeySpec xks;
    PKCS8EncodedKeySpec pks;
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      try {
        type = trueKeyPairTypes[i];
        kf = KeyFactory.getInstance(type.alg);
        xks = new X509EncodedKeySpec(truePublicKeys[i]);
        publicKeys[i] = kf.generatePublic(xks);
        pks = new PKCS8EncodedKeySpec(truePrivateKeys[i]);
        privateKeys[i] = kf.generatePrivate(pks);
      } catch (GeneralSecurityException e) {
        throw new Error(e); // Classpath error?
      }
    }
  }

  @Test
  void genKeyPair_whenTypeSupported_expectNotNull() {
    // Arrange
    // types provided by trueKeyPairTypes
    for (KeyPairType type : trueKeyPairTypes) {
      // Act
      KeyPair pair = KeyGenUtils.genKeyPair(type);

      // Assert
      assertNotNull(pair, "KeyPairType: " + type.name());
    }
  }

  @Test
  void genKeyPair_whenTypeProvided_expectPublicKeyLengthMatchesFixture() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];

      // Act
      byte[] publicKey = KeyGenUtils.genKeyPair(type).getPublic().getEncoded();

      // Assert
      assertEquals(truePublicKeys[i].length, publicKey.length, "KeyPairType: " + type.name());
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void genKeyPair_whenNullType_expectNullPointerException() {
    // Arrange
    // Act + Assert
    assertThrows(NullPointerException.class, () -> KeyGenUtils.genKeyPair(null));
  }

  @Test
  void getPublicKey_whenValidBytes_expectSameEncoding() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      byte[] encoded = truePublicKeys[i];

      // Act
      PublicKey key = KeyGenUtils.getPublicKey(type, encoded);

      // Assert
      assertArrayEquals(key.getEncoded(), encoded, "KeyPairType: " + type.name());
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void getPublicKey_whenNullType_expectNullPointerException() {
    // Arrange
    byte[] encoded = truePublicKeys[0];

    // Act + Assert
    assertThrows(NullPointerException.class, () -> KeyGenUtils.getPublicKey(null, encoded));
  }

  @Test
  void getPublicKey_whenNullBytes_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.getPublicKey(trueKeyPairTypes[0], (byte[]) null));
  }

  @Test
  void getPublicKeyPair_whenValidBytes_expectPublicSetAndPrivateNull() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      byte[] encoded = truePublicKeys[i];

      // Act
      KeyPair key = KeyGenUtils.getPublicKeyPair(type, encoded);

      // Assert
      assertArrayEquals(key.getPublic().getEncoded(), encoded, "KeyPairType: " + type.name());
      assertNull(key.getPrivate(), "KeyPairType: " + type.name());
    }
  }

  @Test
  void getPublicKey_whenValidBytes_expectNotNull() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      byte[] encoded = truePublicKeys[i];

      // Act
      PublicKey key = KeyGenUtils.getPublicKey(type, encoded);

      // Assert
      assertNotNull(key, "KeyPairType: " + type.name());
    }
  }

  @Test
  void getPublicKeyPair_whenNullType_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> KeyGenUtils.getPublicKeyPair(null, truePublicKeys[0]));
  }

  @Test
  void getPublicKeyPair_whenNullBytes_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.getPublicKeyPair(trueKeyPairTypes[0], (byte[]) null));
  }

  @Test
  void getKeyPair_whenTypeAndEncodedKeysProvided_expectKeyPairNotNull() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      byte[] pub = truePublicKeys[i];
      byte[] prv = truePrivateKeys[i];

      // Act
      KeyPair pair = KeyGenUtils.getKeyPair(type, pub, prv);

      // Assert
      assertNotNull(pair, "KeyPairType: " + type.name());
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void getKeyPair_whenNullType_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.getKeyPair(null, truePublicKeys[0], truePrivateKeys[0]));
  }

  @Test
  void getKeyPair_whenNullPublicKeyBytes_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.getKeyPair(trueKeyPairTypes[0], null, truePrivateKeys[0]));
  }

  @Test
  void getKeyPair_whenNullPrivateKeyBytes_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.getKeyPair(trueKeyPairTypes[0], truePublicKeys[0], null));
  }

  @Test
  void getKeyPair_whenPublicAndPrivateKeysProvided_expectNotNull() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      PublicKey pub = publicKeys[i];
      PrivateKey prv = privateKeys[i];

      // Act
      KeyPair pair = KeyGenUtils.getKeyPair(pub, prv);

      // Assert
      assertNotNull(pair, "KeyPairType: " + trueKeyPairTypes[i].name());
    }
  }

  @Test
  void getKeyPair_whenPublicAndPrivateKeysProvided_expectSamePublic() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      PublicKey pub = publicKeys[i];
      PrivateKey prv = privateKeys[i];

      // Act
      KeyPair pair = KeyGenUtils.getKeyPair(pub, prv);

      // Assert
      assertEquals(pair.getPublic(), pub, "KeyPairType: " + trueKeyPairTypes[i].name());
    }
  }

  @Test
  void getKeyPair_whenPublicAndPrivateKeysProvided_expectSamePrivate() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      PublicKey pub = publicKeys[i];
      PrivateKey prv = privateKeys[i];

      // Act
      KeyPair pair = KeyGenUtils.getKeyPair(pub, prv);

      // Assert
      assertEquals(pair.getPrivate(), prv, "KeyPairType: " + trueKeyPairTypes[i].name());
    }
  }

  @Test
  void genSecretKey_whenTypeProvided_expectNotNull() {
    for (KeyType type : keyTypes) {
      // Arrange
      // type from iteration

      // Act
      SecretKey key = KeyGenUtils.genSecretKey(type);

      // Assert
      assertNotNull(key, "KeyType: " + type.name());
    }
  }

  @Test
  void genSecretKey_whenTypeProvided_expectCorrectLength() {
    for (KeyType type : keyTypes) {
      // Arrange
      int keySizeBytes = type.keySize >> 3;

      // Act
      byte[] key = KeyGenUtils.genSecretKey(type).getEncoded();

      // Assert
      assertEquals(keySizeBytes, key.length, "KeyType: " + type.name());
    }
  }

  @Test
  void genSecretKey_whenNullType_expectNullPointerException() {
    // Arrange
    // Act + Assert
    assertThrows(NullPointerException.class, () -> KeyGenUtils.genSecretKey(null));
  }

  @Test
  void getSecretKey_whenTypeAndBytesProvided_expectEqualEncoding() {
    for (int i = 0; i < keyTypes.length; i++) {
      // Arrange
      KeyType type = keyTypes[i];
      byte[] material = trueLengthSecretKeys[i];

      // Act
      SecretKey newKey = KeyGenUtils.getSecretKey(type, material);

      // Assert
      assertArrayEquals(material, newKey.getEncoded(), "KeyType: " + type.name());
    }
  }

  @Test
  void getSecretKey_whenNullBytes_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> KeyGenUtils.getSecretKey(keyTypes[1], (byte[]) null));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void getSecretKey_whenNullType_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> KeyGenUtils.getSecretKey(null, trueSecretKeys[0]));
  }

  @Test
  void getSecretKey_whenNonHmacWrongLength_expectIllegalArgumentException() {
    // AES-128 expects 16 bytes; supply 15 bytes
    byte[] wrong = new byte[15];
    assertThrows(
        IllegalArgumentException.class, () -> KeyGenUtils.getSecretKey(KeyType.AES_128, wrong));
  }

  @Test
  void getSecretKey_whenHmacWrongLength_expectAccepted() {
    // HMAC accepts arbitrary key length
    byte[] arbitrary = new byte[7];
    SecretKey key = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA256, arbitrary);
    assertArrayEquals(arbitrary, key.getEncoded());
  }

  @Test
  void getSecretKey_whenNonHmacByteBufferValid_expectEqualEncoding() {
    // Arrange
    ByteBuffer buf = ByteBuffer.wrap(trueLengthSecretKeys[3]);

    // Act
    SecretKey aesFromBuffer = KeyGenUtils.getSecretKey(KeyType.AES_256, buf);

    // Assert
    assertArrayEquals(trueLengthSecretKeys[3], aesFromBuffer.getEncoded());
  }

  @Test
  void getSecretKey_whenHmacByteBufferArbitraryLength_expectEqualEncoding() {
    // Arrange
    byte[] arbitrary = new byte[9];

    // Act
    SecretKey hmacFromBuffer =
        KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, ByteBuffer.wrap(arbitrary));

    // Assert
    assertArrayEquals(arbitrary, hmacFromBuffer.getEncoded());
  }

  @Test
  void genNonce_whenLengthProvided_expectCapacityEqualsLength() {
    // Arrange
    int len = TRUE_LENGTH;

    // Act
    ByteBuffer nonce = KeyGenUtils.genNonce(len);

    // Assert
    assertEquals(len, nonce.capacity());
  }

  @Test
  void genNonce_whenNegativeLength_expectNegativeArraySizeException() {
    // Arrange

    // Act + Assert
    assertThrows(NegativeArraySizeException.class, () -> KeyGenUtils.genNonce(FALSE_LENGTH));
  }

  @Test
  void genIV_whenLengthProvided_expectLengthEqualsInput() {
    // Arrange
    int len = TRUE_LENGTH;

    // Act
    IvParameterSpec spec = KeyGenUtils.genIV(len);

    // Assert
    assertEquals(len, spec.getIV().length);
  }

  @Test
  void genIV_whenNegativeLength_expectNegativeArraySizeException() {
    // Arrange

    // Act + Assert
    assertThrows(NegativeArraySizeException.class, () -> KeyGenUtils.genIV(FALSE_LENGTH));
  }

  @Test
  void getIvParameterSpec_whenValidBytesAndOffset_expectLengthMatches() {
    // Arrange
    byte[] bytes = new byte[16];
    int offset = 0;
    int len = TRUE_LENGTH;

    // Act
    IvParameterSpec spec = KeyGenUtils.getIvParameterSpec(bytes, offset, len);

    // Assert
    assertEquals(len, spec.getIV().length);
  }

  @Test
  void getIvParameterSpec_whenNullBytes_expectIllegalArgumentException() {
    // Arrange
    int offset = 0;
    int len = trueIV.length;

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> KeyGenUtils.getIvParameterSpec(null, offset, len));
  }

  @Test
  void getIvParameterSpec_whenByteBufferValid_expectSameBytes() {
    // Arrange
    ByteBuffer buf = ByteBuffer.wrap(trueIV);

    // Act
    IvParameterSpec spec = KeyGenUtils.getIvParameterSpec(buf);

    // Assert
    assertArrayEquals(trueIV, spec.getIV());
  }

  @Test
  void getIvParameterSpec_whenByteBufferNull_expectNullPointerException() {
    // Arrange

    // Act + Assert
    assertThrows(NullPointerException.class, () -> KeyGenUtils.getIvParameterSpec(null));
  }

  @Test
  void getIvParameterSpec_whenNegativeOffset_expectArrayIndexOutOfBoundsException() {
    // Arrange
    int negativeOffset = -4;

    // Act + Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> KeyGenUtils.getIvParameterSpec(trueIV, negativeOffset, trueIV.length));
  }

  @Test
  void getIvParameterSpec_whenExcessLength_expectIllegalArgumentException() {
    // Arrange
    int tooLong = trueIV.length + 20;

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> KeyGenUtils.getIvParameterSpec(trueIV, 0, tooLong));
  }

  @Test
  void deriveSecretKey_whenSameInputs_expectDeterministicEqual() throws InvalidKeyException {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act
    SecretKey buf1 =
        KeyGenUtils.deriveSecretKey(kdfKey, KeyGenUtils.class, KDF_INPUT, KeyType.HMAC_SHA512);
    SecretKey buf2 =
        KeyGenUtils.deriveSecretKey(kdfKey, KeyGenUtils.class, KDF_INPUT, KeyType.HMAC_SHA512);

    // Assert
    assertNotNull(buf1);
    assertEquals(buf1, buf2);
  }

  @Test
  void deriveSecretKey_whenDifferentTypes_expectLengthMatchesType() throws InvalidKeyException {
    for (KeyType type : keyTypes) {
      // Arrange
      SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

      // Act
      SecretKey derived = KeyGenUtils.deriveSecretKey(kdfKey, KeyGenUtils.class, KDF_INPUT, type);

      // Assert
      assertEquals(derived.getEncoded().length, type.keySize >> 3);
    }
  }

  @Test
  void deriveSecretKey_whenKdfKeyNull_expectInvalidKeyException() {
    // Arrange

    // Act + Assert
    assertThrows(
        InvalidKeyException.class,
        () -> KeyGenUtils.deriveSecretKey(null, KeyGenUtils.class, KDF_INPUT, KeyType.CHACHA_128));
  }

  @Test
  void deriveSecretKey_whenContextNull_expectNullPointerException() {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.deriveSecretKey(kdfKey, null, KDF_INPUT, KeyType.CHACHA_128));
  }

  @Test
  void deriveSecretKey_whenInfoNull_expectNullPointerException() {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.deriveSecretKey(kdfKey, KeyGenUtils.class, null, KeyType.CHACHA_128));
  }

  @Test
  void deriveSecretKey_whenRequestedTypeNull_expectNullPointerException() {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.deriveSecretKey(kdfKey, KeyGenUtils.class, KDF_INPUT, null));
  }

  @Test
  void deriveIvParameterSpec_whenSameInputs_expectDeterministicEqual() throws InvalidKeyException {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act
    IvParameterSpec buf1 =
        KeyGenUtils.deriveIvParameterSpec(kdfKey, KeyGenUtils.class, KDF_INPUT, KeyType.CHACHA_128);
    IvParameterSpec buf2 =
        KeyGenUtils.deriveIvParameterSpec(kdfKey, KeyGenUtils.class, KDF_INPUT, KeyType.CHACHA_128);

    // Assert
    assertNotNull(buf1);
    assertArrayEquals(buf1.getIV(), buf2.getIV());
  }

  @Test
  void deriveIvParameterSpec_whenDifferentTypes_expectLengthMatchesType()
      throws InvalidKeyException {
    for (KeyType type : keyTypes) {
      // Arrange
      SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

      // Act
      IvParameterSpec buf1 =
          KeyGenUtils.deriveIvParameterSpec(kdfKey, KeyGenUtils.class, KDF_INPUT, type);

      // Assert
      assertEquals(buf1.getIV().length, type.ivSize >> 3);
    }
  }

  @Test
  void deriveIvParameterSpec_whenKdfKeyNull_expectInvalidKeyException() {
    // Arrange

    // Act + Assert
    assertThrows(
        InvalidKeyException.class,
        () ->
            KeyGenUtils.deriveIvParameterSpec(
                null, KeyGenUtils.class, KDF_INPUT, KeyType.CHACHA_128));
  }

  @Test
  void deriveIvParameterSpec_whenContextNull_expectNullPointerException() {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.deriveIvParameterSpec(kdfKey, null, KDF_INPUT, KeyType.CHACHA_128));
  }

  @Test
  void deriveIvParameterSpec_whenInfoNull_expectNullPointerException() {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () ->
            KeyGenUtils.deriveIvParameterSpec(kdfKey, KeyGenUtils.class, null, KeyType.CHACHA_128));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void deriveIvParameterSpec_whenRequestedTypeNull_expectNullPointerException() {
    // Arrange
    SecretKey kdfKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, trueLengthSecretKeys[6]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> KeyGenUtils.deriveIvParameterSpec(kdfKey, KeyGenUtils.class, KDF_INPUT, null));
  }

  @Test
  void getPublicKey_whenByteBufferValid_expectSameEncoding() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      ByteBuffer buf = ByteBuffer.wrap(truePublicKeys[i]);

      // Act
      PublicKey key = KeyGenUtils.getPublicKey(type, buf);

      // Assert
      assertArrayEquals(truePublicKeys[i], key.getEncoded());
    }
  }

  @Test
  void getPublicKey_whenInvalidBytes_expectIllegalArgumentException() {
    // Arrange
    byte[] bogus = new byte[] {1};
    for (KeyPairType type : trueKeyPairTypes) {
      // Act + Assert
      assertThrows(IllegalArgumentException.class, () -> KeyGenUtils.getPublicKey(type, bogus));
    }
  }

  @Test
  void getPublicKeyPair_whenByteBufferValid_expectPublicSetAndPrivateNull() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      ByteBuffer buf = ByteBuffer.wrap(truePublicKeys[i]);

      // Act
      KeyPair pair = KeyGenUtils.getPublicKeyPair(type, buf);

      // Assert
      assertArrayEquals(truePublicKeys[i], pair.getPublic().getEncoded());
      assertNull(pair.getPrivate());
    }
  }

  @Test
  void getPublicKeyPair_whenInvalidBytes_expectIllegalArgumentException() {
    // Arrange
    byte[] bogus = new byte[] {2, 3, 4};
    for (KeyPairType type : trueKeyPairTypes) {
      // Act + Assert
      assertThrows(IllegalArgumentException.class, () -> KeyGenUtils.getPublicKeyPair(type, bogus));
    }
  }

  @Test
  void getKeyPair_whenByteBuffersValid_expectSameEncodings() {
    for (int i = 0; i < trueKeyPairTypes.length; i++) {
      // Arrange
      KeyPairType type = trueKeyPairTypes[i];
      ByteBuffer pub = ByteBuffer.wrap(truePublicKeys[i]);
      ByteBuffer prv = ByteBuffer.wrap(truePrivateKeys[i]);

      // Act
      KeyPair pair = KeyGenUtils.getKeyPair(type, pub, prv);

      // Assert
      assertArrayEquals(truePublicKeys[i], pair.getPublic().getEncoded());
      assertArrayEquals(truePrivateKeys[i], pair.getPrivate().getEncoded());
    }
  }

  @Test
  void getKeyPair_whenInvalidPublicOrPrivate_expectIllegalArgumentException() {
    // Arrange
    byte[] invalidPub = new byte[] {8};
    byte[] invalidPrv = new byte[] {9};

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> KeyGenUtils.getKeyPair(KeyPairType.ECP256, invalidPub, truePrivateKeys[0]));

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> KeyGenUtils.getKeyPair(KeyPairType.ECP256, truePublicKeys[0], invalidPrv));
  }
}
