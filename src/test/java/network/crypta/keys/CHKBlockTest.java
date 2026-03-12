package network.crypta.keys;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.crypt.SHA256;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // Test method-naming: method_whenCondition_expectOutcome
class CHKBlockTest {

  private static byte[] sha256(byte[] headers, byte[] data) {
    MessageDigest md = SHA256.getMessageDigest();
    md.update(headers);
    md.update(data);
    return md.digest();
  }

  private static byte[] makeHeaders(short hashIdentifier) {
    byte[] h = new byte[CHKBlock.TOTAL_HEADERS_LENGTH];
    // Big-endian short
    h[0] = (byte) ((hashIdentifier >> 8) & 0xFF);
    h[1] = (byte) (hashIdentifier & 0xFF);
    // The rest can be zero for these tests.
    return h;
  }

  private static Stream<Byte> cryptoAlgos() {
    return Stream.of(Key.ALGO_AES_PCFB_256_SHA256, Key.ALGO_AES_CTR_256_SHA256);
  }

  @ParameterizedTest
  @MethodSource("cryptoAlgos")
  @DisplayName("construct(null key) builds NodeCHK from SHA-256(headers||data)")
  void construct_whenKeyNull_buildsNodeCHKFromHash(byte cryptoAlgorithm) throws Exception {
    // Arrange
    byte[] data = new byte[] {1, 2, 3, 4, 5};
    byte[] headers = makeHeaders((short) KeyBlock.HASH_SHA256);
    byte[] expectedRoutingKey = sha256(headers, data);

    // Act
    CHKBlock block = CHKBlock.construct(data, headers, cryptoAlgorithm);

    // Assert
    assertArrayEquals(expectedRoutingKey, block.getRoutingKey(), "routingKey must match digest");
    assertEquals(cryptoAlgorithm, NodeCHK.cryptoAlgorithmFromFullKey(block.getFullKey()));
    assertArrayEquals(
        expectedRoutingKey,
        NodeCHK.routingKeyFromFullKey(block.getFullKey()),
        "fullKey must embed routingKey");
    assertSame(headers, block.getHeaders(), "headers must be exposed as the same array reference");
    assertSame(data, block.getData(), "data must be exposed as the same array reference");
    assertNull(block.getPubkeyBytes(), "CHK blocks do not carry pubkey bytes");
  }

  @Test
  void constructor_withExplicitKey_matchingHash_verifiesAndUsesProvidedKey() throws Exception {
    // Arrange
    byte[] data = new byte[] {10, 20, 30};
    byte[] headers = makeHeaders((short) KeyBlock.HASH_SHA256);
    byte[] digest = sha256(headers, data);
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    NodeCHK key = new NodeCHK(digest, algo);

    // Act
    CHKBlock block = new CHKBlock(data, headers, key);

    // Assert
    assertNotNull(block.getKey());
    assertEquals(key, block.getKey(), "Block must keep the provided NodeCHK");
    assertArrayEquals(digest, block.getRoutingKey());
    assertEquals(key.getType(), block.getKey().getType());
  }

  @Test
  void constructor_withExplicitKey_mismatchedHash_throwsCHKVerifyException() {
    // Arrange
    byte[] data = new byte[] {42};
    byte[] headers = makeHeaders((short) KeyBlock.HASH_SHA256);
    byte[] wrongDigest = new byte[NodeCHK.KEY_LENGTH]; // all zeros -> guaranteed mismatch
    NodeCHK wrongKey = new NodeCHK(wrongDigest, Key.ALGO_AES_CTR_256_SHA256);

    // Act + Assert
    assertThrows(CHKVerifyException.class, () -> new CHKBlock(data, headers, wrongKey));
  }

  @Test
  void constructor_withNonSHA256Header_throwsCHKVerifyException() {
    // Arrange
    byte[] data = new byte[] {1, 2};
    byte[] badHeaders = makeHeaders((short) 0x0002); // not HASH_SHA256

    // Act + Assert
    assertThrows(
        CHKVerifyException.class,
        () -> CHKBlock.construct(data, badHeaders, Key.ALGO_AES_CTR_256_SHA256));
  }

  @Test
  void constructor_withInvalidHeaderLength_throwsIllegalArgumentException() {
    // Arrange
    byte[] data = new byte[] {9, 9, 9};
    byte[] wrongLenHeaders = new byte[CHKBlock.TOTAL_HEADERS_LENGTH - 1];

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> CHKBlock.construct(data, wrongLenHeaders, Key.ALGO_AES_PCFB_256_SHA256));
  }

  @Test
  void constructor_verifyFalse_allowsNonSHA256HeaderAndSkipsHashCheck() throws Exception {
    // Arrange: invalid header ID but verify=false should bypass checks
    byte[] data = new byte[] {7, 7, 7};
    byte[] badHeaders = makeHeaders((short) 0x1234);
    byte[] arbitraryRoutingKey = new byte[NodeCHK.KEY_LENGTH];
    Arrays.fill(arbitraryRoutingKey, (byte) 0xA5);
    NodeCHK providedKey = new NodeCHK(arbitraryRoutingKey, Key.ALGO_AES_CTR_256_SHA256);

    // Act
    CHKBlock block =
        new CHKBlock(data, badHeaders, providedKey, false, providedKey.cryptoAlgorithm);

    // Assert: constructed and kept the provided key; no exceptions
    assertSame(providedKey, block.getKey(), "verify=false must accept the provided key verbatim");
    assertSame(badHeaders, block.getHeaders());
    assertSame(data, block.getData());
  }

  @Test
  void equals_and_hashCode_whenAllFieldsMatch_areEqual() throws Exception {
    // Arrange
    byte[] data1 = new byte[] {1, 3, 3, 7};
    byte[] headers1 = makeHeaders((short) KeyBlock.HASH_SHA256);
    byte[] data2 = Arrays.copyOf(data1, data1.length);
    byte[] headers2 = Arrays.copyOf(headers1, headers1.length);
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;

    CHKBlock a = CHKBlock.construct(data1, headers1, algo);
    CHKBlock b = CHKBlock.construct(data2, headers2, algo);

    // Act + Assert
    assertEquals(a, b, "Blocks with identical content must be equal");
    assertEquals(a.hashCode(), b.hashCode(), "Equal blocks must share hashCode");
  }

  @Test
  void equals_whenHeadersOrDataDiffer_notEqualEvenIfKeySameWithBypass() throws Exception {
    // Arrange: build a baseline block
    byte[] data = new byte[] {5, 6, 7};
    byte[] headers = makeHeaders((short) KeyBlock.HASH_SHA256);
    CHKBlock original = CHKBlock.construct(data, headers, Key.ALGO_AES_CTR_256_SHA256);

    // Now construct a block with the same key but a different header and data via verify=false
    byte[] differentHeaders = makeHeaders((short) KeyBlock.HASH_SHA256);
    differentHeaders[5] = 1; // mutate some header byte
    byte[] differentData = new byte[] {9, 9};
    CHKBlock different =
        new CHKBlock(
            differentData,
            differentHeaders,
            original.getKey(),
            false,
            NodeCHK.cryptoAlgorithmFromFullKey(original.getFullKey()));

    // Act + Assert
    assertNotEquals(original, different);
    assertNotEquals(
        original.hashCode(),
        different.hashCode(),
        "Likely different hashCodes when content differs (not strictly required)");
  }
}
