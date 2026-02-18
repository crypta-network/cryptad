package network.crypta.node;

import java.nio.charset.StandardCharsets;
import java.util.stream.IntStream;
import network.crypta.crypt.HMAC;
import network.crypta.crypt.RandomSource;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DatabaseKeyTest {

  private static byte[] fixedKey32() {
    byte[] key = new byte[32];
    // 0,1,2,...,31
    for (int i = 0; i < key.length; i++) key[i] = (byte) i;
    return key;
  }

  private static byte[] derivePluginExpected(byte[] dbKey, String storeId) {
    byte[] id = storeId.getBytes(StandardCharsets.UTF_8);
    byte[] plugin = "PLUGIN".getBytes(StandardCharsets.UTF_8);
    byte[] full = new byte[dbKey.length + plugin.length + id.length];
    int x = 0;
    System.arraycopy(dbKey, 0, full, 0, dbKey.length);
    x += dbKey.length;
    System.arraycopy(plugin, 0, full, x, plugin.length);
    x += plugin.length;
    System.arraycopy(id, 0, full, x, id.length);
    return HMAC.macWithSHA256(dbKey, full);
  }

  private static byte[] deriveClientExpected(byte[] dbKey) {
    byte[] client = "CLIENT".getBytes(StandardCharsets.UTF_8);
    byte[] full = new byte[dbKey.length + client.length];
    int x = 0;
    System.arraycopy(dbKey, 0, full, 0, dbKey.length);
    x += dbKey.length;
    System.arraycopy(client, 0, full, x, client.length);
    return HMAC.macWithSHA256(dbKey, full);
  }

  static String[] storeIds() {
    return new String[] {"", "MyPlugin", "πlugïn-数据"};
  }

  @ParameterizedTest
  @MethodSource("storeIds")
  @DisplayName("getPluginStoreKey derives expected 32-byte key for various identifiers")
  void getPluginStoreKey_variousInputs_returnsExpectedKey(String storeId) {
    // Arrange
    byte[] key = fixedKey32();
    DatabaseKey dbKey = new DatabaseKey(key);
    byte[] expected = derivePluginExpected(key, storeId);

    // Act
    byte[] actual = dbKey.getPluginStoreKey(storeId);

    // Assert
    assertEquals(32, actual.length, "HMAC-SHA-256 output length");
    assertArrayEquals(expected, actual);
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void getPluginStoreKey_whenStoreIdNull_throwsNPE() {
    DatabaseKey dbKey = new DatabaseKey(fixedKey32());
    assertThrows(NullPointerException.class, () -> dbKey.getPluginStoreKey(null));
  }

  @Test
  void getPluginStoreKey_whenKeyNot32_throwsIAE() {
    // Arrange: 16-byte key triggers HMAC key-length guard
    byte[] bad = new byte[16];
    DatabaseKey dbKey = new DatabaseKey(bad);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> dbKey.getPluginStoreKey("x"));
  }

  @Test
  void getKeyForClientLayer_withValidKey_returnsExpected() {
    // Arrange
    byte[] key = fixedKey32();
    DatabaseKey dbKey = new DatabaseKey(key);
    byte[] expected = deriveClientExpected(key);

    // Act
    byte[] actual = dbKey.getKeyForClientLayer();

    // Assert
    assertEquals(32, actual.length);
    assertArrayEquals(expected, actual);
  }

  @Test
  void getKeyForClientLayer_whenKeyNot32_throwsIAE() {
    DatabaseKey dbKey = new DatabaseKey(new byte[8]);
    assertThrows(IllegalArgumentException.class, dbKey::getKeyForClientLayer);
  }

  @Test
  void createEncryptedBucketForClientLayer_wrapsUnderlyingInAEADBucket() {
    // Arrange
    DatabaseKey dbKey = new DatabaseKey(fixedKey32());
    Bucket underlying = new ArrayBucket("underlyingBucket");

    // Act
    Bucket wrapped = dbKey.createEncryptedBucketForClientLayer(underlying);

    // Assert
    assertNotNull(wrapped);
    assertTrue(
        wrapped.getClass().getName().endsWith("AEADCryptBucket"), "Should return AEADCryptBucket");
    // AEADCryptBucket#getName prefixes with "AEADEncrypted:" and appends underlying name
    assertTrue(wrapped.getName().contains("underlyingBucket"));
  }

  @Test
  void equals_and_hashCode_obeyValueSemantics() {
    // Arrange
    byte[] k1 = fixedKey32();
    byte[] k2 = fixedKey32(); // distinct array instance with same contents
    DatabaseKey a = new DatabaseKey(k1);
    DatabaseKey b = new DatabaseKey(k2);
    byte[] k3 = fixedKey32();
    k3[0] ^= 0x7F; // different content
    DatabaseKey c = new DatabaseKey(k3);

    // Act + Assert
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    //noinspection EqualsWithItself
    assertEquals(a, a); // reflexive
    // symmetry/transitivity covered by equals with b
    assertNotEquals(c, a);
    assertNotEquals(null, a);
    assertNotEquals(new Object(), a);
  }

  @Test
  void constructor_defensivelyCopiesInputArray() {
    // Arrange
    byte[] src = fixedKey32();
    byte[] original = src.clone();
    DatabaseKey dbKey = new DatabaseKey(src);
    // Mutate the original array after construction
    for (int i = 0; i < src.length; i++) src[i] ^= (byte) 0xFF;

    // Act: derive using the instance – should use the original, not the mutated src
    byte[] derived = dbKey.getKeyForClientLayer();
    byte[] expected = deriveClientExpected(original);

    // Assert
    assertArrayEquals(expected, derived);
  }

  // Deprecated two-arg constructor removed; no longer tested.

  @Test
  void createRandom_usesProvidedRandomSourceBytes() {
    // Arrange: mock RandomSource to fill the buffer with a known pattern 0..31
    // Delegate to default for other methods
    RandomSource rs = mock(RandomSource.class, InvocationOnMock::callRealMethod);
    doAnswer(
            invocation -> {
              byte[] buf = invocation.getArgument(0, byte[].class);
              IntStream.range(0, buf.length).forEach(i -> buf[i] = (byte) i);
              return null;
            })
        .when(rs)
        .nextBytes(any(byte[].class));

    // Act
    DatabaseKey dbKey = DatabaseKey.createRandom(rs);

    // Assert: derived client key matches expectation from pattern 0..31
    byte[] expected = deriveClientExpected(fixedKey32());
    assertArrayEquals(expected, dbKey.getKeyForClientLayer());
  }
}
