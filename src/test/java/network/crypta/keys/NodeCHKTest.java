package network.crypta.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.support.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100") // Test naming: method_whenCondition_expectOutcome
class NodeCHKTest {

  private static Stream<Byte> cryptoAlgos() {
    return Stream.of(Key.ALGO_AES_PCFB_256_SHA256, Key.ALGO_AES_CTR_256_SHA256);
  }

  private static byte[] routingKeyWithPattern(int seed) {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    for (int i = 0; i < rk.length; i++) rk[i] = (byte) (seed + i);
    return rk;
  }

  @ParameterizedTest
  @MethodSource("cryptoAlgos")
  void constructor_whenRoutingKeyWrongLength_throwsIAE(byte algo) {
    assertThrows(
        IllegalArgumentException.class, () -> new NodeCHK(new byte[NodeCHK.KEY_LENGTH - 1], algo));
    assertThrows(
        IllegalArgumentException.class, () -> new NodeCHK(new byte[NodeCHK.KEY_LENGTH + 1], algo));
  }

  @ParameterizedTest
  @MethodSource("cryptoAlgos")
  void getType_and_getFullKey_whenAlgoSet_areEncodedProperly(byte algo) {
    // Arrange
    byte[] rk = routingKeyWithPattern(0x10);
    NodeCHK key = new NodeCHK(rk, algo);

    // Act
    short type = key.getType();
    byte[] full = key.getFullKey();

    // Assert: high byte is BASE_TYPE, low byte is algo (unsigned)
    assertEquals(NodeCHK.BASE_TYPE, (byte) (type >> 8));
    assertEquals((short) (algo & 0xFF), (short) (type & 0xFF));
    assertEquals(NodeCHK.FULL_KEY_LENGTH, full.length);
    assertEquals(NodeCHK.BASE_TYPE, full[0]);
    assertEquals(algo, full[1]);
    assertArrayEquals(rk, Arrays.copyOfRange(full, 2, 2 + NodeCHK.KEY_LENGTH));
    assertEquals(algo, NodeCHK.cryptoAlgorithmFromFullKey(full));
    assertArrayEquals(rk, NodeCHK.routingKeyFromFullKey(full));
  }

  @ParameterizedTest
  @MethodSource("cryptoAlgos")
  void write_and_writeToDataOutputStream_matchGetFullKeyFormat(byte algo) throws IOException {
    // Arrange
    byte[] rk = routingKeyWithPattern(0x20);
    NodeCHK key = new NodeCHK(rk, algo);
    byte[] expected = key.getFullKey();

    // Act: write using DataOutputStream API
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      key.writeToDataOutputStream(dos);
    }
    byte[] written = baos.toByteArray();

    // Assert: write() uses the same binary format as getFullKey()
    assertArrayEquals(expected, written);
  }

  @ParameterizedTest
  @MethodSource("cryptoAlgos")
  void readCHK_whenExactKeyLength_readsAndConstructsKey(byte algo) throws IOException {
    // Arrange: stream with exactly 32 routing-key bytes
    byte[] rk = routingKeyWithPattern(0x01);
    ByteArrayInputStream bais = new ByteArrayInputStream(rk);
    DataInputStream dis = new DataInputStream(bais);

    // Act
    Key parsed = NodeCHK.readCHK(dis, algo);

    // Assert
    assertInstanceOf(NodeCHK.class, parsed);
    NodeCHK chk = (NodeCHK) parsed;
    assertEquals(algo, NodeCHK.cryptoAlgorithmFromFullKey(chk.getFullKey()));
    assertArrayEquals(rk, chk.getRoutingKey());
  }

  @Test
  void readCHK_whenTruncatedInput_throwsEOFException() {
    // Arrange: only 31 bytes available
    byte[] truncated = new byte[NodeCHK.KEY_LENGTH - 1];
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(truncated));

    // Act + Assert
    assertThrows(EOFException.class, () -> NodeCHK.readCHK(dis, Key.ALGO_AES_PCFB_256_SHA256));
  }

  @Test
  @DisplayName("routingKeyFromFullKey(length==KEY_LENGTH) returns same reference")
  void routingKeyFromFullKey_whenKeyLength_returnsSameReference() {
    byte[] rk = routingKeyWithPattern(0x7A);
    byte[] result = NodeCHK.routingKeyFromFullKey(rk);
    assertSame(rk, result);
  }

  @Test
  void routingKeyFromFullKey_whenInvalidLength_returnsNull() {
    assertNull(NodeCHK.routingKeyFromFullKey(new byte[0]));
    assertNull(NodeCHK.routingKeyFromFullKey(new byte[NodeCHK.FULL_KEY_LENGTH - 1]));
    assertNull(NodeCHK.routingKeyFromFullKey(new byte[NodeCHK.FULL_KEY_LENGTH + 1]));
  }

  @Test
  void routingKeyFromFullKey_whenUnknownHeader_returnsFirst32BytesCopy() {
    // Arrange a header that does not match the expected type or algorithm bytes.
    byte[] full = new byte[NodeCHK.FULL_KEY_LENGTH];
    // Header deliberately invalid: type=9, algo=77
    full[0] = 9;
    full[1] = 77;
    for (int i = 0; i < NodeCHK.KEY_LENGTH; i++) full[2 + i] = (byte) (i + 3);

    // Act
    byte[] rk = NodeCHK.routingKeyFromFullKey(full);

    // Assert: equals the first 32 bytes; different reference as input
    assertArrayEquals(Arrays.copyOf(full, NodeCHK.KEY_LENGTH), rk);
    assertNotSame(full, rk);
  }

  @Test
  void routingKeyFromFullKey_whenUnknownHeaderWithTrailingNulls_returnsFirst32BytesCopy() {
    // Arrange: invalid header, last two bytes zero (debug recovery path)
    byte[] full = new byte[NodeCHK.FULL_KEY_LENGTH];
    full[0] = 42; // wrong type
    full[1] = 99; // unknown algo
    for (int i = 0; i < NodeCHK.KEY_LENGTH; i++) full[i] = (byte) (0xA0 + i);
    full[NodeCHK.FULL_KEY_LENGTH - 1] = 0;
    full[NodeCHK.FULL_KEY_LENGTH - 2] = 0;

    // Act
    byte[] rk = NodeCHK.routingKeyFromFullKey(full);

    // Assert
    assertArrayEquals(Arrays.copyOf(full, NodeCHK.KEY_LENGTH), rk);
  }

  @Test
  void equals_and_hashCode_whenRoutingKeyAndAlgoMatch_areEqual() {
    // Arrange
    byte[] rk = routingKeyWithPattern(0x33);
    NodeCHK a = new NodeCHK(rk, Key.ALGO_AES_PCFB_256_SHA256);
    NodeCHK b = new NodeCHK(Arrays.copyOf(rk, rk.length), Key.ALGO_AES_PCFB_256_SHA256);

    // Act + Assert
    //noinspection EqualsWithItself
    assertEquals(a, a);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenDifferentAlgoOrRoutingKey_returnsFalse() {
    byte[] rk = routingKeyWithPattern(0x44);
    NodeCHK base = new NodeCHK(rk, Key.ALGO_AES_PCFB_256_SHA256);
    NodeCHK diffAlgo = new NodeCHK(Arrays.copyOf(rk, rk.length), Key.ALGO_AES_CTR_256_SHA256);
    byte[] rk2 = Arrays.copyOf(rk, rk.length);
    rk2[0] ^= 0x7F; // flip a byte to ensure difference
    NodeCHK diffKey = new NodeCHK(rk2, Key.ALGO_AES_PCFB_256_SHA256);

    assertNotEquals(base, diffAlgo);
    assertNotEquals(base, diffKey);
    // Verify 'equals' returns false for unrelated object types.
    assertNotEquals(new Object(), base);
    // Also verify equals(null) is false per the general contract.
    assertNotEquals(null, base);
  }

  @Test
  void equals_whenComparedToNodeSSK_returnsFalse() {
    // Arrange a CHK and an SSK (different key type)
    NodeCHK chk = new NodeCHK(routingKeyWithPattern(0x55), Key.ALGO_AES_CTR_256_SHA256);
    byte[] pkh = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] ehd = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    NodeSSK ssk = new NodeSSK(pkh, ehd, Key.ALGO_AES_PCFB_256_SHA256);

    // Act + Assert (avoid a.equals(b) on inconvertible types: use assertNotEquals)
    //noinspection AssertBetweenInconvertibleTypes
    assertNotEquals(chk, ssk);
  }

  @Test
  void compareTo_whenComparedWithNodeSSK_returnsPositiveOne() {
    NodeCHK chk = new NodeCHK(routingKeyWithPattern(0x66), Key.ALGO_AES_PCFB_256_SHA256);
    NodeSSK ssk =
        new NodeSSK(
            new byte[NodeSSK.PUBKEY_HASH_SIZE],
            new byte[NodeSSK.E_H_DOCNAME_SIZE],
            Key.ALGO_AES_CTR_256_SHA256);
    assertEquals(1, chk.compareTo(ssk));
  }

  @Test
  void compareTo_ordersByRoutingKeyBytes() {
    byte[] low = new byte[NodeCHK.KEY_LENGTH];
    byte[] high = new byte[NodeCHK.KEY_LENGTH];
    Arrays.fill(low, (byte) 0);
    Arrays.fill(high, (byte) 0);
    low[0] = 0x00;
    high[0] = 0x01; // lexicographically greater

    NodeCHK a = new NodeCHK(low, Key.ALGO_AES_PCFB_256_SHA256);
    NodeCHK b = new NodeCHK(high, Key.ALGO_AES_PCFB_256_SHA256);

    assertTrue(a.compareTo(b) < 0);
    assertTrue(b.compareTo(a) > 0);
  }

  @Test
  void cloneKey_and_archivalCopy_returnEqualIndependentInstances() {
    NodeCHK original = new NodeCHK(routingKeyWithPattern(0x77), Key.ALGO_AES_CTR_256_SHA256);
    Key cloned = original.cloneKey();
    Key archived = original.archivalCopy();

    assertEquals(original, cloned);
    assertEquals(original, archived);
    assertNotSame(original, cloned);
    assertNotSame(original, archived);
  }

  @Test
  void toString_containsBase64RoutingKeyAndHashHex() {
    byte[] rk = routingKeyWithPattern(0x05);
    NodeCHK key = new NodeCHK(rk, Key.ALGO_AES_PCFB_256_SHA256);
    String s = key.toString();

    String b64 = Base64.encode(rk);
    String hex = Integer.toHexString(key.hashCode());

    // Should include "@<b64>:<hex>" after the Object.toString() prefix
    String marker = "@" + b64 + ":" + hex;
    assertTrue(
        s.contains(marker),
        () -> "toString() must include marker '" + marker + "' but was '" + s + "'");
  }
}
