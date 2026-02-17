package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // test method naming uses when/expect style
@ExtendWith(MockitoExtension.class)
class HashTest {
  private static final byte[] HELLO_WORLD = "hello world".getBytes(StandardCharsets.UTF_8);

  private static void ignoreBoolean(boolean ignored) {}

  private static Stream<Arguments> hashVectors() {
    return Stream.of(
        // type, correct hex for "hello world", incorrect hex (same length)
        Arguments.of(
            HashType.MD5, "5eb63bbbe01eeed093cb22bb8f5acdc3", "aa010fbc1d14c795d86ef98c95479d17"),
        Arguments.of(
            HashType.ED2K, "aa010fbc1d14c795d86ef98c95479d17", "5eb63bbbe01eeed093cb22bb8f5acdc3"),
        Arguments.of(
            HashType.SHA1,
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee"),
        Arguments.of(
            HashType.TTH,
            "ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d",
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846edb63dc11d"),
        Arguments.of(
            HashType.SHA256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d9088f7ace2efcde9"),
        Arguments.of(
            HashType.SHA384,
            "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3"
                + "e417cb71ce646efd0819dd8c088de1bd",
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9e417cb71ce646efd0819dd8c08"
                + "8de1bd"),
        Arguments.of(
            HashType.SHA512,
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
                + "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
            "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c08"
                + "8de1bdd830e81f605dcf7dc5542e93ae9cd76f"));
  }

  @ParameterizedTest(name = "{0}: genHash matches known vector")
  @MethodSource("hashVectors")
  void genHash_whenInputProvided_expectExpectedDigest(HashType type, String okHex, String ignored) {
    // Arrange
    Hash hash = new Hash(type);
    byte[] expected = Hex.decode(okHex);
    // Act
    byte[] actual = hash.genHash(HELLO_WORLD);
    // Assert
    assertArrayEquals(expected, actual);
  }

  @ParameterizedTest(name = "{0}: genHash resets digest between calls")
  @MethodSource("hashVectors")
  void genHash_whenCalledTwice_expectReset(HashType type, String okHex, String ignored) {
    Hash hash = new Hash(type);
    byte[] first = hash.genHash(HELLO_WORLD);
    byte[] second = hash.genHash(HELLO_WORLD);
    assertArrayEquals(first, second);
    // Also ensure both equal the expected vector, using okHex so parameters are meaningful
    assertArrayEquals(Hex.decode(okHex), first);
  }

  @ParameterizedTest(name = "{0}: equals provider MessageDigest")
  @MethodSource("hashVectors")
  void genHash_whenComparedToProvider_expectSame(HashType type, String okHex, String ignored) {
    MessageDigest md = type.get();
    byte[] provider = md.digest(HELLO_WORLD);
    byte[] viaHash = new Hash(type).genHash(HELLO_WORLD);
    assertArrayEquals(provider, viaHash);
    // Provider result should match our known vector for the input
    assertArrayEquals(Hex.decode(okHex), provider);
  }

  @ParameterizedTest(name = "{0}: genHash throws on null varargs")
  @EnumSource(HashType.class)
  void genHash_whenNullArray_expectNpe(HashType type) {
    Hash hash = new Hash(type);
    assertThrows(NullPointerException.class, () -> hash.genHash((byte[][]) null));
  }

  @ParameterizedTest(name = "{0}: genHash throws on null element")
  @EnumSource(HashType.class)
  void genHash_whenNullElement_expectNpe(HashType type) {
    Hash hash = new Hash(type);
    assertThrows(NullPointerException.class, () -> hash.genHash(HELLO_WORLD, null));
  }

  @ParameterizedTest(name = "{0}: genHashResult equals expected result")
  @MethodSource("hashVectors")
  void genHashResult_whenInputProvided_expectHashResult(
      HashType type, String okHex, String ignored) {
    HashResult expected = new HashResult(type, Hex.decode(okHex));
    HashResult actual = new Hash(type).genHashResult(HELLO_WORLD);
    assertTrue(Hash.verify(actual, expected));
  }

  @ParameterizedTest(name = "{0}: genHexHash returns lowercase hex")
  @MethodSource("hashVectors")
  void genHexHash_whenBytesAdded_expectHex(HashType type, String okHex, String ignored) {
    Hash h = new Hash(type);
    h.addBytes(HELLO_WORLD);
    assertEquals(okHex, h.genHexHash());
  }

  @ParameterizedTest(name = "{0}: addByte equals array update")
  @MethodSource("hashVectors")
  void addByte_whenAddingSequentially_expectSameDigest(
      HashType type, String okHex, String ignored) {
    Hash h = new Hash(type);
    for (byte b : HELLO_WORLD) h.addByte(b);
    assertArrayEquals(Hex.decode(okHex), h.genHash());
  }

  @ParameterizedTest(name = "{0}: addBytes(ByteBuffer) consumes remaining and matches")
  @MethodSource("hashVectors")
  void addBytes_whenByteBuffer_expectPositionAtLimitAndDigest(
      HashType type, String okHex, String ignored) {
    ByteBuffer buf = ByteBuffer.wrap(HELLO_WORLD).slice();
    Hash h = new Hash(type);
    h.addBytes(buf);
    assertArrayEquals(Hex.decode(okHex), h.genHash());
    assertEquals(buf.limit(), buf.position());
    assertEquals(0, buf.remaining());
  }

  @ParameterizedTest(name = "{0}: addBytes(ByteBuffer) null -> NPE")
  @EnumSource(HashType.class)
  void addBytes_whenByteBufferNull_expectNpe(HashType type) {
    Hash h = new Hash(type);
    assertThrows(NullPointerException.class, () -> h.addBytes((ByteBuffer) null));
  }

  @ParameterizedTest(name = "{0}: addBytes(offset,len) with split halves")
  @MethodSource("hashVectors")
  void addBytes_withOffsetAndLength_expectSameDigest(HashType type, String okHex, String ignored) {
    Hash h = new Hash(type);
    int half = HELLO_WORLD.length / 2;
    h.addBytes(HELLO_WORLD, 0, half);
    h.addBytes(HELLO_WORLD, half, HELLO_WORLD.length - half);
    assertArrayEquals(Hex.decode(okHex), h.genHash());
  }

  @ParameterizedTest(name = "{0}: addBytes(null,off,len) -> IAE")
  @EnumSource(HashType.class)
  void addBytes_whenArrayNull_expectIllegalArgument(HashType type) {
    Hash h = new Hash(type);
    assertThrows(IllegalArgumentException.class, () -> h.addBytes(null, 0, HELLO_WORLD.length));
  }

  @ParameterizedTest(name = "{0}: addBytes negative offset -> AIOOBE")
  @EnumSource(HashType.class)
  void addBytes_whenNegativeOffset_expectArrayIndexOoB(HashType type) {
    Hash h = new Hash(type);
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> h.addBytes(HELLO_WORLD, -3, HELLO_WORLD.length - 3));
  }

  @ParameterizedTest(name = "{0}: addBytes length too long -> IAE")
  @EnumSource(HashType.class)
  void addBytes_whenLengthTooLong_expectIllegalArgument(HashType type) {
    Hash h = new Hash(type);
    assertThrows(
        IllegalArgumentException.class, () -> h.addBytes(HELLO_WORLD, 0, HELLO_WORLD.length + 3));
  }

  @ParameterizedTest(name = "{0}: verify(byte[]) true/false and wrong size")
  @MethodSource("hashVectors")
  void verify_whenByteArrayInputs_expectResults(HashType type, String okHex, String badHex) {
    Hash h = new Hash(type);
    assertTrue(h.verify(Hex.decode(okHex), HELLO_WORLD));
    assertFalse(h.verify(Hex.decode(badHex), HELLO_WORLD));
    assertFalse(h.verify(HELLO_WORLD, HELLO_WORLD)); // wrong-sized "hash"
  }

  @ParameterizedTest(name = "{0}: verify(null, data) returns false")
  @EnumSource(HashType.class)
  void verify_whenNullHash_expectFalse(HashType type) {
    Hash h = new Hash(type);
    assertFalse(h.verify((byte[]) null, HELLO_WORLD));
  }

  @ParameterizedTest(name = "{0}: verify(hash, null) -> NPE")
  @MethodSource("hashVectors")
  void verify_whenNullData_expectNpe(HashType type, String okHex, String ignored) {
    Hash h = new Hash(type);
    byte[] bytes = Hex.decode(okHex);
    assertThrows(NullPointerException.class, () -> h.verify(bytes, (byte[][]) null));
  }

  @ParameterizedTest(name = "{0}: static verify(HashResult, data)")
  @MethodSource("hashVectors")
  void verify_whenHashResultAndData_expectResults(HashType type, String okHex, String badHex) {
    HashResult good = new HashResult(type, Hex.decode(okHex));
    HashResult bad = new HashResult(type, Hex.decode(badHex));
    assertTrue(Hash.verify(good, HELLO_WORLD));
    assertFalse(Hash.verify(bad, HELLO_WORLD));
  }

  @ParameterizedTest(name = "{0}: static verify(HashResult, data) wrong-sized result -> false")
  @EnumSource(HashType.class)
  void verify_whenWrongSizedHashResult_expectFalse(HashType type) {
    HashResult wrongSized = new HashResult(type, HELLO_WORLD, true);
    assertFalse(Hash.verify(wrongSized, HELLO_WORLD));
  }

  @SuppressWarnings("DataFlowIssue")
  @ParameterizedTest(name = "{0}: static verify(null, data) -> NPE")
  @EnumSource(HashType.class)
  void verify_whenNullHashResult_expectNpe(HashType type) {
    byte[] bytes = new Hash(type).genHash(HELLO_WORLD);
    assertThrows(
        NullPointerException.class, () -> ignoreBoolean(Hash.verify((HashResult) null, bytes)));
  }

  @ParameterizedTest(name = "{0}: static verify(hash, null) -> NPE")
  @MethodSource("hashVectors")
  void verify_whenNullDataForStatic_expectNpe(HashType type, String okHex, String ignored) {
    HashResult h = new HashResult(type, Hex.decode(okHex));
    assertThrows(NullPointerException.class, () -> ignoreBoolean(Hash.verify(h, (byte[][]) null)));
  }

  @ParameterizedTest(name = "{0}: static verify(HashResult, HashResult)")
  @MethodSource("hashVectors")
  void verify_whenComparingHashResults_expectTrueFalse(HashType type, String okHex, String badHex) {
    HashResult hr1 = new HashResult(type, Hex.decode(okHex));
    HashResult hr2 = new HashResult(type, Hex.decode(okHex));
    HashResult hr3 = new HashResult(type, Hex.decode(badHex));
    assertTrue(Hash.verify(hr1, hr2));
    assertFalse(Hash.verify(hr1, hr3));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  @DisplayName("verify(hash1=null, hash2) throws NPE; verify(hash1, null) returns false")
  void verify_whenFirstNull_expectNpe_andSecondNull_expectFalse() {
    HashResult some =
        new HashResult(HashType.SHA256, new Hash(HashType.SHA256).genHash(HELLO_WORLD));
    assertThrows(NullPointerException.class, () -> ignoreBoolean(Hash.verify(null, some)));
    // Use an environment-dependent path so static analysis does not flag a constant null,
    // while keeping the outcome deterministically false in both branches.
    HashResult other =
        System.getenv("CRYPTO_HASH_TEST_UNSET") == null
            ? null
            : new HashResult(HashType.SHA256, HELLO_WORLD, true);
    assertFalse(Hash.verify(some, other));
  }

  @ParameterizedTest(name = "{0}: after genHash(), new bytes are hashed in isolation")
  @EnumSource(
      value = HashType.class,
      names = {"ED2K", "TTH"})
  void genHash_afterFlush_expectStateClearedForSpecialDigests(HashType type) {
    Hash h = new Hash(type);
    byte[] hello = "hello".getBytes(StandardCharsets.UTF_8);
    byte[] world = " world".getBytes(StandardCharsets.UTF_8);
    // First compute hash of "hello"
    byte[] first = h.genHash(hello);
    // Now ensure second hash includes only new input, not a carry-over
    byte[] second = h.genHash(world);
    byte[] expectedSecond = type.get().digest(world);
    assertArrayEquals(expectedSecond, second);
    // And the first one matched provider as well
    assertArrayEquals(type.get().digest(hello), first);
  }
}
