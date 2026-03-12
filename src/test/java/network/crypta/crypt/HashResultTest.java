package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class HashResultTest {
  private static byte[] bytesFor(HashType type, int seed) {
    byte[] bytes = new byte[type.hashLength];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) (seed + i);
    }
    return bytes;
  }

  private static byte[] resultBytes(HashResult hashResult) {
    return HashResult.get(new HashResult[] {hashResult}, hashResult.type);
  }

  @Test
  void readHashes_whenBitmaskZero_expectEmptyArray() throws IOException {
    // Arrange
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    DataOutputStream dataOutputStream = new DataOutputStream(outputStream);

    // Act
    HashResult.write(null, dataOutputStream);
    DataInputStream dataInputStream =
        new DataInputStream(new ByteArrayInputStream(outputStream.toByteArray()));
    HashResult[] results = HashResult.readHashes(dataInputStream);

    // Assert
    assertArrayEquals(new HashResult[0], results);
  }

  @Test
  void writeAndRead_whenMultipleTypes_expectRoundTripInEnumOrder() throws IOException {
    // Arrange
    byte[] sha512Bytes = bytesFor(HashType.SHA512, 10);
    byte[] sha1Bytes = bytesFor(HashType.SHA1, 20);
    byte[] md5Bytes = bytesFor(HashType.MD5, 30);
    HashResult[] input =
        new HashResult[] {
          new HashResult(HashType.SHA512, sha512Bytes),
          new HashResult(HashType.SHA1, sha1Bytes),
          new HashResult(HashType.MD5, md5Bytes)
        };
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    DataOutputStream dataOutputStream = new DataOutputStream(outputStream);

    // Act
    HashResult.write(input, dataOutputStream);
    DataInputStream dataInputStream =
        new DataInputStream(new ByteArrayInputStream(outputStream.toByteArray()));
    HashResult[] results = HashResult.readHashes(dataInputStream);

    // Assert
    assertNotNull(results);
    assertEquals(3, results.length);
    assertEquals(HashType.SHA1, results[0].type);
    assertEquals(HashType.MD5, results[1].type);
    assertEquals(HashType.SHA512, results[2].type);
    assertArrayEquals(sha1Bytes, HashResult.get(results, HashType.SHA1));
    assertArrayEquals(md5Bytes, HashResult.get(results, HashType.MD5));
    assertArrayEquals(sha512Bytes, HashResult.get(results, HashType.SHA512));
  }

  @Test
  void write_whenDuplicateTypes_expectIllegalArgumentException() {
    // Arrange
    HashResult first = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1));
    HashResult second = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 2));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    DataOutputStream dataOutputStream = new DataOutputStream(outputStream);

    // Act
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> HashResult.write(new HashResult[] {first, second}, dataOutputStream));

    // Assert
    assertEquals("Multiple hashes of the same type!", ex.getMessage());
  }

  @Test
  void makeBitmask_whenMultipleHashes_expectCombinedBitmask() {
    // Arrange
    HashResult sha1 = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1));
    HashResult md5 = new HashResult(HashType.MD5, bytesFor(HashType.MD5, 2));

    // Act
    long bitmask = HashResult.makeBitmask(new HashResult[] {sha1, md5});

    // Assert
    assertEquals(HashType.SHA1.bitmask | HashType.MD5.bitmask, bitmask);
  }

  @Test
  void strictEquals_whenLengthsDiffer_expectFalse() {
    // Arrange
    HashResult[] results =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1))};
    HashResult[] hashes =
        new HashResult[] {
          new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1)),
          new HashResult(HashType.MD5, bytesFor(HashType.MD5, 2))
        };

    // Act
    boolean equal = HashResult.strictEquals(results, hashes);

    // Assert
    assertFalse(equal);
  }

  @Test
  void strictEquals_whenTypeMismatch_expectFalse() {
    // Arrange
    HashResult[] results =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1))};
    HashResult[] hashes =
        new HashResult[] {new HashResult(HashType.MD5, bytesFor(HashType.MD5, 1))};

    // Act
    boolean equal = HashResult.strictEquals(results, hashes);

    // Assert
    assertFalse(equal);
  }

  @Test
  void strictEquals_whenByteMismatch_expectFalse() {
    // Arrange
    HashResult[] results =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1))};
    HashResult[] hashes =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 2))};

    // Act
    boolean equal = HashResult.strictEquals(results, hashes);

    // Assert
    assertFalse(equal);
  }

  @Test
  void strictEquals_whenSameTypeAndBytes_expectTrue() {
    // Arrange
    byte[] bytes = bytesFor(HashType.SHA1, 1);
    HashResult[] results = new HashResult[] {new HashResult(HashType.SHA1, bytes)};
    HashResult[] hashes =
        new HashResult[] {new HashResult(HashType.SHA1, Arrays.copyOf(bytes, bytes.length))};

    // Act
    boolean equal = HashResult.strictEquals(results, hashes);

    // Assert
    assertTrue(equal);
  }

  @Test
  void contains_whenTypePresent_expectTrue() {
    // Arrange
    HashResult[] hashes =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1))};

    // Act
    boolean contains = HashResult.contains(hashes, HashType.SHA1);

    // Assert
    assertTrue(contains);
  }

  @Test
  void contains_whenTypeAbsent_expectFalse() {
    // Arrange
    HashResult[] hashes =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1))};

    // Act
    boolean contains = HashResult.contains(hashes, HashType.MD5);

    // Assert
    assertFalse(contains);
  }

  @Test
  void get_whenTypePresent_expectByteArray() {
    // Arrange
    byte[] bytes = bytesFor(HashType.SHA1, 1);
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA1, bytes)};

    // Act
    byte[] found = HashResult.get(hashes, HashType.SHA1);

    // Assert
    assertArrayEquals(bytes, found);
  }

  @Test
  void get_whenReturnedArrayMutated_expectInternalStateUnchanged() {
    // Arrange
    byte[] bytes = bytesFor(HashType.SHA1, 1);
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA1, bytes)};

    // Act
    byte[] first = HashResult.get(hashes, HashType.SHA1);
    first[0] = (byte) (first[0] + 1);
    byte[] second = HashResult.get(hashes, HashType.SHA1);

    // Assert
    assertArrayEquals(bytes, second);
  }

  @Test
  void get_whenTypeAbsent_expectEmptyArray() {
    // Arrange
    HashResult[] hashes =
        new HashResult[] {new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1))};

    // Act
    byte[] found = HashResult.get(hashes, HashType.MD5);

    // Assert
    assertArrayEquals(new byte[0], found);
  }

  @Test
  void copy_whenNull_expectEmptyArray() {
    // Arrange
    HashResult[] hashes = null;

    // Act
    //noinspection ConstantValue
    HashResult[] copy = HashResult.copy(hashes);

    // Assert
    assertArrayEquals(new HashResult[0], copy);
  }

  @Test
  void copy_whenArrayProvided_expectClonedElements() {
    // Arrange
    HashResult original = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1));
    HashResult[] hashes = new HashResult[] {original};

    // Act
    HashResult[] copy = HashResult.copy(hashes);

    // Assert
    assertNotNull(copy);
    assertNotSame(hashes, copy);
    assertEquals(1, copy.length);
    assertNotSame(original, copy[0]);
    assertEquals(original.type, copy[0].type);
    assertArrayEquals(resultBytes(original), resultBytes(copy[0]));
  }

  @Test
  void copyConstructor_whenInvoked_expectDistinctInstanceAndSharedResultArray() {
    // Arrange
    HashResult original = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1));

    // Act
    HashResult cloned = new HashResult(original);

    // Assert
    assertNotSame(original, cloned);
    assertEquals(original.type, cloned.type);
    assertArrayEquals(resultBytes(original), resultBytes(cloned));
  }

  @Test
  void hashAsHex_whenBytesProvided_expectLowercaseHex() {
    // Arrange
    byte[] bytes = new byte[HashType.MD5.hashLength];
    bytes[0] = 0x00;
    bytes[1] = 0x0f;
    bytes[2] = (byte) 0xa5;
    HashResult hashResult = new HashResult(HashType.MD5, bytes);

    // Act
    String hex = hashResult.hashAsHex();

    // Assert
    assertEquals("000fa5" + "00".repeat(HashType.MD5.hashLength - 3), hex);
  }

  @Test
  void equals_whenSameTypeAndBytes_expectTrue() {
    // Arrange
    byte[] bytes = bytesFor(HashType.SHA1, 1);
    HashResult first = new HashResult(HashType.SHA1, bytes);
    HashResult second = new HashResult(HashType.SHA1, Arrays.copyOf(bytes, bytes.length));

    // Act
    boolean equal = first.equals(second);

    // Assert
    assertTrue(equal);
  }

  @Test
  void equals_whenDifferentType_expectFalse() {
    // Arrange
    HashResult first = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1));
    HashResult second = new HashResult(HashType.MD5, bytesFor(HashType.MD5, 1));

    // Act
    boolean equal = first.equals(second);

    // Assert
    assertFalse(equal);
  }

  @Test
  void equals_whenDifferentBytes_expectFalse() {
    // Arrange
    HashResult first = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 1));
    HashResult second = new HashResult(HashType.SHA1, bytesFor(HashType.SHA1, 2));

    // Act
    boolean equal = first.equals(second);

    // Assert
    assertFalse(equal);
  }

  @Test
  void hashCode_whenCalledMultipleTimes_expectStableValue() {
    // Arrange
    byte[] bytes = bytesFor(HashType.SHA1, 1);
    HashResult hashResult = new HashResult(HashType.SHA1, bytes);
    HashResult cloned = new HashResult(hashResult);

    // Act
    int first = hashResult.hashCode();
    int second = hashResult.hashCode();

    // Assert
    assertEquals(first, second);
    assertEquals(first, cloned.hashCode());
  }

  @ParameterizedTest(name = "compareTo {0} vs {1} -> {2}")
  @MethodSource("compareToCases")
  void compareTo_whenBitmaskOrder_expectSignedComparison(
      HashType leftType, HashType rightType, int expectedSign) {
    // Arrange
    HashResult left = new HashResult(leftType, bytesFor(leftType, 1));
    HashResult right = new HashResult(rightType, bytesFor(rightType, 2));

    // Act
    int comparison = Integer.signum(left.compareTo(right));

    // Assert
    assertEquals(expectedSign, comparison);
  }

  private static Stream<Arguments> compareToCases() {
    return Stream.of(
        Arguments.of(HashType.SHA1, HashType.SHA1, 0),
        Arguments.of(HashType.SHA1, HashType.MD5, -1),
        Arguments.of(HashType.SHA512, HashType.SHA1, 1));
  }
}
