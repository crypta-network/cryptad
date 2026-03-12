package network.crypta.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test case for {@link HexUtil} class.
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
@SuppressWarnings("java:S100")
class HexUtilTest {

  @Test
  void bytesToHex_whenSingleByteValues_expectTwoDigitHex() {
    // Arrange
    byte[] methodByteArray = new byte[1];

    // Act + Assert
    for (int i = 255; i >= 0; i--) {
      methodByteArray[0] = (byte) i;
      String actual = HexUtil.bytesToHex(methodByteArray);
      String expected = twoDigitHex(i);
      assertEquals(expected, actual);
    }
  }

  @Test
  void hexToBytes_whenSingleByteHexStrings_expectMatchingByteArray() {
    // Arrange
    byte[] expectedByteArray = new byte[1];

    // Act + Assert
    for (int i = 255; i >= 0; i--) {
      expectedByteArray[0] = (byte) i;
      String methodHexString = twoDigitHex(i);
      assertArrayEquals(expectedByteArray, HexUtil.hexToBytes(methodHexString));
    }
  }

  @Test
  void hexToBytesWithOffset_whenOffsetIsZero_expectMatchingByteArray() {
    // Arrange
    byte[] expectedByteArray = new byte[1];

    // Act + Assert
    for (int i = 255; i >= 0; i--) {
      expectedByteArray[0] = (byte) i;
      String methodHexString = twoDigitHex(i);
      assertArrayEquals(expectedByteArray, HexUtil.hexToBytes(methodHexString, 0));
    }
  }

  @Test
  void hexToBytesIntoBuffer_whenSingleByteHexStrings_expectWrittenByte() {
    // Arrange
    byte[] expectedByteArray = new byte[1];
    byte[] outputArray = new byte[1];

    // Act + Assert
    for (int i = 255; i >= 0; i--) {
      expectedByteArray[0] = (byte) i;
      String methodHexString = twoDigitHex(i);
      HexUtil.hexToBytes(methodHexString, outputArray, 0);
      assertArrayEquals(expectedByteArray, outputArray);
    }
  }

  @Test
  void bitsToBytes_whenAllSingleByteBitPatterns_expectSequentialByteValues() {
    // Arrange
    byte[] expectedByteArray = new byte[1];
    BitSet methodBitSet = new BitSet(8);

    // Act + Assert
    for (int i = 0; i < 256; i++) {
      byte[] outputArray = HexUtil.bitsToBytes(methodBitSet, 8);
      expectedByteArray[0] = (byte) i;
      assertArrayEquals(expectedByteArray, outputArray);
      addOne(methodBitSet);
    }
  }

  @Test
  void countBytesForBits_whenValuesCrossByteBoundaries_expectExpectedCounts() {
    // Arrange + Act + Assert
    assertEquals(0, HexUtil.countBytesForBits(0));
    for (int expectedBytesCount = 1; expectedBytesCount < 256; expectedBytesCount++) {
      for (int bits = (expectedBytesCount - 1) * 8 + 1; bits <= expectedBytesCount * 8; bits++) {
        assertEquals(expectedBytesCount, HexUtil.countBytesForBits(bits));
      }
    }
  }

  @Test
  void bytesToBits_whenConvertingSingleByteValues_expectRoundTripViaBitsToBytes() {
    // Arrange
    byte[] methodByteArray = new byte[1];
    BitSet methodBitSet = new BitSet(8);

    // Act + Assert
    for (int i = 0; i < 255; i++) {
      methodByteArray[0] = (byte) i;
      HexUtil.bytesToBits(methodByteArray, methodBitSet, 7);
      assertArrayEquals(methodByteArray, HexUtil.bitsToBytes(methodBitSet, 8));
    }
  }

  @Test
  void biToHex_whenGivenKnownValues_expectExpectedHexStrings() {
    // Arrange + Act + Assert
    BigInteger methodBigInteger = new BigInteger("999999999999999");
    assertEquals("038d7ea4c67fff", HexUtil.biToHex(methodBigInteger));

    methodBigInteger = BigInteger.ZERO;
    assertEquals("00", HexUtil.biToHex(methodBigInteger));

    methodBigInteger = new BigInteger("72057594037927935");
    assertEquals("00ffffffffffffff", HexUtil.biToHex(methodBigInteger));
  }

  @Test
  void bitsToHexString_whenBitsSet_expectExpectedHexRepresentation() {
    // Arrange
    BitSet methodBitSet = new BitSet(8);

    // Act + Assert
    assertEquals("00", HexUtil.bitsToHexString(methodBitSet, 8));

    methodBitSet.set(0, 7, true);
    assertEquals("7f", HexUtil.bitsToHexString(methodBitSet, 8));

    methodBitSet.set(0, 9, true);
    assertEquals("ff", HexUtil.bitsToHexString(methodBitSet, 8));
  }

  @Test
  void hexToBits_whenKnownHexValues_expectBitSetIntersectsExpectedBits() {
    // Arrange
    BitSet expectedBitSet = new BitSet(8);

    // Act
    BitSet bitSetFromZero = new BitSet(8);
    HexUtil.hexToBits("00", bitSetFromZero, bitSetFromZero.size());

    expectedBitSet.set(0, 7, true);
    BitSet bitSetFrom7f = new BitSet(8);
    HexUtil.hexToBits("7f", bitSetFrom7f, bitSetFrom7f.size());

    expectedBitSet.set(0, 9, true);
    BitSet bitSetFromFf = new BitSet(8);
    HexUtil.hexToBits("ff", bitSetFromFf, bitSetFromFf.size());

    // Assert
    assertEquals(0, bitSetFromZero.cardinality());
    assertTrue(bitSetFrom7f.intersects(expectedBitSet));
    assertTrue(bitSetFromFf.intersects(expectedBitSet));
  }

  @Test
  void writeBigIntegerAndReadBigInteger_whenRoundTrippedThroughDataStreams_expectSameValue() {
    // Arrange
    BigInteger methodBigInteger = new BigInteger("999999999999999");
    ByteArrayOutputStream methodByteArrayOutStream = new ByteArrayOutputStream();
    DataOutputStream methodDataOutStream = new DataOutputStream(methodByteArrayOutStream);

    // Act
    BigInteger actual =
        assertDoesNotThrow(
            () -> {
              HexUtil.writeBigInteger(methodBigInteger, methodDataOutStream);
              ByteArrayInputStream methodByteArrayInStream =
                  new ByteArrayInputStream(methodByteArrayOutStream.toByteArray());
              DataInputStream methodDataInStream = new DataInputStream(methodByteArrayInStream);
              return HexUtil.readBigInteger(methodDataInStream);
            });

    // Assert
    assertEquals(0, methodBigInteger.compareTo(actual));
  }

  @Test
  void bytesToHexWithRange_whenOffsetIsTooLong_expectIllegalArgumentException() {
    // Arrange
    int arrayLength = 3;
    byte[] methodBytesArray = new byte[arrayLength];

    // Act
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> HexUtil.bytesToHex(methodBytesArray, arrayLength + 1, 1));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void bytesToHexWithRange_whenLengthIsTooLong_expectIllegalArgumentException() {
    // Arrange
    int arrayLength = 3;
    byte[] methodBytesArray = new byte[arrayLength];

    // Act
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> HexUtil.bytesToHex(methodBytesArray, 0, arrayLength + 1));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void bytesToHexWithRange_whenLengthIsZero_expectEmptyString() {
    // Arrange
    int length = 0;
    byte[] methodBytesArray = {1, 2, 3};

    // Act
    String actual = HexUtil.bytesToHex(methodBytesArray, 0, length);

    // Assert
    assertEquals("", actual);
  }

  @Test
  void hexToBytesIntoBuffer_whenOffsetIsTooLong_expectArrayIndexOutOfBoundsException() {
    // Arrange
    String methodString = "0";
    byte[] methodByteArray = new byte[1];

    // Act
    ArrayIndexOutOfBoundsException exception =
        assertThrows(
            ArrayIndexOutOfBoundsException.class,
            () -> HexUtil.hexToBytes(methodString, methodByteArray, methodByteArray.length));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void hexToBytesIntoBuffer_whenOutputBufferIsTooShort_expectIndexOutOfBoundsException() {
    // Arrange
    String methodString = "0000";
    byte[] methodByteArray = new byte[1];

    // Act
    IndexOutOfBoundsException exception =
        assertThrows(
            IndexOutOfBoundsException.class,
            () -> HexUtil.hexToBytes(methodString, methodByteArray, 0));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void hexToBytesIntoBuffer_whenInputContainsBadDigit_expectNumberFormatException() {
    // Arrange
    String methodString = "00%0";
    byte[] methodByteArray = new byte[methodString.length()];

    // Act
    NumberFormatException exception =
        assertThrows(
            NumberFormatException.class,
            () -> HexUtil.hexToBytes(methodString, methodByteArray, 0));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void hexToBytesWithOffset_whenInputContainsBadDigit_expectNumberFormatException() {
    // Arrange
    String methodString = "00%0";

    // Act
    NumberFormatException exception =
        assertThrows(NumberFormatException.class, () -> HexUtil.hexToBytes(methodString, 0));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void hexToBytes_whenInputContainsBadDigit_expectNumberFormatException() {
    // Arrange
    String methodString = "00%0";

    // Act
    NumberFormatException exception =
        assertThrows(NumberFormatException.class, () -> HexUtil.hexToBytes(methodString));

    // Assert
    assertNotNull(exception);
  }

  @Test
  void bitsToBytes_whenSizeIsSmallerThanSetBits_expectTruncatedResult() {
    // Arrange
    byte[] expectedByteArray = new byte[1];
    BitSet methodBitSet = new BitSet(8);
    methodBitSet.flip(0);
    expectedByteArray[0] = (byte) 1;

    // Act
    byte[] outputAtSizeZero = HexUtil.bitsToBytes(methodBitSet, 0);
    byte[] outputAtSizeOne = HexUtil.bitsToBytes(methodBitSet, 1);

    // Assert
    assertFalse(Arrays.equals(expectedByteArray, outputAtSizeZero));
    assertArrayEquals(expectedByteArray, outputAtSizeOne);

    // Arrange
    methodBitSet.flip(7);
    methodBitSet.flip(3);
    expectedByteArray[0] = (byte) (128 + 8 + 1);

    // Act
    byte[] outputAtSizeThree = HexUtil.bitsToBytes(methodBitSet, 3);
    byte[] outputAtSizeEight = HexUtil.bitsToBytes(methodBitSet, 8);

    // Assert
    assertFalse(Arrays.equals(expectedByteArray, outputAtSizeThree));
    assertArrayEquals(expectedByteArray, outputAtSizeEight);
  }

  @Test
  void bytesToHexWithRange_whenLengthZeroAndOffsetAtEnd_expectEmptyString() {
    // Arrange + Act + Assert
    assertEquals("", HexUtil.bytesToHex(new byte[0], 0, 0));
    assertEquals("", HexUtil.bytesToHex(new byte[2], 2, 0));
  }

  private static String twoDigitHex(int value) {
    return value <= 15 ? "0" + Integer.toHexString(value) : Integer.toHexString(value);
  }

  private static void addOne(BitSet aBitSet) {
    int bitSetIndex = 0;
    while (aBitSet.get(bitSetIndex)) {
      aBitSet.flip(bitSetIndex);
      bitSetIndex++;
    }
    aBitSet.flip(bitSetIndex);
  }
}
