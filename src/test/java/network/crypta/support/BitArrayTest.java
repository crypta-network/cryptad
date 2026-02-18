package network.crypta.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Comprehensive unit tests for {@link BitArray}.
 *
 * <p>These tests cover construction, serialization/deserialization, boundary conditions, and the
 * search helpers.
 */
class BitArrayTest {

  private static final int SAMPLE_SIZE = 10;

  private static BitArray newFilled(int size, boolean value) {
    BitArray arr = new BitArray(size);
    for (int i = 0; i < arr.getSize(); i++) {
      arr.setBit(i, value);
    }
    return arr;
  }

  private static String repeat(int count, char c) {
    return String.valueOf(c).repeat(Math.max(0, count));
  }

  @Test
  @DisplayName("constructor_withSize_initializesAllFalseAndSizeCorrect")
  void constructorWithSizeInitializesAllFalseAndSizeCorrect() {
    // Arrange & Act
    BitArray arr = new BitArray(SAMPLE_SIZE);

    // Assert
    assertEquals(SAMPLE_SIZE, arr.getSize());
    for (int i = 0; i < SAMPLE_SIZE; i++) {
      assertFalse(arr.bitAt(i));
    }
  }

  @Test
  @DisplayName("toString_whenAllOnesOrZeros_matchesExpected")
  void toStringWhenAllOnesOrZerosMatchesExpected() {
    // Arrange
    BitArray ones = newFilled(SAMPLE_SIZE, true);
    BitArray zeros =
        newFilled(8, false); // use a different size to avoid a constant-parameter smell

    // Act
    String onesStr = ones.toString();
    String zerosStr = zeros.toString();

    // Assert
    assertEquals(repeat(SAMPLE_SIZE, '1'), onesStr);
    assertEquals(repeat(zeros.getSize(), '0'), zerosStr);
  }

  @Test
  @DisplayName("toString_whenZeroSize_returnsEmpty")
  void toStringWhenZeroSizeReturnsEmpty() {
    // Arrange
    BitArray arr = new BitArray(0);

    // Act & Assert
    assertEquals(0, arr.toString().length());
  }

  @Test
  @DisplayName("setBit_whenIndexGreaterThanSize_throwsAIOOBE")
  void setBitWhenIndexGreaterThanSizeThrowsAIOOBE() {
    // Arrange
    BitArray arr = new BitArray(SAMPLE_SIZE);

    // Act & Assert
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> arr.setBit(SAMPLE_SIZE + 1, true));
  }

  @Test
  @DisplayName("bitAccess_whenIndexNegative_throwsAIOOBE")
  void bitAccessWhenIndexNegativeThrowsAIOOBE() {
    // Arrange
    BitArray arr = new BitArray(SAMPLE_SIZE);

    // Act & Assert
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> arr.setBit(-1, true));
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> arr.bitAt(-1));
  }

  @Test
  @DisplayName("setAndGetBit_whenEvenIndices_setTrueAndOddRemainFalse")
  void setAndGetBitWhenEvenIndicesSetTrueAndOddRemainFalse() {
    // Arrange
    BitArray arr = new BitArray(SAMPLE_SIZE);

    // Act
    for (int i = 0; i < arr.getSize(); i += 2) {
      arr.setBit(i, true);
    }

    // Assert
    for (int i = 0; i < arr.getSize(); i += 2) {
      assertTrue(arr.bitAt(i));
    }
    for (int i = 1; i < arr.getSize(); i += 2) {
      assertFalse(arr.bitAt(i));
    }
  }

  @Test
  @DisplayName("unsignedByteToInt_whenAllByteValues_returnsUnsignedRange")
  void unsignedByteToIntWhenAllByteValuesReturnsUnsignedRange() {
    // Arrange, Act & Assert
    for (int i = 0; i < 256; i++) {
      byte b = (byte) i;
      assertEquals(i, BitArray.unsignedByteToInt(b));
    }
  }

  @Test
  @DisplayName("getSize_whenVariousSizes_returnsConfiguredSize")
  void getSizeWhenVariousSizesReturnsConfiguredSize() {
    // Arrange, Act & Assert
    assertEquals(0, new BitArray(0).getSize());
    assertEquals(SAMPLE_SIZE, new BitArray(SAMPLE_SIZE).getSize());
  }

  @Test
  @DisplayName("setAllOnes_whenCalled_setsEveryBitTrue")
  void setAllOnesWhenCalledSetsEveryBitTrue() {
    // Arrange
    BitArray expected = newFilled(SAMPLE_SIZE, true);
    BitArray actual = new BitArray(SAMPLE_SIZE);

    // Act
    actual.setAllOnes();

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  @DisplayName("firstOne_whenSingleBitSet_returnsCorrectIndexAndMinusOneWhenEmpty")
  void firstOneWhenSingleBitSetReturnsCorrectIndexAndMinusOneWhenEmpty() {
    // Arrange
    int oneByteBits = 8;
    BitArray arr = new BitArray(oneByteBits);

    // Act & Assert: exactly one bit set at each position
    for (int i = 0; i < oneByteBits; i++) {
      arr = new BitArray(oneByteBits);
      arr.setBit(i, true);
      assertEquals(i, arr.firstOne());
    }

    // All ones then progressively introduce zeros at the front
    arr.setAllOnes();
    for (int i = 0; i < oneByteBits - 1; i++) {
      arr.setBit(i, false);
      assertEquals(i + 1, arr.firstOne());
    }

    // All zeros
    arr.setBit(oneByteBits - 1, false);
    assertEquals(-1, arr.firstOne());
  }

  @Test
  @DisplayName("firstZero_whenMixedOrAllOnes_returnsExpectedIndexOrMinusOne")
  void firstZeroWhenMixedOrAllOnesReturnsExpectedIndexOrMinusOne() {
    // Arrange: 8 bits; set first three bits to 1, others 0
    BitArray arr = new BitArray(8);
    arr.setBit(0, true);
    arr.setBit(1, true);
    arr.setBit(2, true);

    // Act & Assert
    assertEquals(3, arr.firstZero(0));
    assertEquals(4, arr.firstZero(4));

    // All ones -> no zero within size
    arr.setAllOnes();
    assertEquals(-1, arr.firstZero(0));
    assertEquals(-1, arr.firstZero(5));
  }

  @Test
  @DisplayName("lastOne_whenMultipleBitsSet_returnsNearestAtOrBeforeStartOrMinusOne")
  void lastOneWhenMultipleBitsSetReturnsNearestAtOrBeforeStartOrMinusOne() {
    // Arrange
    BitArray arr = new BitArray(16);
    arr.setBit(3, true);
    arr.setBit(7, true);
    arr.setBit(12, true);

    // Assert
    assertEquals(12, arr.lastOne(Integer.MAX_VALUE));
    assertEquals(12, arr.lastOne(15));
    assertEquals(7, arr.lastOne(10));
    assertEquals(3, arr.lastOne(3));
    assertEquals(-1, arr.lastOne(2));

    BitArray empty = new BitArray(16);
    assertEquals(-1, empty.lastOne(Integer.MAX_VALUE));
    assertEquals(-1, empty.lastOne(0));
  }

  @Test
  @DisplayName("setSize_whenShrinkThenGrow_bitsBeyondNewSizeAreCleared")
  void setSizeWhenShrinkThenGrowBitsBeyondNewSizeAreCleared() {
    // Arrange
    BitArray arr = new BitArray(16);
    arr.setAllOnes();

    // Act: shrink then grow
    arr.setSize(9);
    arr.setSize(16);

    // Assert
    for (int i = 0; i < 9; i++) {
      assertTrue(arr.bitAt(i));
    }
    for (int i = 9; i < 16; i++) {
      assertFalse(arr.bitAt(i));
    }
  }

  @Test
  @DisplayName("serialization_roundTrip_preservesBitsAndSizeForNonByteMultiple")
  void serializationRoundTripPreservesBitsAndSizeForNonByteMultiple() throws IOException {
    // Arrange: size=10 (spans 2 full bytes + 2 bits => 3 bytes)
    BitArray original = new BitArray(10);
    original.setBit(0, true);
    original.setBit(6, true);
    original.setBit(9, true);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);

    // Act: write -> read
    original.writeToDataOutputStream(dos);
    byte[] serialized = bos.toByteArray();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(serialized));
    BitArray roundTrip = new BitArray(dis);

    // Assert
    assertEquals(original, roundTrip);
    assertEquals(BitArray.serializedLength(original.getSize()), serialized.length);
  }

  @Test
  @DisplayName("constructor_fromDataInput_whenSizeZeroOrNegative_throwsIOException")
  void constructorFromDataInputWhenSizeZeroOrNegativeThrowsIOException() throws IOException {
    // Arrange: size = 0
    ByteArrayOutputStream bos0 = new ByteArrayOutputStream();
    DataOutputStream dos0 = new DataOutputStream(bos0);
    dos0.writeInt(0);
    DataInputStream dis0 = new DataInputStream(new ByteArrayInputStream(bos0.toByteArray()));
    assertThrows(IOException.class, () -> new BitArray(dis0));

    // Arrange: size = -5
    ByteArrayOutputStream bosNeg = new ByteArrayOutputStream();
    DataOutputStream dosNeg = new DataOutputStream(bosNeg);
    dosNeg.writeInt(-5);
    DataInputStream disNeg = new DataInputStream(new ByteArrayInputStream(bosNeg.toByteArray()));
    assertThrows(IOException.class, () -> new BitArray(disNeg));
  }

  @Test
  @DisplayName("constructor_fromDataInputWithMaxSize_whenExceeds_throwsIOException")
  void constructorFromDataInputWithMaxSizeWhenExceedsThrowsIOException() throws IOException {
    // Arrange: encode size=16 with 2 bytes of data
    int size = 16;
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    dos.writeInt(size);
    dos.write(new byte[(size + 7) / 8]);

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));

    // Act & Assert
    assertThrows(IOException.class, () -> new BitArray(dis, 15));
  }

  @Test
  @DisplayName("equalsAndHashCode_whenSameBitsAndSize_areConsistent")
  void equalsAndHashCodeWhenSameBitsAndSizeAreConsistent() {
    // Arrange
    BitArray a = new BitArray(8);
    a.setBit(1, true);
    a.setBit(3, true);

    BitArray b = new BitArray(8);
    b.setBit(1, true);
    b.setBit(3, true);

    // Act & Assert
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());

    BitArray cDifferentBits = new BitArray(8);
    cDifferentBits.setBit(1, true);
    assertNotEquals(a, cDifferentBits);

    BitArray dDifferentSize = new BitArray(9);
    dDifferentSize.setBit(1, true);
    dDifferentSize.setBit(3, true);
    assertNotEquals(a, dDifferentSize);
  }
}
