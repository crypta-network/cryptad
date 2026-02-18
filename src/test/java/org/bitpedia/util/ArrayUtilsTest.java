package org.bitpedia.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ArrayUtilsTest {

  private static void ignoreString(String ignored) {}

  @ParameterizedTest
  @CsvSource({"0,00", "1,01", "15,0f", "16,10", "127,7f", "-1,ff", "-128,80"})
  @DisplayName("byteToHex returns two lowercase hex chars for any byte value")
  void byteToHex_whenAnyByte_expectTwoDigitLowercase(int value, String expected) {
    // Arrange
    byte input = (byte) value;

    // Act
    String result = ArrayUtils.byteToHex(input);

    // Assert
    assertEquals(expected, result);
  }

  @Test
  void byteArrayToHex_whenSliceRequested_returnsConcatenatedHex() {
    // Arrange
    byte[] data = new byte[] {0x00, 0x01, 0x0F, 0x10, (byte) 0xAB};

    // Act
    String result = ArrayUtils.byteArrayToHex(data, 1, 3);

    // Assert
    assertEquals("010f10", result);
  }

  @Test
  void byteArrayToHex_whenLengthIsZero_returnsEmptyString() {
    // Arrange
    byte[] data = new byte[] {0x01, 0x02};

    // Act
    String result = ArrayUtils.byteArrayToHex(data, 0, 0);

    // Assert
    assertEquals("", result);
  }

  @Test
  void byteArrayToHex_whenOffsetNegative_throwsException() {
    // Arrange
    byte[] data = new byte[] {0x01, 0x02};

    // Act + Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> ignoreString(ArrayUtils.byteArrayToHex(data, -1, 1)));
  }

  @Test
  void byteArrayToHex_whenOffsetBeyondArray_throwsException() {
    // Arrange
    byte[] data = new byte[] {0x01, 0x02};

    // Act + Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> ignoreString(ArrayUtils.byteArrayToHex(data, 2, 1)));
  }

  @Test
  void byteArrayToHex_whenArrayIsNull_throwsNullPointerException() {
    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> ignoreString(ArrayUtils.byteArrayToHex(null, 0, 1)));
  }
}
