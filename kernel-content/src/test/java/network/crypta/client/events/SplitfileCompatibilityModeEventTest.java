package network.crypta.client.events;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class SplitfileCompatibilityModeEventTest {

  @Test
  void getCode_whenCalled_returnsDefinedConstant() {
    // Arrange
    byte[] key = new byte[] {1, 2, 3, 4};
    SplitfileCompatibilityModeEvent evt =
        new SplitfileCompatibilityModeEvent(
            SplitfileCompatibilityMode.COMPAT_1250,
            SplitfileCompatibilityMode.COMPAT_1468,
            key,
            false,
            true);

    // Act
    int code = evt.getCode();

    // Assert
    assertEquals(SplitfileCompatibilityModeEvent.CODE, code);
    assertEquals(0x0D, code);
  }

  @Test
  void getDescription_whenEnumsProvided_formatsExpectedString() {
    // Arrange
    byte[] key = new byte[] {9};
    SplitfileCompatibilityModeEvent evt =
        new SplitfileCompatibilityModeEvent(
            SplitfileCompatibilityMode.COMPAT_1250_EXACT,
            SplitfileCompatibilityMode.COMPAT_1468,
            key,
            true,
            false);

    // Act
    String description = evt.getDescription();

    // Assert
    assertEquals("CompatibilityMode between COMPAT_1250_EXACT and COMPAT_1468", description);
  }

  @Test
  void constructor_whenValuesProvided_setsAllFields() {
    // Arrange
    SplitfileCompatibilityMode min = SplitfileCompatibilityMode.COMPAT_1251;
    SplitfileCompatibilityMode max = SplitfileCompatibilityMode.COMPAT_1416;
    byte[] key = new byte[] {10, 11, 12};
    boolean dontCompress = true;
    boolean bottomLayer = true;

    // Act
    SplitfileCompatibilityModeEvent evt =
        new SplitfileCompatibilityModeEvent(min, max, key, dontCompress, bottomLayer);

    // Assert
    assertSame(min, evt.minCompatibilityMode);
    assertSame(max, evt.maxCompatibilityMode);
    assertSame(key, evt.splitfileCryptoKey);
    assertArrayEquals(new byte[] {10, 11, 12}, evt.splitfileCryptoKey);
    assertTrue(evt.dontCompress);
    assertTrue(evt.bottomLayer);
  }

  @Test
  void getDescription_whenNullEnums_returnsLiteralNullText() {
    // Arrange
    SplitfileCompatibilityModeEvent evt =
        new SplitfileCompatibilityModeEvent(null, null, null, false, false);

    // Act
    String description = evt.getDescription();

    // Assert
    assertEquals("CompatibilityMode between null and null", description);
    assertNull(evt.splitfileCryptoKey);
  }

  @Test
  void getDescription_whenMinNullMaxPresent_formatsMixedString() {
    // Arrange
    SplitfileCompatibilityModeEvent evt =
        new SplitfileCompatibilityModeEvent(
            null, SplitfileCompatibilityMode.COMPAT_1250, new byte[] {1}, false, false);

    // Act
    String description = evt.getDescription();

    // Assert
    assertEquals("CompatibilityMode between null and COMPAT_1250", description);
  }

  @Test
  void byCode_whenKnownCode_returnsDetachedMode() {
    // Arrange
    short code = SplitfileCompatibilityMode.COMPAT_1416.code;

    // Act
    SplitfileCompatibilityMode mode = SplitfileCompatibilityMode.byCode(code);

    // Assert
    assertSame(SplitfileCompatibilityMode.COMPAT_1416, mode);
  }

  @Test
  void byCode_whenUnknownCode_throwsIllegalArgumentException() {
    // Arrange
    short code = 99;

    // Act & Assert
    assertThrows(IllegalArgumentException.class, () -> SplitfileCompatibilityMode.byCode(code));
  }
}
