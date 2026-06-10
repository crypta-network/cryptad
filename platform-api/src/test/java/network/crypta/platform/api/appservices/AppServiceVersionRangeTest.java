package network.crypta.platform.api.appservices;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppServiceVersionRangeTest {
  @Test
  void contains_whenNumericPartExceedsIntegerRange_expectVersionMismatchOnly() {
    AppServiceVersionRange range = new AppServiceVersionRange("2147483648", "2147483650");

    assertTrue(range.contains("2147483649"));
    assertFalse(range.contains("2147483647"));
    assertFalse(range.contains("2147483651"));
  }

  @Test
  void constructor_whenLargeMinimumExceedsLargeMaximum_expectRangeValidationError() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new AppServiceVersionRange("2147483650", "2147483648"));

    assertEquals("minimum service version must not exceed maximum", exception.getMessage());
  }

  @Test
  void contains_whenLargeNumericPartsHaveLeadingZeroes_expectNumericComparison() {
    AppServiceVersionRange range = new AppServiceVersionRange("1.0000000000000000000002", "1.10");

    assertTrue(range.contains("1.2"));
  }

  @Test
  void contains_whenProviderVersionUsesDisplayText_expectVersionMismatchOnly() {
    AppServiceVersionRange range = new AppServiceVersionRange("1", "2");

    assertFalse(range.contains("RC 1"));
  }
}
