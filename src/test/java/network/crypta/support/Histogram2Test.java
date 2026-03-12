package network.crypta.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for {@link Histogram2}.
 *
 * <p>Focus areas: - Bin selection across boundary values and typical inputs. - Per-bin averaging
 * via the underlying running averages. - Scaling behavior of {@link
 * Histogram2#getPercentageArray(int)}.
 */
@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
class Histogram2Test {

  @Test
  @DisplayName("constructor_whenCreated_expectZeroedBars")
  void constructor_whenCreated_expectZeroedBars() {
    // Arrange
    int bars = 5;
    int max = 100;
    Histogram2 h = new Histogram2(bars, max);

    // Act
    int[] percentages = h.getPercentageArray(100);

    // Assert
    assertEquals(bars, percentages.length, "array length = numBars");
    assertArrayEquals(new int[bars], percentages, "all bars start at 0");
  }

  @Test
  @DisplayName("report_whenKeyOutOfRange_expectIgnored")
  void report_whenKeyOutOfRange_expectIgnored() {
    // Arrange
    Histogram2 h = new Histogram2(4, 100);

    // Act: keys < 0 and >= MAX are ignored
    h.report(-0.0001, 50);
    h.report(100.0, 50);
    h.report(1234.56, 50);

    // Assert: still all zeros
    assertArrayEquals(new int[] {0, 0, 0, 0}, h.getPercentageArray(100));
  }

  @ParameterizedTest(name = "key={0} -> bin={1}")
  @CsvSource({
    // Lower edges
    "0.0, 0",
    "0.1, 0",
    "24.9999, 0",
    // Exact cutoffs for 4 equally-sized bins across [0,100)
    "25.0, 1",
    "49.9999, 1",
    "50.0, 2",
    "74.9999, 2",
    "75.0, 3",
    "99.9999, 3"
  })
  @DisplayName("report_whenKeyWithinRange_expectCorrectBin")
  void report_whenKeyWithinRange_expectCorrectBin(double key, int expectedBin) {
    // Arrange
    Histogram2 h = new Histogram2(4, 100);

    // Act
    h.report(key, 50.0);
    int[] out = h.getPercentageArray(100);

    // Assert: only expected bin is non-zero and equals value (50)
    int[] expected = new int[] {0, 0, 0, 0};
    expected[expectedBin] = 50; // 50 * 100 / 100 = 50
    assertArrayEquals(expected, out);
  }

  @Test
  @DisplayName("report_whenMultipleReportsPerBin_expectPerBinAverages")
  void report_whenMultipleReportsPerBin_expectPerBinAverages() {
    // Arrange
    Histogram2 h = new Histogram2(4, 100);

    // Act: populate bin 0 with values -> average should be (20 + 40) / 2 = 30
    h.report(0.0, 20);
    h.report(10.0, 40);

    // Populate bin 2 with three values -> average = (30 + 60 + 90) / 3 = 60
    h.report(50.0, 30);
    h.report(60.0, 60);
    h.report(70.0, 90);

    int[] out = h.getPercentageArray(100);

    // Assert: scaled by localMax=100 and MAX=100, so equals the averages
    assertArrayEquals(new int[] {30, 0, 60, 0}, out);
  }

  @Test
  @DisplayName("getPercentageArray_whenScaled_expectUsesLocalMax")
  void getPercentageArray_whenScaled_expectUsesLocalMax() {
    // Arrange
    Histogram2 h = new Histogram2(3, 100);

    // Act: put a single report with value = MAX into bin 0
    h.report(0.0, 100.0);

    // Scale to a small localMax; with average == MAX, the scaled value should equal localMax
    int[] out = h.getPercentageArray(7);

    // Assert
    assertArrayEquals(new int[] {7, 0, 0}, out);
  }

  @Test
  @DisplayName("getPercentageArray_whenLocalMaxIsZero_expectAllZero")
  void getPercentageArray_whenLocalMaxIsZero_expectAllZero() {
    // Arrange
    Histogram2 h = new Histogram2(2, 100);
    h.report(10.0, 100.0); // non-zero value to ensure scaling by 0 zeros it out

    // Act
    int[] out = h.getPercentageArray(0);

    // Assert
    assertArrayEquals(new int[] {0, 0}, out);
  }

  @Test
  @DisplayName("report_whenSingleBin_expectAllKeysMapToThatBin")
  void report_whenSingleBin_expectAllKeysMapToThatBin() {
    // Arrange
    Histogram2 h = new Histogram2(1, 100);

    // Act
    h.report(0.0, 10);
    h.report(50.0, 20);
    h.report(99.9999, 30);

    // Average for the single bin = (10 + 20 + 30) / 3 = 20
    int[] out = h.getPercentageArray(100);

    // Assert
    assertAll(() -> assertEquals(1, out.length), () -> assertEquals(20, out[0]));
  }
}
