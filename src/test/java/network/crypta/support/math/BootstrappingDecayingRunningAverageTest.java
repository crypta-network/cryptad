package network.crypta.support.math;

import java.util.stream.DoubleStream;
import java.util.stream.Stream;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link BootstrappingDecayingRunningAverage}.
 *
 * <p>Style: AAA (Arrange-Act-Assert), deterministic, and parameterized where helpful.
 */
class BootstrappingDecayingRunningAverageTest {
  private static final double EPS = 1e-9;

  // --- Utilities

  private static BootstrappingDecayingRunningAverage newAvg(
      double def, double min, double max, int maxReports) {
    return new BootstrappingDecayingRunningAverage(def, min, max, maxReports, null);
  }

  private static double arithmeticMean(double... vals) {
    return DoubleStream.of(vals).average().orElse(Double.NaN);
  }

  // --- Step 1: API surface and invariants (documented as tests below)

  @Test
  void currentValue_whenNoReports_expectDefault() {
    // Arrange
    var avg = newAvg(42.25, 0, 100, 8);
    // Act
    double cv = avg.currentValue();
    // Assert
    assertEquals(42.25, cv, EPS);
    assertEquals(0L, avg.countReports());
  }

  @ParameterizedTest
  @ValueSource(ints = {0, -1, -10})
  void constructor_whenMaxReportsNonPositive_expectIllegalArgument(int badMaxReports) {
    // Arrange / Act / Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> new BootstrappingDecayingRunningAverage(0.0, 0, 100, badMaxReports, null));
  }

  @ParameterizedTest
  @MethodSource("validBoundaryValues")
  void report_whenAtInclusiveBoundaries_expectAccepted(double min, double max, double value) {
    // Arrange
    var avg = newAvg(1000.0, min, max, 10);
    // Act
    avg.report(value);
    // Assert - first valid report uses weight 1 and becomes the value
    assertEquals(value, avg.currentValue(), EPS);
    assertEquals(1L, avg.countReports());
  }

  static Stream<Arguments> validBoundaryValues() {
    return Stream.of(
        Arguments.of(0.0, 100.0, 0.0), // min boundary
        Arguments.of(0.0, 100.0, 100.0), // max boundary
        Arguments.of(-5.0, -1.0, -5.0), // negative min boundary
        Arguments.of(-5.0, -1.0, -1.0)); // negative max boundary
  }

  @ParameterizedTest
  @MethodSource("invalidValues")
  void report_whenInvalidInput_expectIgnored(double invalid) {
    // Arrange
    var avg = newAvg(10.0, 0.0, 100.0, 4);
    // Act
    avg.report(invalid);
    // Assert
    assertEquals(10.0, avg.currentValue(), EPS);
    assertEquals(0L, avg.countReports());
  }

  static Stream<Arguments> invalidValues() {
    return Stream.of(
        Arguments.of(Double.NaN),
        Arguments.of(Double.POSITIVE_INFINITY),
        Arguments.of(Double.NEGATIVE_INFINITY),
        Arguments.of(-1.0), // below min
        Arguments.of(101.0) // above max
        );
  }

  @ParameterizedTest
  @MethodSource("invalidValues")
  void valueIfReported_whenInvalidInput_expectUnchanged(double invalid) {
    // Arrange
    var avg = newAvg(7.5, 0.0, 100.0, 3);
    // Act
    double predicted = avg.valueIfReported(invalid);
    // Assert
    assertEquals(7.5, predicted, EPS);
    assertEquals(7.5, avg.currentValue(), EPS);
    assertEquals(0L, avg.countReports());
  }

  @Test
  void reportLong_whenWithinRange_expectAcceptedAndCountIncremented() {
    // Arrange
    var avg = newAvg(0.0, 0.0, 1000.0, 5);
    // Act
    avg.report(200L);
    // Assert
    assertEquals(200.0, avg.currentValue(), EPS);
    assertEquals(1L, avg.countReports());
  }

  @Test
  void report_whenBootstrapping_expectArithmeticMeanOverEarlyReports() {
    // Arrange
    var avg = newAvg(999.0, -100.0, 1000.0, 10); // maxReports > number of values
    double[] vals = {10.0, 20.0, 30.0, 40.0, 50.0};
    // Act
    for (double v : vals) avg.report(v);
    // Assert
    assertEquals(arithmeticMean(vals), avg.currentValue(), EPS);
    assertEquals(vals.length, avg.countReports());
  }

  @Test
  void report_whenBeyondMaxReports_expectExponentialDecayWeight() {
    // Arrange: maxReports = 3 => steady weight = 1/3 after 3 reports
    var avg = newAvg(0.0, 0.0, 100.0, 3);
    avg.report(9.0); // cv = 9
    avg.report(9.0); // cv = 9
    avg.report(9.0); // cv = 9
    assertEquals(3L, avg.countReports());
    assertEquals(9.0, avg.currentValue(), EPS);

    // Act: next report uses decayFactor = 1 / min(4, 3) = 1/3
    double predicted = avg.valueIfReported(12.0);
    avg.report(12.0);

    // Assert
    double expected = (12.0 * (1.0 / 3.0)) + (9.0 * (1.0 - (1.0 / 3.0)));
    assertEquals(expected, predicted, EPS);
    assertEquals(expected, avg.currentValue(), EPS);
    assertEquals(4L, avg.countReports());
  }

  @Test
  void valueIfReported_whenCalled_expectMatchesSubsequentReport() {
    // Arrange
    var avg = newAvg(5.0, 0.0, 100.0, 4);
    avg.report(9.0);
    avg.report(13.0);
    // Act
    double predicted = avg.valueIfReported(17.0);
    avg.report(17.0);
    // Assert
    assertEquals(predicted, avg.currentValue(), EPS);
  }

  @Test
  void constructor_whenFieldSetHasValidStoredValues_expectInitializesFromFieldSet() {
    // Arrange
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("CurrentValue", 42.5);
    fs.put("Reports", 10L);
    // Act
    var avg = new BootstrappingDecayingRunningAverage(0.0, 0.0, 100.0, 8, fs);
    // Assert
    assertEquals(42.5, avg.currentValue(), EPS);
    assertEquals(10L, avg.countReports());
  }

  @Test
  void constructor_whenFieldSetHasInvalidCurrentValue_expectIgnoresAndUsesDefault() {
    // Arrange
    SimpleFieldSet fs = mock(SimpleFieldSet.class);
    when(fs.getDouble(eq("CurrentValue"), anyDouble())).thenReturn(Double.NaN);
    // If code were to call getLong, it's a bug in this path; make it obvious if it happens
    when(fs.getLong(eq("Reports"), anyLong()))
        .thenAnswer(
            inv -> {
              fail("getLong should not be called when CurrentValue is invalid");
              return 99L;
            });

    // Act
    var avg = new BootstrappingDecayingRunningAverage(7.0, 0.0, 100.0, 8, fs);

    // Assert
    assertEquals(7.0, avg.currentValue(), EPS); // default retained
    assertEquals(0L, avg.countReports()); // reports not overridden
    verify(fs, times(1)).getDouble(eq("CurrentValue"), anyDouble());
    verify(fs, never()).getLong(eq("Reports"), anyLong());
  }

  @Test
  void exportFieldSet_whenCalled_expectContainsTypeAndValues() {
    // Arrange
    var avg = newAvg(3.0, 0.0, 100.0, 5);
    avg.report(5.0);
    avg.report(7.0);
    // Act
    SimpleFieldSet out = avg.exportFieldSet(true);
    // Assert
    assertEquals("BootstrappingDecayingRunningAverage", out.get("Type"));
    assertEquals(avg.currentValue(), out.getDouble("CurrentValue", -1.0), EPS);
    assertEquals(avg.countReports(), out.getLong("Reports", -1));
  }

  @Test
  void copyConstructor_whenSourceMutatesLater_expectSnapshotIndependence() {
    // Arrange
    var original = newAvg(0.0, 0.0, 100.0, 4);
    original.report(10.0);
    original.report(20.0);
    var copy = new BootstrappingDecayingRunningAverage(original);

    // Act - mutate original further
    original.report(30.0);

    // Assert - copy remains as it was at snapshot time
    assertNotEquals(original.currentValue(), copy.currentValue(), EPS);
    assertEquals(2L, copy.countReports());
  }

  @Test
  void changeMaxReports_whenSetToSmaller_expectHeavierWeightOnNextObservation() {
    // Arrange
    var avg = newAvg(0.0, 0.0, 100.0, 5);
    avg.report(10.0); // n=1, cv=10
    avg.report(20.0); // n=2, cv=15
    double predictedBefore = avg.valueIfReported(100.0); // would use 1/3

    // Act - reduce maxReports so next uses weight 1/2 instead of 1/3
    avg.changeMaxReports(2);
    double predictedAfter = avg.valueIfReported(100.0);

    // Assert
    double expectedBefore = (100.0 * (1.0 / 3.0)) + (15.0 * (1.0 - (1.0 / 3.0)));
    double expectedAfter = (100.0 * (1.0 / 2.0)) + (15.0 * (1.0 - (1.0 / 2.0)));
    assertEquals(expectedBefore, predictedBefore, EPS);
    assertEquals(expectedAfter, predictedAfter, EPS);
    assertTrue(
        predictedAfter > predictedBefore, "Smaller maxReports should increase weight of new value");
  }

  @Test
  void changeMaxReports_whenSetToZero_expectNaNOnNextPredictionAndUpdate() {
    // Arrange
    var avg = newAvg(1.0, 0.0, 100.0, 5);
    avg.report(5.0); // one valid report
    assertEquals(1L, avg.countReports());
    // Act
    avg.changeMaxReports(0);
    double predicted = avg.valueIfReported(10.0);
    avg.report(10.0);
    // Assert
    assertTrue(Double.isNaN(predicted));
    assertTrue(Double.isNaN(avg.currentValue()));
  }
}
