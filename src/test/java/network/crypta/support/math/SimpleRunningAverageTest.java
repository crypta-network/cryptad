package network.crypta.support.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SimpleRunningAverageTest {
  private static final double EPS = 1e-9;

  private static void ignoreDouble(double ignored) {}

  private static void constructAverage(int window, double init) {
    new SimpleRunningAverage(window, init);
  }

  @Test
  void currentValue_whenNoReports_returnsInitValue() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(4, 100.0);

    // Act
    double value = avg.currentValue();

    // Assert
    assertEquals(100.0, value, EPS);
  }

  @Test
  void report_whenWithinWindow_updatesCurrentValue() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(4, 100.0);

    // Act & Assert
    avg.report(10);
    assertEquals(10.0, avg.currentValue(), EPS);

    avg.report(40);
    assertEquals(25.0, avg.currentValue(), EPS);

    avg.report(40);
    assertEquals(30.0, avg.currentValue(), EPS);

    avg.report(110);
    assertEquals(50.0, avg.currentValue(), EPS);
  }

  @Test
  void report_whenExceedsWindow_evictsOldestAndComputesAverage() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(4, 0.0);
    avg.report(10);
    avg.report(40);
    avg.report(40);
    avg.report(110); // window full: [10, 40, 40, 110]
    assertEquals(50.0, avg.currentValue(), EPS);

    // Act & Assert (oldest 10 evicted)
    avg.report(40); // [40, 40, 110, 40]
    assertEquals(57.5, avg.currentValue(), EPS);

    avg.report(10); // [40, 110, 40, 10]
    assertEquals(50.0, avg.currentValue(), EPS);
  }

  @Test
  void clear_whenCalled_resetsToInitialAndResetsCount() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(4, 100.0);
    for (int i = 0; i < 4; i++) avg.report(12345);
    assertEquals(12345.0, avg.currentValue(), EPS);
    assertEquals(4L, avg.countReports());

    // Act
    avg.clear();

    // Assert
    assertEquals(100.0, avg.currentValue(), EPS);
    assertEquals(0L, avg.countReports());
  }

  @ParameterizedTest
  @MethodSource("valueIfReportedNotFullCases")
  @DisplayName("valueIfReported when window not full includes hypothetical value")
  void valueIfReported_whenWindowNotFull_returnsAverageIncludingHypothetical(
      double[] alreadyReported, double hypothetical) {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(3, -1.0);
    Arrays.stream(alreadyReported).forEach(avg::report);
    double before = avg.currentValue();
    long countBefore = avg.countReports();

    // Act
    double predicted = avg.valueIfReported(hypothetical);

    // Assert
    double sum = Arrays.stream(alreadyReported).sum();
    double expected = (sum + hypothetical) / (alreadyReported.length + 1);
    assertEquals(expected, predicted, EPS);
    // Must not mutate state
    assertEquals(before, avg.currentValue(), EPS);
    assertEquals(countBefore, avg.countReports());
  }

  static Stream<Arguments> valueIfReportedNotFullCases() {
    return Stream.of(
        Arguments.of(new double[] {}, 8.0),
        Arguments.of(new double[] {2.0}, 8.0),
        Arguments.of(new double[] {2.0, 4.0}, 8.0));
  }

  @ParameterizedTest
  @MethodSource("valueIfReportedFullCases")
  @DisplayName("valueIfReported when window full replaces oldest value")
  void valueIfReported_whenWindowFull_returnsAverageWithOldestEvicted(
      int window, double[] initial, double hypothetical) {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(window, 0.0);
    Arrays.stream(initial).forEach(avg::report);
    double before = avg.currentValue();
    long countBefore = avg.countReports();

    // Sanity guard: window must be full for this case
    if (initial.length != window) throw new AssertionError("window not full in test setup");

    // Act
    double predicted = avg.valueIfReported(hypothetical);

    // Assert (oldest initial[0] will be evicted)
    double sum = Arrays.stream(initial).sum();
    double expected = (sum + hypothetical - initial[0]) / window;
    assertEquals(expected, predicted, EPS);
    // Must not mutate state
    assertEquals(before, avg.currentValue(), EPS);
    assertEquals(countBefore, avg.countReports());
  }

  static Stream<Arguments> valueIfReportedFullCases() {
    return Stream.of(
        Arguments.of(3, new double[] {2.0, 4.0, 6.0}, 0.0),
        Arguments.of(3, new double[] {2.0, 4.0, 6.0}, 3.0),
        Arguments.of(3, new double[] {2.0, 4.0, 6.0}, 9.0),
        Arguments.of(2, new double[] {5.0, 7.0}, 9.0));
  }

  @Test
  void valueIfReported_whenCalled_doesNotMutateState() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(3, 0.0);
    avg.report(1.0);
    avg.report(2.0);
    double before = avg.currentValue();
    long countBefore = avg.countReports();

    // Act
    double predictedHigh = avg.valueIfReported(100.0);
    double predictedLow = avg.valueIfReported(-100.0);

    // Assert (predictions are correct and state doesn't change)
    assertEquals((1.0 + 2.0 + 100.0) / 3.0, predictedHigh, EPS);
    assertEquals((1.0 + 2.0 - 100.0) / 3.0, predictedLow, EPS);
    assertEquals(before, avg.currentValue(), EPS);
    assertEquals(countBefore, avg.countReports());
  }

  @Test
  void reportLong_whenCalled_isEquivalentToReportDouble() {
    // Arrange
    SimpleRunningAverage a = new SimpleRunningAverage(2, 0.0);
    SimpleRunningAverage b = new SimpleRunningAverage(2, 0.0);

    // Act
    a.report(1L);
    a.report(3.0);

    b.report(1.0);
    b.report(3L);

    // Assert
    assertEquals(a.currentValue(), b.currentValue(), EPS);
    assertEquals(a.countReports(), b.countReports());
  }

  @Test
  void countReports_whenMoreThanWindow_reportsMonotonicIncrease() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(3, 0.0);

    // Act
    for (int i = 0; i < 10; i++) avg.report(i);

    // Assert
    assertEquals(10L, avg.countReports());
  }

  @Test
  void constructor_whenZeroLength_thenReport_throwsArrayIndex() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(0, 7.0);

    // Assert: current value still returns init
    assertEquals(7.0, avg.currentValue(), EPS);
    assertEquals(0L, avg.countReports());

    // Act & Assert: operations that access storage fail
    assertThrows(
        ArrayIndexOutOfBoundsException.class, () -> ignoreDouble(avg.valueIfReported(1.0)));
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> avg.report(1.0));
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> avg.report(1L));
  }

  @Test
  void constructor_whenNegativeLength_throwsNegativeArraySize() {
    assertThrows(NegativeArraySizeException.class, () -> constructAverage(-1, 0.0));
  }

  @Test
  void toString_whenNoReports_containsAverageNaNAndDoesNotThrow() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(3, 42.0);

    // Act
    String s = avg.toString();

    // Assert: should include average=NaN when no reports
    // (toString computes total/curLen directly).
    assertFalse(s.isEmpty());
    org.hamcrest.MatcherAssert.assertThat(s, org.hamcrest.Matchers.containsString("average="));
    org.hamcrest.MatcherAssert.assertThat(s, org.hamcrest.Matchers.containsString("NaN"));
  }

  @Test
  void toString_whenHasReports_containsAverageNotNaN() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(2, 0.0);
    avg.report(2.0);

    // Act
    String s = avg.toString();

    // Assert
    org.hamcrest.MatcherAssert.assertThat(s, org.hamcrest.Matchers.containsString("average="));
    org.hamcrest.MatcherAssert.assertThat(
        s, org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("NaN")));
  }

  @Test
  void copyConstructor_whenOriginalMutates_copyRemainsIndependent() {
    // Arrange
    SimpleRunningAverage original = new SimpleRunningAverage(3, 0.0);
    original.report(10.0);
    original.report(20.0);
    original.report(30.0); // avg = 20
    SimpleRunningAverage copy = new SimpleRunningAverage(original);

    // Act (mutate original; evict 10)
    original.report(100.0); // now [20, 30, 100] => avg 50

    // Assert
    assertEquals(20.0, copy.currentValue(), EPS);
    assertEquals(3L, copy.countReports());
    assertEquals(50.0, original.currentValue(), EPS);
    assertEquals(4L, original.countReports());
  }

  @Test
  void report_whenNaNInput_propagatesNaN() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(2, 0.0);
    avg.report(1.0);

    // Act
    avg.report(Double.NaN);

    // Assert: any arithmetic with NaN yields NaN
    String s = avg.toString();
    org.hamcrest.MatcherAssert.assertThat(s, org.hamcrest.Matchers.containsString("average=NaN"));
  }

  @Test
  void report_whenInfinityInput_propagatesInfinity() {
    // Arrange
    SimpleRunningAverage avg = new SimpleRunningAverage(2, 0.0);
    avg.report(Double.POSITIVE_INFINITY);

    // Assert
    String s = avg.toString();
    org.hamcrest.MatcherAssert.assertThat(
        s, org.hamcrest.Matchers.containsString("average=Infinity"));
  }
}
