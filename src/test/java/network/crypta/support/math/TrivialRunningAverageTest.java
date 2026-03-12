package network.crypta.support.math;

import java.io.Serial;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/** Unit tests for {@link TrivialRunningAverage}. */
class TrivialRunningAverageTest {

  // ---- Constructors and initial state ----

  @Test
  void currentValue_whenEmpty_returnsNaN() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    double current = avg.currentValue();

    // Assert
    assertTrue(Double.isNaN(current), "Empty average should be NaN");
  }

  @Test
  void totalValue_whenEmpty_returnsZero() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act & Assert
    assertEquals(0.0, avg.totalValue(), 0.0);
  }

  @Test
  void countReports_whenNew_returnsZero() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act & Assert
    assertEquals(0L, avg.countReports());
  }

  @Test
  @SuppressWarnings({"ConstantConditions", "DataFlowIssue"})
  void constructor_whenNullAverage_throwsNullPointerException() {
    // Arrange
    TrivialRunningAverage source = null;

    // Act & Assert
    assertThrows(NullPointerException.class, () -> new TrivialRunningAverage(source));
  }

  @Test
  void copyConstructor_whenSourceHasValues_copiesSnapshotAndIsIndependent() {
    // Arrange
    TrivialRunningAverage original = new TrivialRunningAverage();
    original.report(10.0);
    original.report(20.0);
    long originalReportsBefore = original.countReports();
    double originalTotalBefore = original.totalValue();

    // Act
    TrivialRunningAverage copy = new TrivialRunningAverage(original);

    // Assert snapshot copied
    assertEquals(originalReportsBefore, copy.countReports());
    assertEquals(originalTotalBefore, copy.totalValue(), 0.0);
    assertEquals(original.currentValue(), copy.currentValue(), 1e-12);

    // Mutate original; copy should not change
    original.report(30.0);
    assertEquals(originalReportsBefore + 1, original.countReports());
    assertEquals(originalReportsBefore, copy.countReports());

    // Mutate copy; original should not change further
    copy.report(40.0);
    assertEquals(originalReportsBefore + 1, original.countReports());
    assertEquals(originalReportsBefore + 1, copy.countReports());
  }

  // ---- Reporting and averaging behavior ----

  static Stream<Arguments> sequencesAndMeans() {
    return Stream.of(
        Arguments.of(new double[] {42.0}, 42.0),
        Arguments.of(new double[] {1.0, 3.0}, 2.0),
        Arguments.of(new double[] {-2.0, 2.0}, 0.0),
        Arguments.of(new double[] {0.0, 0.0, 0.0}, 0.0),
        Arguments.of(new double[] {1.5, 2.5, 3.0}, (1.5 + 2.5 + 3.0) / 3.0));
  }

  @ParameterizedTest
  @MethodSource("sequencesAndMeans")
  @DisplayName("report(double) accumulates average correctly for sequences")
  void report_whenDoubleSequence_computeCorrectAverage(double[] values, double expectedMean) {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    for (double v : values) {
      avg.report(v);
    }

    // Assert
    assertEquals(values.length, avg.countReports());
    assertEquals(Arrays.stream(values).sum(), avg.totalValue(), 1e-12);
    assertEquals(expectedMean, avg.currentValue(), 1e-12);
  }

  static Stream<Arguments> longSequencesAndMeans() {
    return Stream.of(
        Arguments.of(new long[] {5L}, 5.0),
        Arguments.of(new long[] {1L, 2L, 3L}, 2.0),
        Arguments.of(new long[] {-10L, 10L}, 0.0));
  }

  @ParameterizedTest
  @MethodSource("longSequencesAndMeans")
  void report_whenLongSequence_computeCorrectAverage(long[] values, double expectedMean) {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    for (long v : values) {
      avg.report(v);
    }

    // Assert
    assertEquals(values.length, avg.countReports());
    double total = Arrays.stream(values).asDoubleStream().sum();
    assertEquals(total, avg.totalValue(), 1e-12);
    assertEquals(expectedMean, avg.currentValue(), 1e-12);
  }

  @Test
  void valueIfReported_whenEmpty_returnsThatValueAndDoesNotMutate() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    double predicted = avg.valueIfReported(7.5);

    // Assert
    assertEquals(7.5, predicted, 0.0);
    assertEquals(0L, avg.countReports());
    assertEquals(0.0, avg.totalValue(), 0.0);
    assertTrue(Double.isNaN(avg.currentValue()));
  }

  @Test
  void valueIfReported_whenNonEmpty_returnsPredictedAndDoesNotMutate() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();
    avg.report(2.0);
    avg.report(4.0);
    long beforeReports = avg.countReports();
    double beforeTotal = avg.totalValue();

    // Act
    double predicted = avg.valueIfReported(6.0);

    // Assert: predicted mean (2 + 4 + 6) / 3 = 4.0
    assertEquals(4.0, predicted, 1e-12);
    assertEquals(beforeReports, avg.countReports());
    assertEquals(beforeTotal, avg.totalValue(), 0.0);
    assertEquals((2.0 + 4.0) / 2.0, avg.currentValue(), 1e-12);
  }

  // ---- Special numeric values ----

  @Test
  void report_whenNaN_propagatesToAverageAndTotal() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    avg.report(Double.NaN);

    // Assert
    assertEquals(1L, avg.countReports());
    assertTrue(Double.isNaN(avg.totalValue()));
    assertTrue(Double.isNaN(avg.currentValue()));
    assertTrue(Double.isNaN(avg.valueIfReported(1.0)));
  }

  @Test
  void report_whenInfinity_propagatesToAverageAndTotal() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    avg.report(Double.POSITIVE_INFINITY);

    // Assert
    assertEquals(1L, avg.countReports());
    assertTrue(Double.isInfinite(avg.totalValue()));
    assertTrue(Double.isInfinite(avg.currentValue()));
  }

  @Test
  void report_whenDoubleMaxLeadsToOverflow_averageBecomesInfinity() {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    // Act
    avg.report(Double.MAX_VALUE);
    avg.report(Double.MAX_VALUE); // total should overflow to +Infinity

    // Assert
    assertEquals(2L, avg.countReports());
    assertTrue(Double.isInfinite(avg.totalValue()));
    assertTrue(Double.isInfinite(avg.currentValue()));
  }

  // ---- Concurrency (deterministic) ----

  @Test
  void report_whenConcurrent_updatesDeterministically()
      throws InterruptedException, ExecutionException {
    // Arrange
    TrivialRunningAverage avg = new TrivialRunningAverage();

    int threads = 4;
    int itemsPerThread = 1000;
    try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
      CountDownLatch start = new CountDownLatch(1);
      CountDownLatch done = new CountDownLatch(threads);
      List<Future<?>> futures = new ArrayList<>(threads);

      List<Double> expectedValues = new ArrayList<>(threads * itemsPerThread);
      for (int t = 0; t < threads; t++) {
        for (int i = 1; i <= itemsPerThread; i++) {
          expectedValues.add((double) (t * itemsPerThread + i));
        }
      }

      for (int t = 0; t < threads; t++) {
        final int threadIndex = t;
        futures.add(
            pool.submit(
                () -> {
                  try {
                    start.await();
                    int base = threadIndex * itemsPerThread;
                    for (int i = 1; i <= itemsPerThread; i++) {
                      avg.report(base + i);
                    }
                  } catch (InterruptedException _) {
                    Thread.currentThread().interrupt();
                    fail("Interrupted during test execution");
                  } finally {
                    done.countDown();
                  }
                }));
      }

      // Act
      start.countDown();
      boolean finished = done.await(10, TimeUnit.SECONDS);

      // Assert
      assertTrue(finished, "Worker threads should finish promptly");
      for (Future<?> future : futures) {
        future.get();
      }
      long expectedCount = (long) threads * itemsPerThread;
      double expectedTotal = expectedValues.stream().mapToDouble(Double::doubleValue).sum();

      assertEquals(expectedCount, avg.countReports());
      assertEquals(expectedTotal, avg.totalValue(), 1e-8);
      assertEquals(expectedTotal / expectedCount, avg.currentValue(), 1e-8);
    }
  }

  // ---- RunningAverage.copyOf() behavior ----

  @Test
  void copyOf_whenNull_throwsNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(NullPointerException.class, () -> RunningAverage.copyOf(null));
  }

  @Test
  void copyOf_whenTrivialRunningAverage_returnsEquivalentIndependentCopy() {
    // Arrange
    TrivialRunningAverage original = new TrivialRunningAverage();
    original.report(100);
    original.report(200);
    long reportsBefore = original.countReports();
    double totalBefore = original.totalValue();
    double meanBefore = original.currentValue();

    // Act
    RunningAverage copyAsIface = RunningAverage.copyOf(original);

    // Assert: type may not be the same static type, but state must match and be independent
    assertInstanceOf(TrivialRunningAverage.class, copyAsIface);
    TrivialRunningAverage copy = (TrivialRunningAverage) copyAsIface;
    assertEquals(reportsBefore, copy.countReports());
    assertEquals(totalBefore, copy.totalValue(), 0.0);
    assertEquals(meanBefore, copy.currentValue(), 1e-12);

    // Mutations do not affect each other
    original.report(300);
    assertEquals(reportsBefore + 1, original.countReports());
    assertEquals(reportsBefore, copy.countReports());
    copy.report(400);
    assertEquals(reportsBefore + 1, copy.countReports());
  }

  @Test
  void copyOf_whenUnknownImplementation_throwsUnsupportedOperationException() {
    // Arrange: a minimal unknown implementation
    class UnknownAverage implements RunningAverage {
      @Serial private static final long serialVersionUID = 1L;
      private long n;
      private double t;

      @Override
      public double currentValue() {
        return n == 0 ? Double.NaN : t / n;
      }

      @Override
      public void report(double d) {
        t += d;
        n++;
      }

      @Override
      public void report(long d) {
        t += d;
        n++;
      }

      @Override
      public double valueIfReported(double r) {
        return (t + r) / (n + 1);
      }

      @Override
      public long countReports() {
        return n;
      }
    }
    RunningAverage unknown = new UnknownAverage();
    unknown.report(1.0);

    // Act & Assert
    assertThrows(UnsupportedOperationException.class, () -> RunningAverage.copyOf(unknown));
  }
}
