package org.spaceroots.mantissa.random;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ScalarSampleStatisticsTest {

  @Test
  void constructor_whenNewInstance_expectEmptySampleDefaults() {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();

    assertEquals(0, stats.size());
    assertTrue(Double.isNaN(stats.getMin()));
    assertTrue(Double.isNaN(stats.getMax()));
    assertEquals(0.0, stats.getMean(), 0.0);
    assertEquals(0.0, stats.getStandardDeviation(), 0.0);
  }

  @Test
  void add_whenSinglePoint_expectStatsSetToPoint() {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();

    stats.add(5.0);

    assertEquals(1, stats.size());
    assertEquals(5.0, stats.getMin(), 0.0);
    assertEquals(5.0, stats.getMax(), 0.0);
    assertEquals(5.0, stats.getMean(), 0.0);
    assertEquals(0.0, stats.getStandardDeviation(), 0.0);
  }

  @Test
  void add_whenMultiplePoints_expectMinMaxMeanAndStdUpdated() {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();
    double[] points = {1.0, 2.0, 3.0, 4.0};

    for (double point : points) {
      stats.add(point);
    }

    assertEquals(4, stats.size());
    assertEquals(1.0, stats.getMin(), 0.0);
    assertEquals(4.0, stats.getMax(), 0.0);
    assertEquals(2.5, stats.getMean(), 1e-15);
    assertEquals(sampleStandardDeviation(points), stats.getStandardDeviation(), 1e-15);
  }

  @Test
  void add_whenArrayProvided_expectAllPointsAdded() {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();
    double[] points = {-1.0, 7.0, 3.0};

    stats.add(points);

    assertEquals(3, stats.size());
    assertEquals(-1.0, stats.getMin(), 0.0);
    assertEquals(7.0, stats.getMax(), 0.0);
    assertEquals(3.0, stats.getMean(), 1e-15);
    assertEquals(sampleStandardDeviation(points), stats.getStandardDeviation(), 1e-15);
  }

  @Test
  void add_whenOtherSampleEmpty_expectNoChange() {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();
    stats.add(new double[] {2.0, 4.0});
    ScalarSampleStatistics empty = new ScalarSampleStatistics();

    stats.add(empty);

    assertEquals(2, stats.size());
    assertEquals(2.0, stats.getMin(), 0.0);
    assertEquals(4.0, stats.getMax(), 0.0);
    assertEquals(3.0, stats.getMean(), 1e-15);
  }

  @Test
  void add_whenThisSampleEmpty_expectCopyOfOther() {
    ScalarSampleStatistics target = new ScalarSampleStatistics();
    ScalarSampleStatistics source = new ScalarSampleStatistics();
    double[] points = {10.0, 12.0, 14.0};
    source.add(points);

    target.add(source);

    assertEquals(3, target.size());
    assertEquals(10.0, target.getMin(), 0.0);
    assertEquals(14.0, target.getMax(), 0.0);
    assertEquals(source.getMean(), target.getMean(), 1e-15);
    assertEquals(source.getStandardDeviation(), target.getStandardDeviation(), 1e-15);
  }

  @Test
  void add_whenBothSamplesNonEmpty_expectMergedStatistics() {
    ScalarSampleStatistics a = new ScalarSampleStatistics();
    ScalarSampleStatistics b = new ScalarSampleStatistics();
    a.add(new double[] {1.0, 2.0});
    b.add(new double[] {5.0, 6.0});

    a.add(b);

    double[] merged = {1.0, 2.0, 5.0, 6.0};
    assertEquals(4, a.size());
    assertEquals(1.0, a.getMin(), 0.0);
    assertEquals(6.0, a.getMax(), 0.0);
    assertEquals(3.5, a.getMean(), 1e-15);
    assertEquals(sampleStandardDeviation(merged), a.getStandardDeviation(), 1e-15);
  }

  @Test
  void add_whenOtherSampleHasSmallerMin_expectMinUpdatedOnly() {
    ScalarSampleStatistics a = new ScalarSampleStatistics();
    ScalarSampleStatistics b = new ScalarSampleStatistics();
    a.add(new double[] {5.0, 6.0});
    b.add(new double[] {1.0, 2.0});

    a.add(b);

    double[] merged = {5.0, 6.0, 1.0, 2.0};
    assertEquals(4, a.size());
    assertEquals(1.0, a.getMin(), 0.0);
    assertEquals(6.0, a.getMax(), 0.0);
    assertEquals(3.5, a.getMean(), 1e-15);
    assertEquals(sampleStandardDeviation(merged), a.getStandardDeviation(), 1e-15);
  }

  @ParameterizedTest
  @MethodSource("smallSamples")
  void getStandardDeviation_whenLessThanTwoPoints_expectZero(double[] points) {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();

    stats.add(points);

    assertEquals(0.0, stats.getStandardDeviation(), 0.0);
  }

  static Stream<Arguments> smallSamples() {
    return Stream.of(
        Arguments.of((Object) new double[] {}), Arguments.of((Object) new double[] {42.0}));
  }

  @Test
  void add_whenNaNIncluded_expectNaNPropagatesToAggregates() {
    ScalarSampleStatistics stats = new ScalarSampleStatistics();

    stats.add(1.0);
    stats.add(Double.NaN);
    stats.add(2.0);

    assertEquals(3, stats.size());
    assertEquals(1.0, stats.getMin(), 0.0);
    assertEquals(2.0, stats.getMax(), 0.0);
    assertTrue(Double.isNaN(stats.getMean()));
    assertTrue(Double.isNaN(stats.getStandardDeviation()));
  }

  private static double sampleStandardDeviation(double[] points) {
    if (points.length < 2) {
      return 0.0;
    }
    double mean = 0.0;
    for (double point : points) {
      mean += point;
    }
    mean /= points.length;

    double sumSq = 0.0;
    for (double point : points) {
      double d = point - mean;
      sumSq += d * d;
    }
    return Math.sqrt(sumSq / (points.length - 1));
  }
}
