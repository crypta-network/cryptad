package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class RateCalculatorTest {

  private static final double EPSILON = 1e-6;

  @Test
  void isPaused_whenNew_returnsFalse() {
    // Arrange
    RateCalculator calculator = new RateCalculator();

    // Act & Assert
    assertFalse(calculator.isPaused());
  }

  @Test
  void pause_whenAlreadyPaused_throwsIllegalStateException() {
    // Arrange
    RateCalculator calculator = new RateCalculator();
    calculator.pause(1_000L);

    // Act & Assert
    assertThrows(IllegalStateException.class, () -> calculator.pause(1_500L));
  }

  @Test
  void resume_whenNotPaused_throwsIllegalStateException() {
    // Arrange
    RateCalculator calculator = new RateCalculator();

    // Act & Assert
    assertThrows(IllegalStateException.class, () -> calculator.resume(1_000L));
  }

  @Test
  void getRate_whenWithinFirstInterval_usesCurrentIntervalAverage() {
    // Arrange
    RateCalculator calculator = new RateCalculator(100, 2, 0.5f);
    calculator.update(10, 0L);

    // Act
    double rate = calculator.getRate(50L);

    // Assert
    assertEquals(10d / 51d, rate, EPSILON);
  }

  @Test
  void getRate_whenMultipleIntervals_appliesWeightedAverage() {
    // Arrange
    RateCalculator calculator = new RateCalculator(100, 2, 0.5f);
    calculator.update(50, 0L);
    calculator.update(0, 100L); // closes first interval with rate 0.5
    calculator.update(100, 150L); // second interval in progress

    // Act
    double rate = calculator.getRate(200L); // closes second interval with rate 1.0

    // Assert
    // Weighted average: (1.0 * 1) + (0.5 * 0.5) = 1.25; weight total = 1.5 => 0.8333...
    assertEquals(0.8333333333d, rate, EPSILON);
  }

  @Test
  void getEstimatedEventCount_whenUsingRecentRate_returnsProjectedCount() {
    // Arrange
    RateCalculator calculator = new RateCalculator(100, 2, 0.5f);
    calculator.update(50, 0L);
    calculator.update(0, 100L); // first interval recorded
    calculator.update(100, 150L);
    calculator.getRate(200L); // finalize second interval and compute rate baseline

    // Act
    double estimatedCount = calculator.getEstimatedEventCount(250L);

    // Assert
    assertEquals(233.3333333d, estimatedCount, EPSILON);
  }

  @Test
  void getEstimatedTimeRemaining_whenRatePositive_returnsPositiveDuration() {
    // Arrange
    RateCalculator calculator = new RateCalculator(100, 2, 0.5f);
    calculator.update(50, 0L);
    calculator.update(0, 100L); // first interval recorded
    calculator.update(100, 150L);
    calculator.getRate(200L); // finalize second interval

    // Act
    long remaining = calculator.getEstimatedTimeRemaining(300, 250L);

    // Assert
    assertEquals(79L, remaining);
  }

  @Test
  void pauseAndResume_whenResumesAdjustsIntervalTiming_maintainsRateAfterPause() {
    // Arrange
    RateCalculator calculator = new RateCalculator(100, 2, 0.5f);
    calculator.update(50, 0L);
    calculator.pause(50L);

    // Act
    assertTrue(calculator.isPaused());
    calculator.resume(150L); // shift interval timelines by pause duration
    double rate = calculator.getRate(200L);

    // Assert
    assertFalse(calculator.isPaused());
    assertEquals(0.5d, rate, EPSILON);
  }
}
