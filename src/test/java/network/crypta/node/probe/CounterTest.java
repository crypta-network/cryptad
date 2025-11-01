package network.crypta.node.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Test naming uses method_whenCondition_expectOutcome
class CounterTest {

  @Test
  @DisplayName("value_whenNew_expectZeroAndMaxAccessible")
  void value_whenNew_expectZeroAndMaxAccessible() {
    // Arrange
    Counter counter = new Counter(3);

    // Act & Assert
    assertEquals(0, counter.value(), "New counter should start at zero");
    assertEquals(3, counter.maxAccepted, "maxAccepted should reflect constructor argument");
  }

  @Test
  @DisplayName("increment_whenBelowMax_expectValueIncrements")
  void increment_whenBelowMax_expectValueIncrements() {
    // Arrange
    Counter counter = new Counter(2);

    // Act
    counter.increment();
    counter.increment();

    // Assert
    assertEquals(2, counter.value());
  }

  @Test
  @DisplayName("increment_whenExceedsMax_expectIllegalStateException")
  void increment_whenExceedsMax_expectIllegalStateException() {
    // Arrange
    Counter counter = new Counter(1);
    counter.increment(); // reaches max

    // Act + Assert
    IllegalStateException ex = assertThrows(IllegalStateException.class, counter::increment);
    // The message includes the illegal value after increment (max + 1)
    assertEquals("Number of accepted probes exceeds the maximum: 2", ex.getMessage());
  }

  @Test
  @DisplayName("decrement_whenFromZero_expectIllegalStateException")
  void decrement_whenFromZero_expectIllegalStateException() {
    // Arrange
    Counter counter = new Counter(1);

    // Act + Assert
    IllegalStateException ex = assertThrows(IllegalStateException.class, counter::decrement);
    assertEquals("Number of accepted probes is negative: -1", ex.getMessage());
  }

  @Test
  @DisplayName("decrement_whenAfterIncrement_expectBackToZero")
  void decrement_whenAfterIncrement_expectBackToZero() {
    // Arrange
    Counter counter = new Counter(3);
    counter.increment();

    // Act
    counter.decrement();

    // Assert
    assertEquals(0, counter.value());
  }

  @Test
  @DisplayName("sequence_incrementToMax_decrementOnce_thenIncrementAgain_expectAllowed")
  void sequence_incrementToMax_decrementOnce_thenIncrementAgain_expectAllowed() {
    // Arrange
    Counter counter = new Counter(2);
    counter.increment();
    counter.increment(); // now at max

    // Act
    counter.decrement(); // back to 1
    counter.increment(); // allowed again to reach max

    // Assert
    assertEquals(2, counter.value());
  }

  @Test
  @DisplayName("constructor_withNegativeMax_expectOperationsFailDeterministically")
  void constructor_withNegativeMax_expectOperationsFailDeterministically() {
    // Arrange
    Counter counter = new Counter(-1);

    // Act + Assert (increment fails because 1 > -1)
    IllegalStateException incEx = assertThrows(IllegalStateException.class, counter::increment);
    assertEquals("Number of accepted probes exceeds the maximum: 1", incEx.getMessage());

    // A decrement from zero also fails and goes negative
    Counter fresh = new Counter(-1);
    IllegalStateException decEx = assertThrows(IllegalStateException.class, fresh::decrement);
    assertEquals("Number of accepted probes is negative: -1", decEx.getMessage());
  }
}
