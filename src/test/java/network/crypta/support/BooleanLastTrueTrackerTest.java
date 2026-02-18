package network.crypta.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link BooleanLastTrueTracker}.
 *
 * <p>Focus: state transitions, returned values, and time reporting semantics.
 */
class BooleanLastTrueTrackerTest {

  @Test
  @DisplayName("defaultState_whenConstructed_expectFalseAndMinusOne")
  void defaultState_whenConstructed_expectFalseAndMinusOne() {
    // Arrange
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker();

    // Act
    boolean isTrue = tracker.isTrue();
    long time = tracker.getTimeLastTrue(1000L);

    // Assert
    assertFalse(isTrue, "New tracker should start false");
    assertEquals(-1L, time, "Time should be -1 when never true");
  }

  @Test
  @DisplayName("constructor_withInitialLastTrue_expectTimeReturnedWhileFalse")
  void constructor_withInitialLastTrue_expectTimeReturnedWhileFalse() {
    // Arrange
    long initial = 42L;
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker(initial);

    // Act
    boolean isTrue = tracker.isTrue();
    long time = tracker.getTimeLastTrue(999L);

    // Assert
    assertFalse(isTrue, "Tracker constructed with lastTrue remains false initially");
    assertEquals(initial, time, "Should return provided lastTrue while state is false");
  }

  @Test
  @DisplayName("set_whenFalseToTrue_updatesTimeAndReturnsPreviousFalse")
  void set_whenFalseToTrue_updatesTimeAndReturnsPreviousFalse() {
    // Arrange
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker();
    long tTrue = 100L;

    // Act
    boolean returnedPrev = tracker.set(true, tTrue);

    // Assert
    assertFalse(returnedPrev, "set(true) should return previous state (false)");
    assertTrue(tracker.isTrue(), "State should be true after transition");

    // While true, getTimeLastTrue(now) must return the provided 'now'.
    long nowWhileTrue = 200L;
    assertEquals(
        nowWhileTrue,
        tracker.getTimeLastTrue(nowWhileTrue),
        "When currently true, getTimeLastTrue(now) must echo 'now'");

    // Transition to false should not change the stored last-true time (which is tTrue).
    boolean prevOnFalse = tracker.set(false, 300L);
    assertTrue(prevOnFalse, "set(false) should return previous state (true)");
    assertFalse(tracker.isTrue(), "State should be false after transition");
    assertEquals(
        tTrue,
        tracker.getTimeLastTrue(400L),
        "When false, last-true time should be the time of the most recent false->true transition");
  }

  @Test
  @DisplayName("set_whenTrueToFalse_keepsLastTrueTime")
  void set_whenTrueToFalse_keepsLastTrueTime() {
    // Arrange
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker();
    long t1 = 123L;
    tracker.set(true, t1); // becomes true at t1

    // Act
    boolean returnedPrev = tracker.set(false, 200L); // back to false

    // Assert
    assertTrue(returnedPrev, "set(false) should return previous state (true)");
    assertFalse(tracker.isTrue(), "State should be false after transition");
    assertEquals(
        t1,
        tracker.getTimeLastTrue(999L),
        "While false, last-true time should remain the time we became true (t1)");
  }

  @Test
  @DisplayName("set_whenSettingSameValue_returnsSameValueAndNoTimeChange_falseCase")
  void set_whenSettingSameValue_returnsSameValueAndNoTimeChange_falseCase() {
    // Arrange
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker();

    // Act
    boolean returnedPrev = tracker.set(false, 50L); // no state change

    // Assert
    assertFalse(returnedPrev, "Unchanged set(false) should return false (previous state)");
    assertFalse(tracker.isTrue(), "State remains false");
    assertEquals(-1L, tracker.getTimeLastTrue(999L), "Last-true time remains -1 when never true");
  }

  @Test
  @DisplayName("set_whenSettingSameValueTrue_doesNotUpdateLastTrueTime")
  void set_whenSettingSameValueTrue_doesNotUpdateLastTrueTime() {
    // Arrange: become true at t1
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker();
    long t1 = 100L;
    tracker.set(true, t1);

    // Act: set(true) again with a later time; method should not overwrite the stored last-true
    // moment
    boolean returnedPrev = tracker.set(true, 200L); // unchanged

    // Assert current behavior and then flip to false to read the stored last-true time
    assertTrue(returnedPrev, "Unchanged set(true) should return true (previous state)");
    assertTrue(tracker.isTrue(), "State remains true");

    // Move to false to observe the stored last-true time (should still be t1, not 200)
    tracker.set(false, 300L);
    assertEquals(
        t1,
        tracker.getTimeLastTrue(350L),
        "Unchanged set(true) must not update stored last-true time");
  }

  @Test
  @DisplayName("getTimeLastTrue_whenCurrentlyTrue_returnsProvidedNow")
  void getTimeLastTrue_whenCurrentlyTrue_returnsProvidedNow() {
    // Arrange
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker();
    tracker.set(true, 10L);

    // Act
    long now = 777L;
    long reported = tracker.getTimeLastTrue(now);

    // Assert
    assertEquals(now, reported, "While true, getTimeLastTrue should return the provided 'now'");
  }

  @Test
  @DisplayName("multipleTransitions_onlyFalseToTrueUpdatesStoredTime")
  void multipleTransitions_onlyFalseToTrueUpdatesStoredTime() {
    // Arrange: start with a seed last-true value (pretend last known event)
    BooleanLastTrueTracker tracker = new BooleanLastTrueTracker(5L);

    // Become true at 100
    tracker.set(true, 100L);
    assertEquals(250L, tracker.getTimeLastTrue(250L), "While true, getTimeLastTrue mirrors 'now'");

    // Back to false at 150; stored last-true time should be 100
    tracker.set(false, 150L);
    assertEquals(
        100L,
        tracker.getTimeLastTrue(151L),
        "After true->false, last-true remains when it became true");

    // Repeated false has no effect
    tracker.set(false, 200L);
    assertEquals(
        100L,
        tracker.getTimeLastTrue(201L),
        "Repeated false should not change stored last-true time");

    // Become true again at 250; this should update the stored time
    tracker.set(true, 250L);
    tracker.set(false, 300L);
    assertEquals(
        250L, tracker.getTimeLastTrue(301L), "The most recent false->true time should be recorded");
  }
}
