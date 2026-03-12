package network.crypta.client;

import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ArchiveContextTest {

  @Test
  @DisplayName("doLoopDetection: accepts up to max+1 unique keys, then throws TOO_MANY_LEVELS")
  void doLoopDetection_whenWithinLimit_acceptsUpToMaxPlusOneUnique_thenTooManyOnNext() {
    // Arrange
    int maxLevels = 2;
    ArchiveContext ctx = new ArchiveContext(1_000_000L, maxLevels);
    FreenetURI k1 = new FreenetURI("KSK", "a");
    FreenetURI k2 = new FreenetURI("KSK", "b");
    FreenetURI k3 = new FreenetURI("KSK", "c");
    FreenetURI k4 = new FreenetURI("KSK", "d");

    // Act + Assert (no exception for first max+1 unique keys)
    assertDoesNotThrow(() -> ctx.doLoopDetection(k1));
    assertDoesNotThrow(() -> ctx.doLoopDetection(k2));
    assertDoesNotThrow(() -> ctx.doLoopDetection(k3));

    // Next unique should exceed the limit and throw
    ArchiveFailureException ex =
        assertThrows(ArchiveFailureException.class, () -> ctx.doLoopDetection(k4));
    assertEquals(
        ArchiveFailureException.TOO_MANY_LEVELS,
        ex.getMessage(),
        "Expected TOO_MANY_LEVELS message");
  }

  @Test
  @DisplayName("doLoopDetection: same key twice throws ARCHIVE_LOOP_DETECTED")
  void doLoopDetection_whenSameKeyRepeated_expectArchiveLoopDetected() throws Exception {
    // Arrange
    ArchiveContext ctx = new ArchiveContext(1_000_000L, 10);
    FreenetURI key1 = new FreenetURI("KSK", "dup");
    FreenetURI key1Again = new FreenetURI("KSK", "dup"); // equal to key1

    // Act
    ctx.doLoopDetection(key1);

    // Assert
    ArchiveFailureException ex =
        assertThrows(ArchiveFailureException.class, () -> ctx.doLoopDetection(key1Again));
    assertEquals(
        ArchiveFailureException.ARCHIVE_LOOP_DETECTED,
        ex.getMessage(),
        "Expected ARCHIVE_LOOP_DETECTED message");
  }

  @Test
  @DisplayName("doLoopDetection: null twice is treated as a loop")
  void doLoopDetection_whenNullTwice_expectArchiveLoopDetected() throws Exception {
    // Arrange
    ArchiveContext ctx = new ArchiveContext(1_000_000L, 10);

    // Act
    ctx.doLoopDetection(null);

    // Assert
    ArchiveFailureException ex =
        assertThrows(ArchiveFailureException.class, () -> ctx.doLoopDetection(null));
    assertEquals(
        ArchiveFailureException.ARCHIVE_LOOP_DETECTED,
        ex.getMessage(),
        "Expected ARCHIVE_LOOP_DETECTED message for null re-use");
  }

  @Test
  @DisplayName("clear: resets seen set so re-adding previous key is allowed")
  void clear_whenCalled_resetsStateAllowingReadd() throws Exception {
    // Arrange
    ArchiveContext ctx = new ArchiveContext(1_000_000L, 10);
    FreenetURI key = new FreenetURI("KSK", "x");

    // Act
    ctx.doLoopDetection(key);
    ctx.clear();

    // Assert: after clear the same key should be accepted again once
    assertDoesNotThrow(() -> ctx.doLoopDetection(key));
    // And a consecutive duplicate should now be detected again
    ArchiveFailureException ex =
        assertThrows(ArchiveFailureException.class, () -> ctx.doLoopDetection(key));
    assertEquals(
        ArchiveFailureException.ARCHIVE_LOOP_DETECTED,
        ex.getMessage(),
        "Expected ARCHIVE_LOOP_DETECTED after re-adding same key post-clear");
  }

  @Test
  @DisplayName(
      "default ctor: zero max levels allows one unique, then throws TOO_MANY_LEVELS before add")
  void defaultConstructor_withZeroMaxLevels_allowsOneUniqueThenTooMany() {
    // Arrange: use package-visible protected constructor
    ArchiveContext ctx = new ArchiveContext();
    FreenetURI k1 = new FreenetURI("KSK", "one");
    FreenetURI k2 = new FreenetURI("KSK", "two");

    // Act + Assert
    assertDoesNotThrow(() -> ctx.doLoopDetection(k1));
    ArchiveFailureException ex =
        assertThrows(ArchiveFailureException.class, () -> ctx.doLoopDetection(k2));
    assertEquals(
        ArchiveFailureException.TOO_MANY_LEVELS,
        ex.getMessage(),
        "Expected TOO_MANY_LEVELS with default (0) max levels");
  }
}
