package network.crypta.support;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ProcessPriority} focusing on deterministic behavior of the public API.
 *
 * <p>Notes - We do not mock native/JNA calls. On Linux, increasing niceness to 10 is permitted for
 * unprivileged users, so the native path should succeed on typical CI/dev machines. We guard the
 * tests with {@code @EnabledOnOs(OS.LINUX)} to avoid platform variance. - The tests verify
 * idempotency and emitted console messages without coupling to a specific message beyond key
 * substrings ("succeeded", "Skipping", "failed").
 */
class ProcessPriorityTest {

  private Logger logger;
  private ListAppender<ILoggingEvent> appender;

  @BeforeEach
  void setUpStreamsAndResetFlag() throws Exception {
    // Attach a Logback ListAppender to capture ProcessPriority logs deterministically
    logger = (Logger) LoggerFactory.getLogger(ProcessPriority.class);
    appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);

    // Reset internal background state to ensure test isolation
    Field bg = ProcessPriority.class.getDeclaredField("background");
    bg.setAccessible(true);
    bg.set(null, false);
  }

  @AfterEach
  void restoreStreams() {
    if (logger != null && appender != null) {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  @Test
  @EnabledOnOs(OS.LINUX)
  @DisplayName("enterBackgroundMode when first call returns success message and sets flag")
  void enterBackgroundMode_whenFirstCall_expectSuccessAndBackgroundTrue() {
    // Act
    boolean result = ProcessPriority.enterBackgroundMode();

    // Assert
    // On Linux either native setpriority succeeds or the sandbox path is taken; both return true.
    assertTrue(result, "enterBackgroundMode should succeed on Linux by default");
    List<ILoggingEvent> events = appender.list;
    String combined =
        events.stream().map(ILoggingEvent::getFormattedMessage).reduce("", (a, b) -> a + "\n" + b);
    boolean printedSuccess = combined.contains("succeeded");
    boolean printedSkip = combined.contains("Skipping process setpriority");
    boolean printedFailure = combined.contains("failed");
    assertTrue(
        printedSuccess || printedSkip,
        "Expected success or sandbox skip message in logs, got: " + combined);
    assertFalse(printedFailure, "Did not expect a failure log message: " + combined);
  }

  @Test
  @EnabledOnOs(OS.LINUX)
  @DisplayName("enterBackgroundMode called twice is idempotent and silent on second call")
  void enterBackgroundMode_whenCalledTwice_expectIdempotentAndNoAdditionalOutput() {
    // Arrange
    boolean first = ProcessPriority.enterBackgroundMode();
    int firstEventCount = appender.list.size();
    // Clear captured events before second call to track only new output
    appender.list.clear();

    // Act
    boolean second = ProcessPriority.enterBackgroundMode();

    // Assert: return value is stable and no new output is produced
    assertEquals(first, second, "Second call should return the same state");
    assertEquals(0, appender.list.size(), "Second call should not log additional messages");

    // Sanity: ensure first invocation produced at least some message (success or skip)
    boolean hadFirstMessage = firstEventCount > 0;
    assertTrue(hadFirstMessage, "Expected first call to produce a log message");
  }
}
