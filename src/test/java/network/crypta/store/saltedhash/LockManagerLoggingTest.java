package network.crypta.store.saltedhash;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import java.util.concurrent.locks.Condition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * Smoke test to verify PR2 SLF4J refactor emits expected log messages for LockManager.
 *
 * <p>Note: This test is temporary and not intended to be committed permanently.
 */
public class LockManagerLoggingTest {
  private ch.qos.logback.classic.Logger logger;
  private Level originalLevel;
  private boolean originalAdditivity;
  private ListAppender<ILoggingEvent> appender;

  @BeforeEach
  void setupLogger() {
    logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(LockManager.class);
    originalLevel = logger.getLevel();
    originalAdditivity = logger.isAdditive();

    appender = new ListAppender<>();
    appender.start();

    logger.setLevel(Level.DEBUG);
    logger.setAdditive(false); // capture only this logger
    logger.addAppender(appender);
  }

  @AfterEach
  void teardownLogger() {
    if (logger != null && appender != null) {
      logger.detachAppender(appender);
      logger.setLevel(originalLevel);
      logger.setAdditive(originalAdditivity);
    }
  }

  @Test
  void logsDebugMessagesOnLockAndUnlock() {
    LockManager manager = new LockManager();

    Condition cond = manager.lockEntry(42L);
    assertNotNull(cond);
    manager.unlockEntry(42L, cond);

    List<ILoggingEvent> events = appender.list;
    // Expect messages like: "try locking 42", "locked 42", "unlocking 42"
    StringBuilder all = new StringBuilder();
    for (ILoggingEvent e : events) {
      all.append(e.getFormattedMessage()).append('\n');
    }

    String logs = all.toString();
    assertTrue(logs.contains("try locking 42"), () -> "missing 'try locking 42' in\n" + logs);
    assertTrue(logs.contains("locked 42"), () -> "missing 'locked 42' in\n" + logs);
    assertTrue(logs.contains("unlocking 42"), () -> "missing 'unlocking 42' in\n" + logs);
  }
}
