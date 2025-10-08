package network.crypta.node;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Tests for respecting logger.enabled=false at startup. */
public class LoggingConfigHandlerTest {

  private Level prevRootLevel;

  @BeforeEach
  public void captureRootLevel() {
    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger root = ctx.getLogger(Logger.ROOT_LOGGER_NAME);
    prevRootLevel = root.getLevel();
  }

  @AfterEach
  public void restoreRootLevel() {
    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger root = ctx.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(prevRootLevel);
  }

  @Test
  public void disabledAtStartup_setsRootOff_andSuppressesEvents() throws Exception {
    // Prepare a config with logger.enabled=false
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.put("logger.enabled", false);
    PersistentConfig cfg = new PersistentConfig(sfs);
    SubConfig logging = cfg.createSubConfig("logger");

    // Construct handler (should respect the flag immediately)
    new LoggingConfigHandler(logging);

    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger root = ctx.getLogger(Logger.ROOT_LOGGER_NAME);
    assertEquals(Level.OFF, root.getLevel(), "root level must be OFF when logging is disabled");

    // Attach a list appender to root to verify no events are emitted
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    root.addAppender(appender);
    try {
      Logger log = LoggerFactory.getLogger(LoggingConfigHandlerTest.class);
      log.error("this should not be logged");
    } finally {
      root.detachAppender(appender);
      appender.stop();
    }
    assertThat("no events should be captured when root is OFF", appender.list, empty());
  }
}
