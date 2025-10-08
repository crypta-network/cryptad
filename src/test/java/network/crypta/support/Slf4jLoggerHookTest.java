package network.crypta.support;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Simple sanity tests for the SLF4J hook level mapping. */
public class Slf4jLoggerHookTest {

  private ch.qos.logback.classic.Logger root;
  private ListAppender<ILoggingEvent> listAppender;

  @BeforeEach
  public void setup() throws Exception {
    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    listAppender = new ListAppender<>();
    listAppender.start();
    root.addAppender(listAppender);

    // Initialize SLF4J root to DEBUG for this test
    Logging.bootstrap(org.slf4j.event.Level.DEBUG, null);
  }

  @AfterEach
  public void teardown() {
    if (root != null && listAppender != null) {
      root.detachAppender(listAppender);
      listAppender.stop();
    }
  }

  @Test
  public void normalMapsToInfo() {
    Logger log = LoggerFactory.getLogger(Slf4jLoggerHookTest.class);
    log.info("normal-info-test");
    List<ILoggingEvent> events = listAppender.list;
    ILoggingEvent last = events.get(events.size() - 1);
    assertThat(last.getLevel(), equalTo(Level.INFO));
    assertThat(last.getFormattedMessage(), equalTo("normal-info-test"));
  }

  @Test
  public void minorMapsToDebug() {
    Logger log = LoggerFactory.getLogger(Slf4jLoggerHookTest.class);
    log.debug("minor-debug-test");
    List<ILoggingEvent> events = listAppender.list;
    ILoggingEvent last = events.get(events.size() - 1);
    assertThat(last.getLevel(), equalTo(Level.DEBUG));
    assertThat(last.getFormattedMessage(), equalTo("minor-debug-test"));
  }
}
