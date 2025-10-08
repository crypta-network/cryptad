package network.crypta.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.ArrayList;
import java.util.List;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

public class PersistentConfigTest {

  @Test
  public void configDoesNotLogAnErrorWhenIgnoredOptionIsRead() {
    List<String> messages = interceptLogger(config::finishedInit);
    assertThat(messages, empty());
  }

  @Test
  public void configDoesNotContainIgnoredOptionWhenExported() {
    assertThat(config.exportFieldSet().isEmpty(), equalTo(true));
  }

  private List<String> interceptLogger(Runnable runnable) {
    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger logger = ctx.getLogger(PersistentConfig.class);
    Level prev = logger.getLevel();
    logger.setLevel(Level.TRACE); // capture all
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    try {
      runnable.run();
    } finally {
      logger.detachAppender(appender);
      appender.stop();
      logger.setLevel(prev);
    }
    List<String> messages = new ArrayList<>();
    for (ILoggingEvent e : appender.list) {
      messages.add(e.getFormattedMessage());
    }
    return messages;
  }

  private final SimpleFieldSet fieldSetWithIgnoredOption = new SimpleFieldSet(true);

  {
    fieldSetWithIgnoredOption.put("sub.ignored", true);
  }

  private final PersistentConfig config = new PersistentConfig(fieldSetWithIgnoredOption);
  private final SubConfig subConfig = config.createSubConfig("sub");

  {
    subConfig.registerIgnoredOption("ignored");
    subConfig.finishedInitialization();
  }
}
