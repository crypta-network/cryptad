package network.crypta.client.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import network.crypta.client.async.ClientContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming uses method_whenCondition_expectOutcome
class EventLoggerTest {

  private Logger logger;
  private ch.qos.logback.classic.Level previousLevel;
  private ListAppender<ILoggingEvent> appender;

  @Mock private ClientEvent event;
  @Mock private ClientContext context;

  @BeforeEach
  void setUp() {
    logger = (Logger) LoggerFactory.getLogger(EventLogger.class);
    previousLevel = logger.getLevel();
    appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
  }

  @AfterEach
  void tearDown() {
    if (logger != null) {
      logger.detachAppender(appender);
      logger.setLevel(previousLevel);
    }
    if (appender != null) {
      appender.stop();
    }
  }

  @Test
  @DisplayName("receive_whenLevelError_logsAtError")
  void receive_whenLevelError_logsAtError() {
    logger.setLevel(ch.qos.logback.classic.Level.INFO); // ensure ERROR is enabled
    EventLogger el = new EventLogger(Level.ERROR, false);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.ERROR, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
  }

  @Test
  @DisplayName("receive_whenLevelWarn_logsAtWarn")
  void receive_whenLevelWarn_logsAtWarn() {
    logger.setLevel(ch.qos.logback.classic.Level.WARN);
    EventLogger el = new EventLogger(Level.WARN, true);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.WARN, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
  }

  @Test
  @DisplayName("receive_whenLevelInfo_logsAtInfo")
  void receive_whenLevelInfo_logsAtInfo() {
    logger.setLevel(ch.qos.logback.classic.Level.INFO);
    EventLogger el = new EventLogger(Level.INFO, false);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.INFO, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
  }

  @Test
  @DisplayName("receive_whenLevelDebugAndEnabled_logsAtDebug")
  void receive_whenLevelDebugAndEnabled_logsAtDebug() {
    logger.setLevel(ch.qos.logback.classic.Level.DEBUG); // enable DEBUG
    EventLogger el = new EventLogger(Level.DEBUG, true);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.DEBUG, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
    verify(event, atLeastOnce()).getDescription();
  }

  @Test
  @DisplayName("receive_whenLevelDebugAndDisabled_doesNotLogOrCallGetDescription")
  void receive_whenLevelDebugAndDisabled_doesNotLogOrCallGetDescription() {
    logger.setLevel(ch.qos.logback.classic.Level.INFO); // disable DEBUG
    // Override to detect accidental description access
    reset(event);
    EventLogger el = new EventLogger(Level.DEBUG, false);

    el.receive(event, context);

    assertTrue(appender.list.isEmpty());
    verify(event, never()).getDescription();
  }

  @Test
  @DisplayName("receive_whenLevelTraceAndTraceEnabled_logsAtTrace")
  void receive_whenLevelTraceAndTraceEnabled_logsAtTrace() {
    logger.setLevel(ch.qos.logback.classic.Level.TRACE);
    EventLogger el = new EventLogger(Level.TRACE, false);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.TRACE, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
  }

  @Test
  @DisplayName("receive_whenLevelTraceAndOnlyDebugEnabled_logsAtDebug")
  void receive_whenLevelTraceAndOnlyDebugEnabled_logsAtDebug() {
    logger.setLevel(ch.qos.logback.classic.Level.DEBUG); // TRACE disabled, DEBUG enabled
    EventLogger el = new EventLogger(Level.TRACE, true);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.DEBUG, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
  }

  @Test
  @DisplayName("receive_whenLevelTraceAndNeitherTraceNorDebug_logsAtInfo")
  void receive_whenLevelTraceAndNeitherTraceNorDebug_logsAtInfo() {
    logger.setLevel(ch.qos.logback.classic.Level.INFO); // neither TRACE nor DEBUG enabled
    EventLogger el = new EventLogger(Level.TRACE, false);
    when(event.getDescription()).thenReturn("desc");

    el.receive(event, context);

    List<ILoggingEvent> events = appender.list;
    assertEquals(1, events.size());
    assertEquals(ch.qos.logback.classic.Level.INFO, events.getFirst().getLevel());
    assertEquals("desc", events.getFirst().getFormattedMessage());
  }

  @Test
  @DisplayName("constructor_whenNullLevel_defaultsToInfoAndStoresRemoveWithProducer")
  void constructor_whenNullLevel_defaultsToInfoAndStoresRemoveWithProducer() {
    EventLogger el = new EventLogger(null, true);
    // Access package-private fields from same package
    assertEquals(Level.INFO, el.slf4jLevel);
    assertTrue(el.removeWithProducer);
  }
}
