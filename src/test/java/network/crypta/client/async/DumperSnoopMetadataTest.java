package network.crypta.client.async;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import network.crypta.client.Metadata;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DumperSnoopMetadataTest {

  private Logger getLogger() {
    return (Logger) LoggerFactory.getLogger(DumperSnoopMetadata.class);
  }

  private ListAppender<ILoggingEvent> attachListAppender(Logger logger) {
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  @Test
  void snoopMetadata_whenCalled_logsDumpAtErrorAndReturnsFalse() {
    // Arrange
    DumperSnoopMetadata dumper = new DumperSnoopMetadata();
    Metadata meta = mock(Metadata.class);
    when(meta.dump()).thenReturn("TEST-DUMP-LINES\nline2\n");
    ClientContext ctx = mock(ClientContext.class);

    Logger logger = getLogger();
    ListAppender<ILoggingEvent> appender = attachListAppender(logger);
    try {
      // Act
      boolean cancel = dumper.snoopMetadata(meta, ctx);

      // Assert
      assertFalse(cancel, "DumperSnoopMetadata should never request cancellation");
      List<ILoggingEvent> events = appender.list;
      assertEquals(1, events.size());
      assertEquals(Level.ERROR, events.getFirst().getLevel());
      assertEquals("TEST-DUMP-LINES\nline2\n", events.getFirst().getFormattedMessage());
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  @Test
  void snoopMetadata_whenMetaDumpEmpty_logsEmptyMessageAndReturnsFalse() {
    // Arrange
    DumperSnoopMetadata dumper = new DumperSnoopMetadata();
    Metadata meta = mock(Metadata.class);
    when(meta.dump()).thenReturn("");

    Logger logger = getLogger();
    ListAppender<ILoggingEvent> appender = attachListAppender(logger);
    try {
      // Act
      boolean cancel = dumper.snoopMetadata(meta, mock(ClientContext.class));

      // Assert
      assertFalse(cancel);
      List<ILoggingEvent> events = appender.list;
      assertEquals(1, events.size());
      assertEquals("", events.getFirst().getFormattedMessage());
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  @Test
  void snoopMetadata_whenMetaIsNull_throwsNullPointerException() {
    // Arrange
    DumperSnoopMetadata dumper = new DumperSnoopMetadata();

    // Act + Assert
    //noinspection DataFlowIssue
    assertThrows(
        NullPointerException.class, () -> dumper.snoopMetadata(null, mock(ClientContext.class)));
  }

  @Test
  void snoopMetadata_whenContextIsNull_logsDumpAndReturnsFalse() {
    // Arrange
    DumperSnoopMetadata dumper = new DumperSnoopMetadata();
    Metadata meta = mock(Metadata.class);
    when(meta.dump()).thenReturn("ABC");

    Logger logger = getLogger();
    ListAppender<ILoggingEvent> appender = attachListAppender(logger);
    try {
      // Act
      boolean cancel = dumper.snoopMetadata(meta, null);

      // Assert
      assertFalse(cancel);
      List<ILoggingEvent> events = appender.list;
      assertEquals(1, events.size());
      assertEquals("ABC", events.getFirst().getFormattedMessage());
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  @Test
  void snoopMetadata_whenDumpReturnsNull_logsLiteralNullAndReturnsFalse() {
    // Arrange
    DumperSnoopMetadata dumper = new DumperSnoopMetadata();
    Metadata meta = mock(Metadata.class);
    when(meta.dump()).thenReturn(null);

    Logger logger = getLogger();
    ListAppender<ILoggingEvent> appender = attachListAppender(logger);
    try {
      // Act
      boolean cancel = dumper.snoopMetadata(meta, mock(ClientContext.class));

      // Assert
      assertFalse(cancel);
      List<ILoggingEvent> events = appender.list;
      assertEquals(1, events.size());
      assertEquals("null", events.getFirst().getFormattedMessage());
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }
}
