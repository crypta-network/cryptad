package network.crypta.support.io;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IOUtils}.
 *
 * <p>Tests follow AAA style with deterministic behavior and verify both normal and exceptional
 * paths. Logging is captured via Logback's {@link ListAppender} to assert error reporting without
 * relying on global configuration.
 */
class IOUtilsTest {

  private Logger logger;
  private ListAppender<ILoggingEvent> listAppender;

  @BeforeEach
  void setUpLogger() {
    logger = (Logger) LoggerFactory.getLogger(IOUtils.class);
    listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
  }

  @AfterEach
  void tearDownLogger() {
    if (logger != null && listAppender != null) {
      logger.detachAppender(listAppender);
      listAppender.stop();
    }
  }

  // ----------------------- AutoCloseable.closeQuietly -----------------------

  @Test
  void closeQuietlyAutoCloseable_whenNull_doesNothingNoLog() {
    // Arrange
    AutoCloseable resource = null;

    // Act
    //noinspection ConstantValue
    IOUtils.closeQuietly(resource);

    // Assert
    assertNoErrorLogs();
  }

  @Test
  void closeQuietlyAutoCloseable_whenClosesNormally_callsCloseNoErrorLog() throws Exception {
    // Arrange
    AutoCloseable resource = mock(AutoCloseable.class);

    // Act
    IOUtils.closeQuietly(resource);

    // Assert
    verify(resource).close();
    assertNoErrorLogs();
  }

  static Stream<Exception> autoCloseableExceptions() {
    return Stream.of(new IOException("boom-check"), new IllegalStateException("boom-runtime"));
  }

  @ParameterizedTest
  @MethodSource("autoCloseableExceptions")
  void closeQuietlyAutoCloseable_whenThrowsException_logsErrorAndContinues(Exception thrown)
      throws Exception {
    // Arrange
    AutoCloseable resource = mock(AutoCloseable.class);
    doThrow(thrown).when(resource).close();

    // Act
    IOUtils.closeQuietly(resource);

    // Assert
    verify(resource).close();
    List<ILoggingEvent> errors = getErrorLogs();
    assertEquals(1, errors.size(), "one error log expected");
    ILoggingEvent evt = errors.getFirst();
    assertTrue(
        evt.getFormattedMessage().startsWith("Error during close() on "),
        "message should start with prefix");
    IThrowableProxy proxy = evt.getThrowableProxy();
    assertNotNull(proxy, "throwable proxy should be present");
    assertEquals(thrown.getClass().getName(), proxy.getClassName());
    if (proxy instanceof ThrowableProxy throwableProxy) {
      assertEquals(thrown.getMessage(), throwableProxy.getThrowable().getMessage());
    }
  }

  @Test
  void closeQuietlyAutoCloseable_whenThrowsError_propagatesAndNoLog() {
    // Arrange + Act within try-with-resources to satisfy static analysis (S2093):
    // the close() throws only on the first invocation triggered by IOUtils; the implicit
    // close at the end of TWR is a no-op.
    try (ThrowingOnceCloseable resource = new ThrowingOnceCloseable("serious-error")) {
      // Act + Assert
      AssertionError err = assertThrows(AssertionError.class, () -> IOUtils.closeQuietly(resource));
      assertEquals("serious-error", err.getMessage());
      assertNoErrorLogs();
    }
  }

  // ---------------------------- ZipFile.closeQuietly ----------------------------

  @Test
  void closeQuietlyZipFile_whenNull_doesNothingNoLog() {
    // Arrange
    ZipFile zipFile = null;

    // Act
    //noinspection ConstantValue
    IOUtils.closeQuietly(zipFile);

    // Assert
    assertNoErrorLogs();
  }

  @Test
  void closeQuietlyZipFile_whenClosesNormally_callsCloseNoErrorLog() throws Exception {
    // Arrange
    ZipFile zipFile = mock(ZipFile.class);

    // Act
    IOUtils.closeQuietly(zipFile);

    // Assert
    verify(zipFile).close();
    assertNoErrorLogs();
  }

  @Test
  void closeQuietlyZipFile_whenThrowsIOException_logsErrorAndContinues() throws Exception {
    // Arrange
    ZipFile zipFile = mock(ZipFile.class);
    IOException thrown = new IOException("io-failure");
    doThrow(thrown).when(zipFile).close();

    // Act
    IOUtils.closeQuietly(zipFile);

    // Assert
    verify(zipFile).close();
    List<ILoggingEvent> errors = getErrorLogs();
    assertEquals(1, errors.size(), "one error log expected");
    ILoggingEvent evt = errors.getFirst();
    assertEquals("Error during close() on ZipFile", evt.getFormattedMessage());
    IThrowableProxy proxy = evt.getThrowableProxy();
    assertNotNull(proxy, "throwable proxy should be present");
    assertEquals(IOException.class.getName(), proxy.getClassName());
    if (proxy instanceof ThrowableProxy throwableProxy) {
      assertEquals("io-failure", throwableProxy.getThrowable().getMessage());
    }
  }

  @Test
  void closeQuietlyZipFile_whenThrowsRuntimeException_propagatesAndNoLog() throws Exception {
    // Arrange
    ZipFile zipFile = mock(ZipFile.class);
    doThrow(new IllegalStateException("runtime-bang")).when(zipFile).close();

    // Act + Assert
    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> IOUtils.closeQuietly(zipFile));
    assertEquals("runtime-bang", ex.getMessage());
    assertNoErrorLogs();
  }

  // ---------------------------- skipFully ----------------------------

  @Test
  void skipFully_whenStreamAdvancesInChunks_discardsRequestedBytes() throws Exception {
    // Arrange
    InputStream input = mock(InputStream.class);
    when(input.skip(anyLong())).thenReturn(2L, 3L);

    // Act
    IOUtils.skipFully(input, 5);

    // Assert
    verify(input, times(2)).skip(anyLong());
    assertNoErrorLogs();
  }

  @Test
  void skipFully_whenStreamStopsAdvancing_throwsIOException() throws Exception {
    // Arrange
    InputStream input = mock(InputStream.class);
    when(input.skip(anyLong())).thenReturn(2L, 0L);

    // Act
    IOException exception = assertThrows(IOException.class, () -> IOUtils.skipFully(input, 5));

    // Assert
    assertEquals("Unable to skip 3 bytes", exception.getMessage());
    verify(input, times(2)).skip(anyLong());
    assertNoErrorLogs();
  }

  // ---------------------------- Helpers ----------------------------

  private List<ILoggingEvent> getErrorLogs() {
    return listAppender.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
  }

  private void assertNoErrorLogs() {
    List<ILoggingEvent> errors = getErrorLogs();
    assertTrue(errors.isEmpty(), () -> "unexpected error logs: " + errors);
  }

  private static class ThrowingOnceCloseable implements AutoCloseable {
    private final String message;
    private boolean thrown;

    private ThrowingOnceCloseable(String message) {
      this.message = message;
    }

    @Override
    public void close() {
      if (!thrown) {
        thrown = true;
        throw new AssertionError(message);
      }
      // no-op on subsequent closes
    }
  }
}
