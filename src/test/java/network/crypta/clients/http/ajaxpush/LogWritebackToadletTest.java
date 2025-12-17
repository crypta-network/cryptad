package network.crypta.clients.http.ajaxpush;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.URLDecoder;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LogWritebackToadletTest {

  private static final String HELLO_ENCODED = "hello%20world";

  @Mock private HighLevelSimpleClient client;

  @Mock private HTTPRequest request;

  @Mock private ToadletContext context;

  @Test
  void path_whenCalled_expectUpdaterConstant() {
    // Arrange
    LogWritebackToadlet toadlet = new LogWritebackToadlet(client);

    // Act
    String path = toadlet.path();

    // Assert
    assertEquals(UpdaterConstants.LOG_WRITEBACK_PATH, path);
  }

  @Test
  void handleMethodGET_whenDebugDisabled_expectSuccessReplyAndNoDecode() throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(LogWritebackToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try (MockedStatic<URLDecoder> urlDecoder = Mockito.mockStatic(URLDecoder.class)) {
      CapturingLogWritebackToadlet toadlet = new CapturingLogWritebackToadlet(client);

      // Act
      toadlet.handleMethodGET(
          URI.create("http://localhost/logwriteback/?msg=" + HELLO_ENCODED), request, context);

      // Assert
      assertEquals(1, toadlet.writeHtmlReplyCalls);
      assertSame(context, toadlet.capturedContext);
      assertEquals(200, toadlet.capturedStatusCode);
      assertEquals("OK", toadlet.capturedDescription);
      assertEquals(UpdaterConstants.SUCCESS, toadlet.capturedReply);
      urlDecoder.verifyNoInteractions();
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenDebugEnabledAndDecodeSucceeds_expectDecodeCalledAndSuccessReply()
      throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(LogWritebackToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    try (MockedStatic<URLDecoder> urlDecoder = Mockito.mockStatic(URLDecoder.class)) {
      CapturingLogWritebackToadlet toadlet = new CapturingLogWritebackToadlet(client);
      Mockito.when(request.getParam("msg")).thenReturn(HELLO_ENCODED);
      urlDecoder.when(() -> URLDecoder.decode(HELLO_ENCODED, false)).thenReturn("hello world");

      // Act
      toadlet.handleMethodGET(
          URI.create("http://localhost/logwriteback/?msg=" + HELLO_ENCODED), request, context);

      // Assert
      urlDecoder.verify(() -> URLDecoder.decode(HELLO_ENCODED, false));
      assertEquals(1, toadlet.writeHtmlReplyCalls);
      assertEquals(UpdaterConstants.SUCCESS, toadlet.capturedReply);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenDebugEnabledAndDecodeThrows_expectSuccessReply() throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(LogWritebackToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    try {
      CapturingLogWritebackToadlet toadlet = new CapturingLogWritebackToadlet(client);
      Mockito.when(request.getParam("msg")).thenReturn("%");

      // Act
      toadlet.handleMethodGET(
          URI.create("http://localhost/logwriteback/?msg=%25"), request, context);

      // Assert
      assertEquals(1, toadlet.writeHtmlReplyCalls);
      assertEquals(UpdaterConstants.SUCCESS, toadlet.capturedReply);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "plain", "%E2%9C%93"})
  void handleMethodGET_whenDebugEnabledAndMessageDecodes_expectSuccessReply(String msg)
      throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(LogWritebackToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    try {
      CapturingLogWritebackToadlet toadlet = new CapturingLogWritebackToadlet(client);
      Mockito.when(request.getParam("msg")).thenReturn(msg);

      // Act
      toadlet.handleMethodGET(URI.create("http://localhost/logwriteback/"), request, context);

      // Assert
      assertEquals(1, toadlet.writeHtmlReplyCalls);
      assertEquals(UpdaterConstants.SUCCESS, toadlet.capturedReply);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenWriteHtmlReplyThrowsIOException_expectExceptionPropagates() {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(LogWritebackToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try {
      IOException failingIoException = new IOException("fail");
      LogWritebackToadlet toadlet = new ThrowingLogWritebackToadlet(client, failingIoException);

      // Act
      IOException thrown =
          assertThrows(
              IOException.class,
              () ->
                  toadlet.handleMethodGET(
                      URI.create("http://localhost/logwriteback/?msg=plain"), request, context));

      // Assert
      assertSame(failingIoException, thrown);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  private static final class CapturingLogWritebackToadlet extends LogWritebackToadlet {
    private int writeHtmlReplyCalls;
    private ToadletContext capturedContext;
    private int capturedStatusCode;
    private String capturedDescription;
    private String capturedReply;

    private CapturingLogWritebackToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      writeHtmlReplyCalls++;
      capturedContext = ctx;
      capturedStatusCode = code;
      capturedDescription = desc;
      capturedReply = reply;
    }
  }

  private static final class ThrowingLogWritebackToadlet extends LogWritebackToadlet {
    private final IOException exceptionToThrow;

    private ThrowingLogWritebackToadlet(
        HighLevelSimpleClient client, IOException exceptionToThrow) {
      super(client);
      this.exceptionToThrow = exceptionToThrow;
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply)
        throws IOException {
      throw exceptionToThrow;
    }
  }
}
