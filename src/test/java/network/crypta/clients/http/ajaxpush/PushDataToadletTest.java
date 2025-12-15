package network.crypta.clients.http.ajaxpush;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.updateableelements.BaseUpdatableElement;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Base64;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PushDataToadletTest {

  private static final String PARAM_REQUEST_ID = "requestId";
  private static final String PARAM_ELEMENT_ID = "elementId";
  private static final URI PUSH_DATA_URI = URI.create("http://localhost/pushdata/");
  private static final String UPDATER_REPLACER = "ReplacerUpdater";
  private static final String CHILDREN_PAYLOAD = "<div>payload</div>";

  @Mock private HighLevelSimpleClient client;

  @Mock private HTTPRequest request;

  @Mock private ToadletContext context;

  @Mock private SimpleToadletServer server;

  @Mock private PushDataManager pushDataManager;

  @Mock private BaseUpdatableElement element;

  @Test
  void path_whenCalled_expectUpdaterConstant() {
    // Arrange
    PushDataToadlet toadlet = new PushDataToadlet(client);

    // Act
    String path = toadlet.path();

    // Assert
    assertEquals(UpdaterConstants.dataPath, path);
  }

  @ParameterizedTest
  @CsvSource({
    "'', ''",
    "'noSpaces', 'noSpaces'",
    "'a b', 'a+b'",
    "'a  b', 'a++b'",
    "'a+b', 'a+b'",
    "' + ', '+++'"
  })
  void handleMethodGET_whenElementIdHasSpaces_expectPlusRestoredBeforeLookup(
      String elementIdParam, String expectedLookupId) throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(PushDataToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try {
      String requestId = "req-1";
      CapturingPushDataToadlet toadlet = new CapturingPushDataToadlet(client);
      when(request.getParam(PARAM_REQUEST_ID)).thenReturn(requestId);
      when(request.getParam(PARAM_ELEMENT_ID)).thenReturn(elementIdParam);
      when(context.getContainer()).thenReturn(server);
      when(server.getPushDataManager()).thenReturn(pushDataManager);
      when(pushDataManager.getRenderedElement(requestId, expectedLookupId)).thenReturn(element);
      when(element.getUpdaterType()).thenReturn(UPDATER_REPLACER);
      when(element.generateChildren()).thenReturn(CHILDREN_PAYLOAD);

      // Act
      toadlet.handleMethodGET(PUSH_DATA_URI, request, context);

      // Assert
      verify(pushDataManager).getRenderedElement(requestId, expectedLookupId);
      assertEquals(1, toadlet.writeHtmlReplyCalls);
      assertEquals(200, toadlet.capturedStatusCode);
      assertEquals("OK", toadlet.capturedDescription);
      assertEquals(expectedReply(UPDATER_REPLACER, CHILDREN_PAYLOAD), toadlet.capturedReply);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenResponseGenerated_expectReplyIsUtf8Base64Encoded() throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(PushDataToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try {
      String updaterType = "tÿpe✓";
      String children = "<span>✓</span>";
      CapturingPushDataToadlet toadlet = new CapturingPushDataToadlet(client);
      when(request.getParam(PARAM_REQUEST_ID)).thenReturn("req-utf8");
      when(request.getParam(PARAM_ELEMENT_ID)).thenReturn("Zg==");
      when(context.getContainer()).thenReturn(server);
      when(server.getPushDataManager()).thenReturn(pushDataManager);
      when(pushDataManager.getRenderedElement("req-utf8", "Zg==")).thenReturn(element);
      when(element.getUpdaterType()).thenReturn(updaterType);
      when(element.generateChildren()).thenReturn(children);

      // Act
      toadlet.handleMethodGET(PUSH_DATA_URI, request, context);

      // Assert
      assertEquals(1, toadlet.writeHtmlReplyCalls);
      assertSame(context, toadlet.capturedContext);
      assertEquals(200, toadlet.capturedStatusCode);
      assertEquals("OK", toadlet.capturedDescription);
      assertEquals(expectedReply(updaterType, children), toadlet.capturedReply);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenDebugEnabled_expectGenerateChildrenCalledTwice() throws Exception {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(PushDataToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    try {
      CapturingPushDataToadlet toadlet = new CapturingPushDataToadlet(client);
      when(request.getParam(PARAM_REQUEST_ID)).thenReturn("req-debug");
      when(request.getParam(PARAM_ELEMENT_ID)).thenReturn("a b");
      when(context.getContainer()).thenReturn(server);
      when(server.getPushDataManager()).thenReturn(pushDataManager);
      when(pushDataManager.getRenderedElement("req-debug", "a+b")).thenReturn(element);
      when(element.getUpdaterType()).thenReturn(UPDATER_REPLACER);
      when(element.generateChildren()).thenReturn("<div>debug</div>");

      // Act
      toadlet.handleMethodGET(PUSH_DATA_URI, request, context);

      // Assert
      verify(element, times(2)).generateChildren();
      assertEquals(expectedReply(UPDATER_REPLACER, "<div>debug</div>"), toadlet.capturedReply);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenRenderedElementIsMissing_expectNullPointerException() {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(PushDataToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try {
      PushDataToadlet toadlet = new PushDataToadlet(client);
      when(request.getParam(PARAM_REQUEST_ID)).thenReturn("req-missing");
      when(request.getParam(PARAM_ELEMENT_ID)).thenReturn("missing");
      when(context.getContainer()).thenReturn(server);
      when(server.getPushDataManager()).thenReturn(pushDataManager);
      when(pushDataManager.getRenderedElement("req-missing", "missing")).thenReturn(null);

      // Act
      assertThrows(
          NullPointerException.class,
          () -> toadlet.handleMethodGET(PUSH_DATA_URI, request, context));
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  @Test
  void handleMethodGET_whenWriteHtmlReplyThrowsIOException_expectExceptionPropagates() {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(PushDataToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try {
      IOException failingIoException = new IOException("fail");
      PushDataToadlet toadlet = new ThrowingPushDataToadlet(client, failingIoException);
      when(request.getParam(PARAM_REQUEST_ID)).thenReturn("req-io");
      when(request.getParam(PARAM_ELEMENT_ID)).thenReturn("Zg==");
      when(context.getContainer()).thenReturn(server);
      when(server.getPushDataManager()).thenReturn(pushDataManager);
      when(pushDataManager.getRenderedElement("req-io", "Zg==")).thenReturn(element);
      when(element.getUpdaterType()).thenReturn(UPDATER_REPLACER);
      when(element.generateChildren()).thenReturn(CHILDREN_PAYLOAD);

      // Act
      IOException thrown =
          assertThrows(
              IOException.class, () -> toadlet.handleMethodGET(PUSH_DATA_URI, request, context));

      // Assert
      assertSame(failingIoException, thrown);
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  private static String expectedReply(String updaterType, String childrenHtml) {
    return UpdaterConstants.SUCCESS
        + UpdaterConstants.SEPARATOR
        + Base64.encodeStandard(updaterType.getBytes(StandardCharsets.UTF_8))
        + UpdaterConstants.SEPARATOR
        + Base64.encodeStandard(childrenHtml.getBytes(StandardCharsets.UTF_8));
  }

  private static final class CapturingPushDataToadlet extends PushDataToadlet {
    private int writeHtmlReplyCalls;
    private ToadletContext capturedContext;
    private int capturedStatusCode;
    private String capturedDescription;
    private String capturedReply;

    private CapturingPushDataToadlet(HighLevelSimpleClient client) {
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

  private static final class ThrowingPushDataToadlet extends PushDataToadlet {
    private final IOException exceptionToThrow;

    private ThrowingPushDataToadlet(HighLevelSimpleClient client, IOException exceptionToThrow) {
      super(client);
      this.exceptionToThrow = exceptionToThrow;
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply)
        throws IOException {
      throw exceptionToThrow;
    }
  }

  @Test
  void handleMethodGET_whenContainerIsNotSimpleToadletServer_expectClassCastException() {
    // Arrange
    Logger logger = (Logger) LoggerFactory.getLogger(PushDataToadlet.class);
    Level originalLevel = logger.getLevel();
    logger.setLevel(Level.INFO);
    try {
      PushDataToadlet toadlet = new PushDataToadlet(client);
      when(request.getParam(PARAM_REQUEST_ID)).thenReturn("req-cast");
      when(request.getParam(PARAM_ELEMENT_ID)).thenReturn("abc");
      when(context.getContainer())
          .thenReturn(mock(network.crypta.clients.http.ToadletContainer.class));

      // Act
      assertThrows(
          ClassCastException.class, () -> toadlet.handleMethodGET(PUSH_DATA_URI, request, context));
    } finally {
      logger.setLevel(originalLevel);
    }
  }
}
