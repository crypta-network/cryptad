package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.LineReadingInputStream;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FCPConnectionInputHandlerTest {

  @Test
  void start_whenSocketIsNull_doesNotSubmitToExecutor() {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPConnectionInputHandler inputHandler = new FCPConnectionInputHandler(handler);

    when(handler.getSocket()).thenReturn(null);

    inputHandler.start();

    verify(handler, never()).getServer();
  }

  @Test
  void start_whenSocketPresent_submitsRunnableWithRemoteAddress() {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPServer server = mock(FCPServer.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    Socket socket = mock(Socket.class);
    InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 9481);

    when(handler.getSocket()).thenReturn(socket);
    when(socket.getRemoteSocketAddress()).thenReturn(address);
    when(handler.getServer()).thenReturn(server);
    when(server.getNode()).thenReturn(node);
    when(node.network().executor()).thenReturn(executor);

    FCPConnectionInputHandler inputHandler = new FCPConnectionInputHandler(handler);

    inputHandler.start();

    verify(executor).execute(eq(inputHandler), contains(address.toString()));
  }

  @Test
  void run_whenRealRunThrowsIOException_invokesCloseAndClosedInput() {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPConnectionInputHandler inputHandler =
        new FCPConnectionInputHandler(handler) {
          @Override
          public void realRun() throws IOException {
            throw new IOException("boom");
          }
        };

    inputHandler.run();

    InOrder order = inOrder(handler);
    order.verify(handler).close();
    order.verify(handler).closedInput();
  }

  @Test
  void realRun_whenFirstMessageNotClientHello_sendsFatalErrorAndCloses() throws Exception {
    TestContext ctx = createContext(message("Custom", "EndMessage", "Field=Value"));
    FakeSimpleMessage unexpected = new FakeSimpleMessage();
    List<String> lines = List.of("Custom", "Field=Value", "EndMessage");

    try (var _ = mockFactory(unexpected, "Custom")) {
      withLineSequence(lines, ctx.inputHandler::realRun);
    }

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(ctx.handler).send(captor.capture());
    ProtocolErrorMessage error = (ProtocolErrorMessage) captor.getValue();
    assertEquals(ProtocolErrorMessage.CLIENT_HELLO_MUST_BE_FIRST_MESSAGE, error.getCode());
    verify(ctx.handler).close();
  }

  @Test
  void realRun_whenSubsequentClientHelloArrives_sendsNoLateHelloError() throws Exception {
    TestContext ctx = createContext(clientHello("One"), clientHello("Two"));

    List<String> lines =
        List.of(
            "ClientHello",
            "Name=One",
            "ExpectedVersion=2.0",
            "EndMessage",
            "ClientHello",
            "Name=Two",
            "ExpectedVersion=2.0",
            "EndMessage");
    withLineSequence(lines, ctx.inputHandler::realRun);

    ProtocolErrorMessage error = findError(ctx.handler, ProtocolErrorMessage.NO_LATE_CLIENT_HELLOS);
    assertEquals(ProtocolErrorMessage.NO_LATE_CLIENT_HELLOS, error.getCode());
    verify(ctx.handler, never()).close();
  }

  @Test
  void realRun_whenEndMarkerInvalid_sendsParseError() throws Exception {
    TestContext ctx = createContext(clientHello("One"), message("Bad", "Oops", "Key=Value"));
    List<String> lines =
        List.of(
            "ClientHello",
            "Name=One",
            "ExpectedVersion=2.0",
            "EndMessage",
            "Bad",
            "Key=Value",
            "Oops");
    withLineSequence(lines, ctx.inputHandler::realRun);

    ProtocolErrorMessage error = findError(ctx.handler, ProtocolErrorMessage.MESSAGE_PARSE_ERROR);
    assertEquals("Invalid end marker: Oops", error.extra);
  }

  @Test
  void realRun_whenBaseDataPayloadParsingFails_sendsProtocolErrorFromException() throws Exception {
    MessageInvalidException mie =
        new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD, "broken", "dataIdent", true);
    FakeDataMessage failingData = new FakeDataMessage(mie);

    TestContext ctx = createContext(clientHello("One"), message("StubData", "EndMessage"));

    List<String> lines =
        List.of(
            "ClientHello",
            "Name=One",
            "ExpectedVersion=2.0",
            "EndMessage",
            "StubData",
            "EndMessage");
    try (var _ = mockFactory(failingData, "StubData")) {
      withLineSequence(lines, ctx.inputHandler::realRun);
    }

    ProtocolErrorMessage error = findError(ctx.handler, ProtocolErrorMessage.INVALID_FIELD);
    assertEquals("broken", error.extra);
    assertEquals("dataIdent", error.ident);
    assertTrue(error.global);
  }

  @Test
  void realRun_whenMessageHandlerThrows_sendsProtocolErrorFromException() throws Exception {
    MessageInvalidException mie =
        new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR, "boom", "ident", false);
    FakeSimpleMessage throwingMessage = new FakeSimpleMessage(() -> {}, mie);

    TestContext ctx = createContext(clientHello("One"), message("AfterHello", "EndMessage"));

    List<String> lines =
        List.of(
            "ClientHello",
            "Name=One",
            "ExpectedVersion=2.0",
            "EndMessage",
            "AfterHello",
            "EndMessage");
    try (var _ = mockFactory(throwingMessage, "AfterHello")) {
      withLineSequence(lines, ctx.inputHandler::realRun);
    }

    ProtocolErrorMessage error = findError(ctx.handler, ProtocolErrorMessage.INTERNAL_ERROR);
    assertEquals("boom", error.extra);
  }

  @Test
  void realRun_whenHandlerIndicatesClosed_stopsConsumingFurtherMessages() throws Exception {
    AtomicBoolean closed = new AtomicBoolean(false);
    FakeSimpleMessage stopMessage = new FakeSimpleMessage(() -> closed.set(true), null);
    TestContext ctx =
        createContext(
            clientHello("One"), message("Stop", "EndMessage"), message("NeverRead", "EndMessage"));

    lenient().when(ctx.handler.isClosed()).thenAnswer(_ -> closed.get());
    List<String> lines =
        List.of(
            "ClientHello",
            "Name=One",
            "ExpectedVersion=2.0",
            "EndMessage",
            "Stop",
            "EndMessage",
            "NeverRead",
            "EndMessage");

    try (MockedStatic<FCPMessage> mocked = mockFactory(stopMessage, "Stop")) {
      withLineSequence(lines, ctx.inputHandler::realRun);
      mocked.verify(
          () -> FCPMessage.create(eq("NeverRead"), any(SimpleFieldSet.class), any(), any()),
          never());
    }
  }

  private static MockedStatic<FCPMessage> mockFactory(FCPMessage message, String name) {
    MockedStatic<FCPMessage> mocked =
        mockStatic(FCPMessage.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
    mocked
        .when(() -> FCPMessage.create(eq(name), any(SimpleFieldSet.class), any(), any()))
        .thenReturn(message);
    return mocked;
  }

  private ProtocolErrorMessage findError(FCPConnectionHandler handler, int code) {
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, atLeastOnce()).send(captor.capture());
    return captor.getAllValues().stream()
        .filter(ProtocolErrorMessage.class::isInstance)
        .map(ProtocolErrorMessage.class::cast)
        .filter(err -> err.getCode() == code)
        .findFirst()
        .orElseThrow(
            () ->
                new AssertionError(
                    "ProtocolError " + code + " not emitted. Sent=" + captor.getAllValues()));
  }

  private TestContext createContext(String... messages) throws Exception {
    String payload = String.join("\n", messages);
    InputStream stream = new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8));

    TestContext ctx = new TestContext();
    ctx.handler = mock(FCPConnectionHandler.class);
    ctx.bucketFactory = mock(TempBucketFactory.class);
    ctx.server = mock(FCPServer.class);
    ctx.node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    ctx.core = mock(NodeClientCore.class);
    ctx.persistentFactory = mock(PersistentTempBucketFactory.class);
    ctx.socket = mock(Socket.class);

    when(ctx.handler.getSocket()).thenReturn(ctx.socket);
    when(ctx.socket.getInputStream()).thenReturn(stream);
    when(ctx.handler.getServer()).thenReturn(ctx.server);
    lenient().when(ctx.server.getNode()).thenReturn(ctx.node);
    lenient().when(ctx.server.getCore()).thenReturn(ctx.core);
    lenient().when(ctx.core.getTempBucketFactory()).thenReturn(ctx.bucketFactory);
    lenient().when(ctx.core.getPersistentTempBucketFactory()).thenReturn(ctx.persistentFactory);
    lenient().when(ctx.handler.isClosed()).thenReturn(false);
    lenient().when(ctx.handler.getConnectionIdentifierUUID()).thenReturn(UUID.randomUUID());

    ctx.inputHandler = new FCPConnectionInputHandler(ctx.handler);
    return ctx;
  }

  private static String message(String name, String endMarker, String... kvPairs) {
    StringBuilder builder = new StringBuilder();
    builder.append(name).append('\n');
    for (String pair : kvPairs) {
      builder.append(pair).append('\n');
    }
    builder.append(endMarker).append('\n');
    return builder.toString();
  }

  private static String clientHello(String clientName) {
    return message("ClientHello", "EndMessage", "Name=" + clientName, "ExpectedVersion=2.0");
  }

  private void withLineSequence(List<String> lines, ThrowingRunnable runnable) throws Exception {
    Deque<String> queue = new ArrayDeque<>(lines);
    try (var _ =
        mockConstruction(
            LineReadingInputStream.class,
            (mock, _) ->
                when(mock.readLine(anyInt(), anyInt(), anyBoolean()))
                    .thenAnswer(_ -> queue.isEmpty() ? null : queue.removeFirst()))) {
      runnable.run();
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  private static final class TestContext {
    FCPConnectionInputHandler inputHandler;
    FCPConnectionHandler handler;
    FCPServer server;
    Node node;
    NodeClientCore core;
    Socket socket;
    TempBucketFactory bucketFactory;
    PersistentTempBucketFactory persistentFactory;
  }

  private static final class FakeDataMessage extends BaseDataCarryingMessage {
    private final MessageInvalidException readFailure;

    FakeDataMessage(MessageInvalidException readFailure) {
      this.readFailure = readFailure;
    }

    @Override
    public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
        throws MessageInvalidException {
      if (readFailure != null) {
        throw readFailure;
      }
    }

    @Override
    public void run(FCPConnectionHandler handler, Node node) {
      // Intentionally empty: run() must remain inert so that tests focus solely on readFrom().
    }

    @Override
    protected void writeData(OutputStream os) {
      // Intentionally empty: tests never serialize this stub, so no payload is written.
    }

    @Override
    long dataLength() {
      return 0;
    }

    @Override
    public SimpleFieldSet getFieldSet() {
      return new SimpleFieldSet(true);
    }

    @Override
    public String getName() {
      return "StubData";
    }
  }

  private static class FakeSimpleMessage extends FCPMessage {
    private final Runnable runHook;
    private final MessageInvalidException runFailure;

    FakeSimpleMessage() {
      this(() -> {}, null);
    }

    FakeSimpleMessage(Runnable runHook, MessageInvalidException runFailure) {
      this.runHook = runHook;
      this.runFailure = runFailure;
    }

    @Override
    public SimpleFieldSet getFieldSet() {
      return new SimpleFieldSet(true);
    }

    @Override
    public String getName() {
      return "Fake";
    }

    @Override
    public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
      if (runHook != null) {
        runHook.run();
      }
      if (runFailure != null) {
        throw runFailure;
      }
    }
  }
}
