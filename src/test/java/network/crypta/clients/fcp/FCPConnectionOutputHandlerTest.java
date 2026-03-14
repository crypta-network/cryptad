package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.stream.IntStream;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FCPConnectionOutputHandlerTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private Socket socket;
  @Mock private OutputStream outputStream;
  @Mock private SocketAddress socketAddress;

  private FCPConnectionOutputHandler outputHandler;

  @BeforeEach
  void setUp() {
    outputHandler = new FCPConnectionOutputHandler(handler);
  }

  @Test
  void start_whenSocketPresent_submitsRunnableWithLabel() {
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    ExecutionPort executionPort = mock(ExecutionPort.class);
    when(handler.getSocket()).thenReturn(socket);
    when(socket.getRemoteSocketAddress()).thenReturn(socketAddress);
    when(socketAddress.toString()).thenReturn("remote");
    when(socket.getPort()).thenReturn(9481);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.execution()).thenReturn(executionPort);

    outputHandler.start();

    verify(executionPort).execute(outputHandler, "FCP output handler for remote:9481");
  }

  @Test
  void start_whenSocketMissing_doesNotScheduleExecutor() {
    when(handler.getSocket()).thenReturn(null);

    outputHandler.start();

    verifyNoInteractions(server);
  }

  @Test
  void run_whenHandlerAlreadyClosed_flushesAndClosesStream() throws IOException {
    when(handler.getSocket()).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(outputStream);
    when(handler.isClosed()).thenReturn(true);

    outputHandler.run();

    verify(outputStream, atLeastOnce()).flush();
    verify(outputStream).close();
    verify(handler).close();
    verify(handler).closedOutput();
    assertTrue(outputHandler.closedOutputQueue);
  }

  @Test
  void run_whenCheckingClosedState_doesNotHoldQueueMonitor() throws IOException {
    when(handler.getSocket()).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(outputStream);
    doAnswer(
            invocation -> {
              assertFalse(Thread.holdsLock(outputHandler.outQueue));
              return true;
            })
        .when(handler)
        .isClosed();

    outputHandler.run();

    verify(outputStream, atLeastOnce()).flush();
    verify(outputStream).close();
    verify(handler).close();
    verify(handler).closedOutput();
    assertTrue(outputHandler.closedOutputQueue);
  }

  @Test
  void run_whenMessageQueued_sendsMessageBeforeClosing() throws IOException {
    FCPMessage message = mock(FCPMessage.class);
    outputHandler.outQueue.addLast(message);
    when(handler.getSocket()).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(outputStream);
    when(handler.isClosed()).thenReturn(false, true);

    outputHandler.run();

    verify(message).send(any(OutputStream.class));
    verify(outputStream, atLeastOnce()).flush();
    verify(outputStream).close();
    verify(handler).close();
    verify(handler).closedOutput();
    assertTrue(outputHandler.closedOutputQueue);
  }

  @Test
  void run_whenMessageSendThrowsIOException_stillClosesHandler() throws IOException {
    FCPMessage message = mock(FCPMessage.class);
    outputHandler.outQueue.addLast(message);
    when(handler.getSocket()).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(outputStream);
    when(handler.isClosed()).thenReturn(false);
    doThrow(new IOException("boom")).when(message).send(any(OutputStream.class));

    outputHandler.run();

    verify(handler).close();
    verify(handler).closedOutput();
    assertTrue(outputHandler.closedOutputQueue);
  }

  @Test
  void onClosed_whenClosedFlagSet_returnsWithoutWaiting() {
    outputHandler.outQueue.addLast(mock(FCPMessage.class));
    outputHandler.closedOutputQueue = true;

    assertTimeoutPreemptively(Duration.ofMillis(200), () -> outputHandler.onClosed());
  }

  @ParameterizedTest
  @CsvSource({"4,false", "5,false", "6,true"})
  void isQueueHalfFull_whenQueueSizeVaries_matchesExpectation(int queueSize, boolean expected) {
    when(handler.getServer()).thenReturn(server);
    when(server.maxMessageQueueLength()).thenReturn(10);
    fillQueue(queueSize);

    assertEquals(expected, outputHandler.isQueueHalfFull());
  }

  private void fillQueue(int messages) {
    IntStream.range(0, messages)
        .forEach(index -> outputHandler.outQueue.addLast(mock(FCPMessage.class)));
  }
}
