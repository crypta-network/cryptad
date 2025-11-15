package network.crypta.clients.fcp;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.LineReadingInputStream;
import network.crypta.support.io.TooLongException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Parses and dispatches Freenet Client Protocol (FCP) messages arriving over a single socket
 * connection.
 *
 * <p>The handler is instantiated per accepted socket and acts as the dedicated reader for that
 * client until the connection is closed. It streams bytes through a {@link LineReadingInputStream},
 * enforces the protocol framing rules (line-oriented headers and an optional payload), and
 * coordinates message-specific execution through {@link #handleNextMessage(LineReadingInputStream,
 * boolean)}. The same instance maintains minimal state, namely whether the initial {@code
 * ClientHello} arrived, because the node rejects clients that attempt to pipeline requests before
 * authenticating.
 *
 * <p>Instances are run on a pooled executor thread configured by {@code FCPConnectionHandler}; the
 * class itself is not thread-safe and assumes a single consumer of the socket. Errors are logged
 * with informative severity while the {@linkplain #run() run loop} always performs cleanup to
 * release sockets promptly, even when unexpected {@link Throwable}s occur. Because the node may
 * receive malformed or malicious data, validations are strict and err on the side of disconnecting
 * noisy peers rather than risking resource exhaustion.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> Read input, validate message envelopes, and route to the
 *       owning {@link FCPConnectionHandler}.
 *   <li><strong>Lifecycle:</strong> Created during connection setup, scheduled via {@link
 *       #start()}, and shut down as soon as {@link #run()} completes.
 *   <li><strong>Threading:</strong> Single-threaded; caller must ensure each instance is executed
 *       once.
 * </ul>
 */
public class FCPConnectionInputHandler implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(FCPConnectionInputHandler.class);
  private static final String CAUGHT_LOG_TEMPLATE = "Caught {}";

  // Legacy threshold callback removed.

  final FCPConnectionHandler handler;

  FCPConnectionInputHandler(FCPConnectionHandler handler) {
    this.handler = handler;
  }

  void start() {
    if (handler.getSocket() == null) return;
    handler
        .getServer()
        .getNode()
        .getExecutor()
        .execute(this, "FCP input handler for " + handler.getSocket().getRemoteSocketAddress());
  }

  /**
   * Drives the connection read loop until the socket closes or an unrecoverable error occurs.
   *
   * <p>The executor invokes this entry point after {@link #start()} queues the handler. The method
   * blocks while draining messages, logging {@link TooLongException} instances at info level,
   * network {@link IOException}s for operational insight, and unexpected {@link Exception}s at
   * error level. Regardless of the outcome it reliably closes the handler, which in turn tears down
   * the socket, unregisters listeners, and notifies {@code FCPConnectionHandler} that no additional
   * input will arrive. Because cleanup happens in a {@code finally} block, even {@link Error}s such
   * as {@link OutOfMemoryError} trigger the same resource release path.
   */
  @Override
  public void run() {
    try {
      realRun();
    } catch (TooLongException e) {
      LOG.info(CAUGHT_LOG_TEMPLATE, e.getMessage(), e);
    } catch (IOException e) {
      LOG.info(CAUGHT_LOG_TEMPLATE, e, e);
    } catch (Exception e) {
      LOG.error(CAUGHT_LOG_TEMPLATE, e, e);
    } finally {
      handler.close();
      handler.closedInput();
    }
  }

  /**
   * Executes the low-level read loop that converts the socket stream into validated FCP messages.
   *
   * <p>Callers should prefer {@link #run()} for lifecycle management; this helper mainly exists to
   * make testing easier by exposing the parsing logic separately. The method wraps the socket input
   * in a {@link BufferedInputStream} to minimize read syscalls, enforces the maximum header length
   * per FCP specification, ensures {@code ClientHello} is the first accepted message, and reads any
   * declared payloads before dispatching. Returning from the method indicates graceful completion,
   * whereas exceptions propagate to signal abnormal termination so the caller can apply policy.
   *
   * <pre>{@code
   * // Example: exercising the parser with a mock handler in tests
   * new FCPConnectionInputHandler(mockHandler).realRun();
   * }</pre>
   *
   * @throws IOException if reading from the socket stream fails, including EOF or transport aborts
   */
  public void realRun() throws IOException {
    try (InputStream is = new BufferedInputStream(handler.getSocket().getInputStream(), 4096)) {
      LineReadingInputStream lis = new LineReadingInputStream(is);
      boolean firstMessage = true;

      while (true) {
        LoopDirective directive = handleNextMessage(lis, firstMessage);
        if (directive == LoopDirective.STOP) {
          return;
        }
        if (directive == LoopDirective.CONTINUE_PROCESSED) {
          firstMessage = false;
        }
      }
    }
  }

  private LoopDirective handleNextMessage(LineReadingInputStream lis, boolean firstMessage)
      throws IOException {
    if (sendShutdownNoticeIfNeeded()) {
      return LoopDirective.STOP;
    }

    String messageType = lis.readLine(128, 128, true);
    if (messageType == null) {
      return LoopDirective.STOP;
    }
    if (messageType.isEmpty()) {
      return LoopDirective.CONTINUE;
    }

    SimpleFieldSet fs = new SimpleFieldSet(lis, 4096, 128, true, true, true);
    if (hasInvalidEndMarker(firstMessage, fs)) {
      sendInvalidEndMarker(fs);
      return LoopDirective.CONTINUE;
    }

    FCPMessage msg;
    try {
      msg = createMessage(messageType, fs);
      if (msg == null) {
        return LoopDirective.CONTINUE;
      }
    } catch (MessageInvalidException e) {
      if (firstMessage) {
        sendClientHelloRequiredError();
        handler.close();
        return LoopDirective.STOP;
      }
      sendProtocolError(e);
      return LoopDirective.CONTINUE;
    }

    if (firstMessage && !(msg instanceof ClientHelloMessage)) {
      sendClientHelloRequiredError();
      handler.close();
      return LoopDirective.STOP;
    }

    if (!readPayloadIfRequired(msg, lis)) {
      return LoopDirective.CONTINUE;
    }

    if (!firstMessage && msg instanceof ClientHelloMessage) {
      sendLateClientHelloError();
      return LoopDirective.CONTINUE;
    }

    if (!runMessage(msg)) {
      return LoopDirective.CONTINUE;
    }

    if (handler.isClosed()) {
      return LoopDirective.STOP;
    }

    return LoopDirective.CONTINUE_PROCESSED;
  }

  private boolean sendShutdownNoticeIfNeeded() {
    if (!WrapperManager.hasShutdownHookBeenTriggered()) {
      return false;
    }
    FCPMessage msg =
        new ProtocolErrorMessage(
            ProtocolErrorMessage.SHUTTING_DOWN, true, "The node is shutting down", "Node", false);
    handler.send(msg);
    return true;
  }

  private boolean hasInvalidEndMarker(boolean firstMessage, SimpleFieldSet fs) {
    return !firstMessage
        && fs.getEndMarker() != null
        && !fs.getEndMarker().startsWith("End")
        && !"Data".equals(fs.getEndMarker());
  }

  private void sendInvalidEndMarker(SimpleFieldSet fs) {
    FCPMessage err =
        new ProtocolErrorMessage(
            ProtocolErrorMessage.MESSAGE_PARSE_ERROR,
            false,
            "Invalid end marker: " + fs.getEndMarker(),
            fs.get("Identifer"),
            fs.getBoolean("Global", false));
    handler.send(err);
  }

  private FCPMessage createMessage(String messageType, SimpleFieldSet fs)
      throws MessageInvalidException {
    if (LOG.isTraceEnabled()) {
      LOG.trace("Incoming FCP message:\n{}\n{}", messageType, fs);
    }
    return FCPMessage.create(
        messageType,
        fs,
        handler.getServer().getCore().getTempBucketFactory(),
        handler.getServer().getCore().getPersistentTempBucketFactory());
  }

  private boolean readPayloadIfRequired(FCPMessage msg, LineReadingInputStream lis)
      throws IOException {
    if (msg instanceof BaseDataCarryingMessage message) {
      try {
        message.readFrom(
            lis, handler.getServer().getCore().getTempBucketFactory(), handler.getServer());
      } catch (MessageInvalidException e) {
        sendProtocolError(e);
        return false;
      }
    }
    return true;
  }

  private void sendProtocolError(MessageInvalidException e) {
    FCPMessage err =
        new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global);
    handler.send(err);
  }

  private void sendClientHelloRequiredError() {
    FCPMessage err =
        new ProtocolErrorMessage(
            ProtocolErrorMessage.CLIENT_HELLO_MUST_BE_FIRST_MESSAGE, true, null, null, false);
    handler.send(err);
  }

  private void sendLateClientHelloError() {
    FCPMessage err =
        new ProtocolErrorMessage(
            ProtocolErrorMessage.NO_LATE_CLIENT_HELLOS, false, null, null, false);
    handler.send(err);
  }

  private boolean runMessage(FCPMessage msg) {
    try {
      if (LOG.isTraceEnabled()) {
        LOG.trace("Parsed message: {} for {}", msg, handler);
      }
      msg.run(handler, handler.getServer().getNode());
      return true;
    } catch (MessageInvalidException e) {
      sendProtocolError(e);
      return false;
    }
  }

  private enum LoopDirective {
    CONTINUE,
    CONTINUE_PROCESSED,
    STOP
  }
}
