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

public class FCPConnectionInputHandler implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(FCPConnectionInputHandler.class);

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

  @Override
  public void run() {
    try {
      realRun();
    } catch (TooLongException e) {
      LOG.info("Caught " + e.getMessage(), e);
    } catch (IOException e) {
      LOG.info("Caught " + e, e);
    } catch (Throwable t) {
      LOG.error("Caught " + t, t);
      t.printStackTrace();
    }
    handler.close();
    handler.closedInput();
  }

  public void realRun() throws IOException {
    try (InputStream is = new BufferedInputStream(handler.getSocket().getInputStream(), 4096)) {
      LineReadingInputStream lis = new LineReadingInputStream(is);

      boolean firstMessage = true;

      while (true) {
        SimpleFieldSet fs;
        if (WrapperManager.hasShutdownHookBeenTriggered()) {
          FCPMessage msg =
              new ProtocolErrorMessage(
                  ProtocolErrorMessage.SHUTTING_DOWN,
                  true,
                  "The node is shutting down",
                  "Node",
                  false);
          handler.send(msg);
          return;
        }
        // Read a message
        String messageType = lis.readLine(128, 128, true);
        if (messageType == null) {
          return;
        }
        if (messageType.isEmpty()) continue;
        fs = new SimpleFieldSet(lis, 4096, 128, true, true, true);

        // check for valid endmarker
        if (!firstMessage
            && fs.getEndMarker() != null
            && (!fs.getEndMarker().startsWith("End"))
            && (!"Data".equals(fs.getEndMarker()))) {
          FCPMessage err =
              new ProtocolErrorMessage(
                  ProtocolErrorMessage.MESSAGE_PARSE_ERROR,
                  false,
                  "Invalid end marker: " + fs.getEndMarker(),
                  fs.get("Identifer"),
                  fs.getBoolean("Global", false));
          handler.send(err);
          continue;
        }

        FCPMessage msg;
        try {
          if (LOG.isTraceEnabled()) LOG.trace("Incoming FCP message:\n" + messageType + '\n' + fs);
          msg =
              FCPMessage.create(
                  messageType,
                  fs,
                  handler.getServer().getCore().getTempBucketFactory(),
                  handler.getServer().getCore().getPersistentTempBucketFactory());
          if (msg == null) continue;
        } catch (MessageInvalidException e) {
          if (firstMessage) {
            FCPMessage err =
                new ProtocolErrorMessage(
                    ProtocolErrorMessage.CLIENT_HELLO_MUST_BE_FIRST_MESSAGE,
                    true,
                    null,
                    null,
                    false);
            handler.send(err);
            handler.close();
            return;
          } else {
            FCPMessage err =
                new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global);
            handler.send(err);
          }
          continue;
        }
        if (firstMessage && !(msg instanceof ClientHelloMessage)) {
          FCPMessage err =
              new ProtocolErrorMessage(
                  ProtocolErrorMessage.CLIENT_HELLO_MUST_BE_FIRST_MESSAGE, true, null, null, false);
          handler.send(err);
          handler.close();
          return;
        }
        if (msg instanceof BaseDataCarryingMessage message) {
          // FIXME tidy up - coalesce with above and below try { } catch (MIE) {}'s?
          try {
            message.readFrom(
                lis, handler.getServer().getCore().getTempBucketFactory(), handler.getServer());
          } catch (MessageInvalidException e) {
            FCPMessage err =
                new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global);
            handler.send(err);
            continue;
          }
        }
        if ((!firstMessage) && (msg instanceof ClientHelloMessage)) {
          FCPMessage err =
              new ProtocolErrorMessage(
                  ProtocolErrorMessage.NO_LATE_CLIENT_HELLOS, false, null, null, false);
          handler.send(err);
          continue;
        }
        try {
          if (LOG.isTraceEnabled()) LOG.trace("Parsed message: " + msg + " for " + handler);
          msg.run(handler, handler.getServer().getNode());
        } catch (MessageInvalidException e) {
          FCPMessage err =
              new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global);
          handler.send(err);
          continue;
        }
        firstMessage = false;
        if (handler.isClosed()) {
          return;
        }
      }
    }
  }
}
