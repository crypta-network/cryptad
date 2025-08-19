package network.crypta.clients.fcp;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

public class FCPConnectionOutputHandler implements Runnable {

  final FCPConnectionHandler handler;
  final Deque<FCPMessage> outQueue;
  // Synced on outQueue
  boolean closedOutputQueue;

  private static volatile boolean logMINOR;
  private static volatile boolean logDEBUG;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
            logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
          }
        });
  }

  public FCPConnectionOutputHandler(FCPConnectionHandler handler) {
    this.handler = handler;
    this.outQueue = new ArrayDeque<>();
  }

  void start() {
    if (handler.getSocket() == null) return;
    handler
        .getServer()
        .getNode()
        .getExecutor()
        .execute(
            this,
            "FCP output handler for "
                + handler.getSocket().getRemoteSocketAddress()
                + ':'
                + handler.getSocket().getPort());
  }

  @Override
  public void run() {
    try {
      realRun();
    } catch (IOException e) {
      if (logMINOR) Logger.minor(this, "Caught " + e, e);
    } catch (Throwable t) {
      Logger.error(this, "Caught " + t, t);
    } finally {
      // Set the closed flag so that onClosed(), both on this thread and the input thread, doesn't
      // wait forever.
      // This happens in realRun() on a healthy exit, but we must do it here too to handle an
      // exceptional exit.
      // I.e. the other side closed the connection, and we threw an IOException.
      synchronized (outQueue) {
        closedOutputQueue = true;
      }
    }
    handler.close();
    handler.closedOutput();
  }

  private void realRun() throws IOException {
    OutputStream os = new BufferedOutputStream(handler.getSocket().getOutputStream(), 4096);
    while (true) {
      boolean closed;
      FCPMessage msg = null;
      boolean flushed = false;
      while (true) {
        closed = handler.isClosed();
        boolean shouldFlush = false;
        synchronized (outQueue) {
          if (outQueue.isEmpty()) {
            if (closed) {
              closedOutputQueue = true;
              outQueue.notifyAll();
              break;
            }
            if (!flushed) shouldFlush = true;
            else {
              try {
                outQueue.wait(1000);
              } catch (InterruptedException e) {
                // Ignore
              }
              continue;
            }
          } else {
            msg = outQueue.removeFirst();
          }
        }
        if (shouldFlush) {
          if (logMINOR) Logger.minor(this, "Flushing");
          os.flush();
          flushed = true;
        } else {
          break;
        }
      }
      if (msg == null) {
        if (closed) {
          os.flush();
          os.close();
          return;
        }
      } else {
        if (logMINOR) Logger.minor(this, "Sending " + msg);
        msg.send(os);
        flushed = false;
      }
    }
  }

  public void onClosed() {
    synchronized (outQueue) {
      outQueue.notifyAll();
      // Give a chance to the output handler to flush
      // its queue before the socket is closed
      // @see #2019 - nextgens
      while (!outQueue.isEmpty()) {
        if (closedOutputQueue) return;
        try {
          outQueue.wait(1500);
        } catch (InterruptedException e) {
        }
      }
    }
  }

  public boolean isQueueHalfFull() {
    int MAX_QUEUE_LENGTH = handler.getServer().maxMessageQueueLength();
    synchronized (outQueue) {
      return outQueue.size() > MAX_QUEUE_LENGTH / 2;
    }
  }
}
