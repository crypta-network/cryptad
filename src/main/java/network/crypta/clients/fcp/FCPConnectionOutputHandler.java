package network.crypta.clients.fcp;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serializes and transmits queued {@link FCPMessage} instances over an FCP socket.
 *
 * <p>This handler owns the write side of a {@link FCPConnectionHandler}, draining the in-memory
 * queue until the peer or node closes the connection. It batches writes through a buffered stream,
 * flushes opportunistically to minimize latency, and shuts down cleanly when the local handler
 * transitions into the closed state. The instance lives for the lifetime of a single socket and is
 * meant to be submitted to the node executor immediately after creation.
 *
 * <p>The class is stateful and thread-aware: producers enqueue messages while the {@link #run()}
 * loop waits, flushes, and writes under synchronization. Interrupted waits trigger a best-effort
 * flush before closing so callers can observe deterministic cleanup even during shutdowns. The
 * queue itself is intentionally simple—there is no prioritization beyond FIFO ordering, and
 * backpressure is exposed to callers via {@link #isQueueHalfFull()} for coarse throttling.
 *
 * <ul>
 *   <li>Responsibilities: drain {@link #outQueue}, flush as needed, and close sockets.
 *   <li>Thread-safety: external synchronization is required when inspecting or modifying shared
 *       state beyond provided helpers.
 *   <li>Typical usage: create via {@link #FCPConnectionOutputHandler(FCPConnectionHandler)}, call
 *       {@link #start()} and rely on {@link #onClosed()} during teardown.
 * </ul>
 *
 * @see FCPConnectionHandler
 */
public class FCPConnectionOutputHandler implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(FCPConnectionOutputHandler.class);
  private static final long OUT_QUEUE_WAIT_MS = 1000L;
  private static final long ON_CLOSED_WAIT_MS = 1500L;

  final FCPConnectionHandler handler;
  final Deque<FCPMessage> outQueue;
  // Synced on outQueue
  boolean closedOutputQueue;

  // Legacy threshold callback removed.

  /**
   * Creates a handler bound to the given connection coordinator.
   *
   * <p>The constructor stores references to the handler and allocates an empty deque for outgoing
   * messages. Callers are expected to enqueue messages quickly after instantiation and to invoke
   * {@link #start()} once the socket has been negotiated. The provided handler must remain alive
   * for the full lifetime of this instance because executor callbacks, queue size checks, and
   * shutdown signaling all dereference it without further null checks.
   *
   * @param handler non-null owner that exposes the socket, server, and lifecycle callbacks needed
   *     to write and tear down the connection safely
   */
  public FCPConnectionOutputHandler(FCPConnectionHandler handler) {
    this.handler = handler;
    this.outQueue = new ArrayDeque<>();
  }

  void start() {
    if (handler.getSocket() == null) return;
    handler
        .getServer()
        .getNode()
        .network()
        .executor()
        .execute(
            this,
            "FCP output handler for "
                + handler.getSocket().getRemoteSocketAddress()
                + ':'
                + handler.getSocket().getPort());
  }

  /**
   * Continuously drains the outgoing queue and writes each message to the socket.
   *
   * <p>The loop blocks until messages arrive, flushes buffered bytes whenever the queue stays empty
   * for a full wait cycle, and breaks only when either the handler reports a closed state or the
   * socket write fails. Unexpected interruptions trigger a final flush before the stream is closed
   * to keep wire state consistent. Any {@link IOException} is logged at debug level, while other
   * exceptions are logged as errors. Regardless of failure mode, the method always runs the handler
   * cleanup hooks so callers can assume the socket resources are released exactly once.
   *
   * <pre>{@code
   * // Typical usage from the connection handler
   * FCPConnectionOutputHandler output = new FCPConnectionOutputHandler(handler);
   * output.start();
   * }</pre>
   */
  @Override
  public void run() {
    try {
      realRun();
    } catch (IOException e) {
      if (LOG.isDebugEnabled()) LOG.debug("Caught {}", e, e);
    } catch (Exception e) {
      LOG.error("Caught {}", e, e);
    } finally {
      // Set the closed flag so that onClosed(), both on this thread and the input thread, doesn't
      // wait forever.
      // This happens in realRun() on a healthy exit, but we must do it here too to handle an
      // exceptional exit.
      // I.e. the other side closed the connection, and we threw an IOException.
      synchronized (outQueue) {
        closedOutputQueue = true;
      }
      handler.close();
      handler.closedOutput();
    }
  }

  private void realRun() throws IOException {
    OutputStream os = new BufferedOutputStream(handler.getSocket().getOutputStream(), 4096);
    boolean flushedSinceLastSend = false;
    while (true) {
      QueueAction action;
      try {
        action = nextQueueAction(flushedSinceLastSend);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        flushAndClose(os);
        return;
      }
      switch (action.type()) {
        case MESSAGE -> {
          sendMessage(os, action.message());
          flushedSinceLastSend = false;
        }
        case FLUSH -> {
          flushOutput(os);
          flushedSinceLastSend = true;
        }
        case CLOSED -> {
          flushAndClose(os);
          return;
        }
      }
    }
  }

  private void sendMessage(OutputStream os, FCPMessage msg) throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Sending {}", msg);
    msg.send(os);
  }

  private void flushAndClose(OutputStream os) throws IOException {
    flushOutput(os);
    os.close();
  }

  private void flushOutput(OutputStream os) throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Flushing");
    os.flush();
  }

  private QueueAction nextQueueAction(boolean flushedSinceLastSend) throws InterruptedException {
    synchronized (outQueue) {
      while (true) {
        boolean closed = handler.isClosed();
        if (!outQueue.isEmpty()) {
          return QueueAction.message(outQueue.removeFirst());
        }
        if (closed) {
          closedOutputQueue = true;
          outQueue.notifyAll();
          return QueueAction.closed();
        }
        if (!flushedSinceLastSend) {
          return QueueAction.flush();
        }
        outQueue.wait(OUT_QUEUE_WAIT_MS);
      }
    }
  }

  /**
   * Waits for the output queue to empty when the input counterpart reports closure.
   *
   * <p>This method allows the socket-owning thread to block briefly so the writer can flush the
   * remaining buffered messages prior to shutdown. It wakes whenever the queue is drained or when
   * {@link #closedOutputQueue} becomes {@code true}. Interruptions propagate by resetting the
   * interrupt flag and returning immediately, enabling higher-level shutdown coordination to take
   * the lead without losing the signal.
   */
  public void onClosed() {
    synchronized (outQueue) {
      outQueue.notifyAll();
      // Give a chance to the output handler to flush
      // its queue before the socket is closed
      // @see #2019 - nextgens
      while (!outQueue.isEmpty()) {
        if (closedOutputQueue) return;
        try {
          outQueue.wait(ON_CLOSED_WAIT_MS);
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
  }

  /**
   * Reports whether the output queue exceeds half of the configured capacity.
   *
   * <p>The helper offers callers a cheap backpressure signal so they can throttle message
   * production or reroute work before the queue reaches the server-imposed hard limit. The method
   * performs its computation under the same lock used for enqueueing to avoid exposing stale data
   * in concurrent scenarios.
   *
   * @return {@code true} when more than half the allowed entries are in the queue; {@code false}
   *     otherwise, meaning the handler still has comfortable headroom
   */
  public boolean isQueueHalfFull() {
    int maxQueueLength = handler.getServer().maxMessageQueueLength();
    synchronized (outQueue) {
      return outQueue.size() > maxQueueLength / 2;
    }
  }

  private enum QueueActionType {
    MESSAGE,
    FLUSH,
    CLOSED
  }

  private record QueueAction(QueueActionType type, FCPMessage message) {
    private static final QueueAction FLUSH = new QueueAction(QueueActionType.FLUSH, null);
    private static final QueueAction CLOSED = new QueueAction(QueueActionType.CLOSED, null);

    static QueueAction message(FCPMessage message) {
      return new QueueAction(QueueActionType.MESSAGE, message);
    }

    static QueueAction flush() {
      return FLUSH;
    }

    static QueueAction closed() {
      return CLOSED;
    }
  }
}
