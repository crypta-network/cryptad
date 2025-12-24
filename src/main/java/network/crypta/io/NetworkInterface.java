package network.crypta.io;

import java.io.Closeable;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.StringTokenizer;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import network.crypta.support.PriorityAwareExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Server-side listener that multiplexes a set of {@link ServerSocket} instances.
 *
 * <p>This class binds one listener per configured local address, queues accepted client
 * connections, and exposes a simple {@link #accept()} method to retrieve them. Inbound connections
 * are filtered using an allow list (see {@link AllowedHosts}). The implementation is thread-safe;
 * it uses a single lock to protect shared state ({@code acceptors}, {@code acceptedSockets}, and
 * related conditions).
 *
 * <p>Typical flow:
 *
 * <ol>
 *   <li>Create an instance via {@link #create(int, String, String, PriorityAwareExecutor, boolean)}
 *       (or subclass and call the constructor).
 *   <li>Optionally adjust the accept timeout via {@link #setSoTimeout(int)}.
 *   <li>Poll or block on {@link #accept()} to obtain client {@link Socket}s and hand them to a
 *       protocol handler.
 * </ol>
 *
 * <p>Lifecycle: calling {@link #close()} closes all underlying server sockets, unblocks waiting
 * threads, and prevents re-binding. If the Tanuki Wrapper shutdown hook has been triggered, the
 * instance refuses to re-bind to avoid resurrecting listeners during shutdown.
 *
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public class NetworkInterface implements Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(NetworkInterface.class);

  /**
   * Default local bindings used when none are provided: IPv4 and IPv6 loopback.
   *
   * <p>Value format is a comma-separated list of literals understood by {@link InetSocketAddress}
   * (for example, {@code 127.0.0.1,0:0:0:0:0:0:0:1}).
   */
  public static final String DEFAULT_BIND_TO = "127.0.0.1,0:0:0:0:0:0:0:1";

  /** Lock guarding shared state and conditions. */
  private final Lock lock = new ReentrantLock();

  /** Signaled when at least one acceptor has been started (bound). */
  private final Condition boundCondition = lock.newCondition();

  /** Signaled when a client socket has been queued. */
  private final Condition socketCondition = lock.newCondition();

  /** Signaled when an {@code Acceptor} terminates to let waiters proceed. */
  private final Condition acceptorClosedCondition = lock.newCondition();

  /** Active acceptors, one per bound local address. */
  private final List<Acceptor> acceptors = new ArrayList<>();

  /** FIFO queue of accepted client connections. */
  private final Queue<Socket> acceptedSockets = new ArrayDeque<>();

  /** Allow list used to decide whether to accept a remote address. */
  protected final AllowedHosts allowedHosts;

  /** The SO_TIMEOUT configured for underlying server sockets via {@link #setSoTimeout(int)}. */
  private int timeout = 0;

  /** Local TCP port to bind each {@link ServerSocket} to. */
  private final int port;

  /** Number of currently running acceptor threads. Guarded by {@link #lock}. */
  private int runningAcceptors = 0;

  private volatile boolean shutdown = false;

  private final PriorityAwareExecutor executor;

  // Maximum number of queued connections awaiting retrieval by accept().
  static final int MAX_QUEUE_LENGTH = 100;

  /**
   * Creates, binds, and starts a {@code NetworkInterface} with the given configuration.
   *
   * <p>Binding attempts one {@link ServerSocket} per address in {@code bindTo}. Addresses that fail
   * to bind are logged; IPv6 binding failures can be ignored when {@code ignoreUnbindableIP6} is
   * {@code true}.
   *
   * @param port local TCP port shared by all bound addresses
   * @param bindTo comma-separated local addresses to bind; if {@code null} or empty, defaults to
   *     {@link #DEFAULT_BIND_TO}
   * @param allowedHosts allow list for remote client addresses (see {@link AllowedHosts})
   * @param executor executor used to run acceptor threads
   * @param ignoreUnbindableIP6 when {@code true}, silently ignore IPv6 addresses that cannot be
   *     bound due to a {@link SocketException}
   * @return configured and started instance; never {@code null}
   */
  public static NetworkInterface create(
      int port,
      String bindTo,
      String allowedHosts,
      PriorityAwareExecutor executor,
      boolean ignoreUnbindableIP6) {
    NetworkInterface iface = new NetworkInterface(port, allowedHosts, executor);
    String[] failedBind = iface.setBindTo(bindTo, ignoreUnbindableIP6);
    if (failedBind != null && failedBind.length > 0 && LOG.isWarnEnabled()) {
      LOG.warn(
          "Could not bind to some of the interfaces specified for port {} : {}",
          port,
          Arrays.toString(failedBind));
    }
    return iface;
  }

  /**
   * Constructs a new instance.
   *
   * <p>The instance is not bound until {@link #setBindTo(String, boolean)} is invoked (directly or
   * via the {@link #create(int, String, String, PriorityAwareExecutor, boolean)} factory).
   *
   * @param port local TCP port to listen on
   * @param allowedHosts allow list used to filter remote client addresses; see {@link AllowedHosts}
   * @param executor executor used to run acceptor threads
   */
  protected NetworkInterface(int port, String allowedHosts, PriorityAwareExecutor executor) {
    this.port = port;
    this.allowedHosts = new AllowedHosts(allowedHosts);
    this.executor = executor;
  }

  /**
   * Factory method for creating a {@link ServerSocket}.
   *
   * <p>Subclasses may override to customize socket options before binding.
   *
   * @return a new, unbound server socket
   * @throws IOException if the socket cannot be created
   */
  protected ServerSocket createServerSocket() throws IOException {
    return new ServerSocket();
  }

  /**
   * Binds the interface to the specified local addresses.
   *
   * <p>Existing acceptors are closed, then a new acceptor is started for each token in {@code
   * bindTo}. If {@code bindTo} is {@code null} or empty, {@link #DEFAULT_BIND_TO} is used. When a
   * shutdown has been requested (either via {@link #close()} or when the Wrapper shutdown hook is
   * active), the method returns without rebinding to avoid resurrecting listeners.
   *
   * @param bindTo comma-separated list of local addresses to bind
   * @param ignoreUnbindableIP6 when {@code true}, ignore {@link SocketException} for IPv6 binding
   *     failures and continue binding other addresses
   * @return array of addresses that failed to bind; returns {@code null} when all bindings succeed
   *     or when a shutdown is in progress (legacy contract relied upon by callers)
   */
  @SuppressWarnings("java:S1168")
  public String[] setBindTo(String bindTo, boolean ignoreUnbindableIP6) {
    if (bindTo == null || bindTo.isEmpty()) bindTo = NetworkInterface.DEFAULT_BIND_TO;
    List<String> bindToTokenList = tokenizeBindTo(bindTo);

    stopOldAcceptorsAndWait();

    // Abort rebinding when shutdown has been requested (explicitly or by the Wrapper hook).
    if (shutdown || WrapperManager.hasShutdownHookBeenTriggered()) {
      // Preserve legacy contract: null signifies success/no failures.
      return null;
    }

    List<String> brokenList = null;
    for (String address : bindToTokenList) {
      InetSocketAddress addr = null;
      try {
        ServerSocket serverSocket = createServerSocket();
        addr = new InetSocketAddress(address, port);
        serverSocket.setReuseAddress(true);
        serverSocket.bind(addr);
        Acceptor acceptor = new Acceptor(serverSocket);
        applyTimeout(acceptor, addr);
        registerAndStart(acceptor);
      } catch (IOException e) {
        if (e instanceof SocketException
            && ignoreUnbindableIP6
            && addr != null
            && addr.getAddress() instanceof Inet6Address) {
          continue;
        }
        LOG.error("Unable to bind to address {} for port {}", address, port);
        if (brokenList == null) brokenList = new ArrayList<>();
        brokenList.add(address);
      }
    }

    signalBound();
    // Legacy contract: null on success, non-null array lists failed addresses.
    return brokenList == null ? null : brokenList.toArray(new String[0]);
  }

  private List<String> tokenizeBindTo(String bindTo) {
    StringTokenizer bindToTokens = new StringTokenizer(bindTo, ",");
    List<String> bindToTokenList = new ArrayList<>();
    while (bindToTokens.hasMoreTokens()) {
      bindToTokenList.add(bindToTokens.nextToken().trim());
    }
    return bindToTokenList;
  }

  private void stopOldAcceptorsAndWait() {
    for (Acceptor acceptor : grabAcceptors()) {
      try {
        acceptor.close();
      } catch (IOException _) {
        // Intentionally ignore errors while closing stale acceptors.
      }
    }
    lock.lock();
    try {
      while (runningAcceptors > 0) {
        acceptorClosedCondition.awaitUninterruptibly();
        if (shutdown || WrapperManager.hasShutdownHookBeenTriggered()) return;
      }
    } finally {
      lock.unlock();
    }
  }

  private void registerAndStart(Acceptor acceptor) {
    lock.lock();
    try {
      acceptors.add(acceptor);
      runningAcceptors++;
      executor.execute(acceptor, "Network Interface Acceptor for " + acceptor.serverSocket);
    } finally {
      lock.unlock();
    }
  }

  private void signalBound() {
    lock.lock();
    try {
      boundCondition.signalAll();
    } finally {
      lock.unlock();
    }
  }

  private void applyTimeout(Acceptor acceptor, InetSocketAddress addr) {
    try {
      acceptor.setSoTimeout(timeout);
    } catch (SocketException _) {
      LOG.error("Unable to setSoTimeout in setBindTo() on {}", addr);
    }
  }

  /**
   * Replaces the current allow list used to filter incoming connections.
   *
   * <p>See {@link AllowedHosts} for supported syntax (IPv4/IPv6 literals with optional masks, or
   * {@code "*"}).
   *
   * @param allowedHosts comma-separated rule list; {@code null} or empty defaults to loopback-only
   */
  public void setAllowedHosts(String allowedHosts) {
    this.allowedHosts.setAllowedHosts(allowedHosts);
  }

  /**
   * Sets {@code SO_TIMEOUT} on all current and future server sockets.
   *
   * <p>The value controls the blocking time of the underlying {@link ServerSocket#accept()} calls
   * within acceptor threads. It does not impose a time limit on {@link #accept()} itself, which
   * waits until a connection becomes available or the interface shuts down.
   *
   * @param timeout timeout in milliseconds; {@code 0} disables the socket-level timeout
   * @throws SocketException if applying the timeout to an existing server socket fails
   * @see ServerSocket#setSoTimeout(int)
   */
  public void setSoTimeout(int timeout) throws SocketException {
    for (Acceptor acceptor : getAcceptors()) {
      acceptor.setSoTimeout(timeout);
    }
    this.timeout = timeout;
  }

  /**
   * Retrieves the next accepted client connection, blocking if necessary.
   *
   * <p>This method waits until a client socket has been queued by an acceptor thread, the interface
   * is closed, or no acceptors are bound. It does not throw {@link SocketTimeoutException}; the
   * {@link #setSoTimeout(int)} value applies to the underlying server sockets only.
   *
   * @return a connected {@link Socket}, or {@code null} if the interface is shut down or currently
   *     unbound
   */
  public Socket accept() {
    lock.lock();
    try {
      Socket socket;
      while ((socket = acceptedSockets.poll()) == null) {
        if (shutdown) return null;
        if (WrapperManager.hasShutdownHookBeenTriggered()) return null;
        if (acceptors.isEmpty()) {
          return null;
        }
        socketCondition.awaitUninterruptibly();
        if (timeout > 0) {
          socket = acceptedSockets.poll();
          break;
        }
      }
      return socket;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Closes this interface and all underlying server sockets.
   *
   * <p>Signals waiting threads and prevents future re-binding. If closing one or more sockets
   * fails, the last encountered {@link IOException} is rethrown after signalling.
   *
   * @throws IOException if an I/O error occurs while closing server sockets
   * @see ServerSocket#close()
   */
  @Override
  public void close() throws IOException {
    IOException exception = null;
    shutdown = true;
    /* Close existing acceptors before signalling waiters. */
    for (Acceptor acceptor : grabAcceptors()) {
      try {
        acceptor.close();
      } catch (IOException ioe1) {
        exception = ioe1;
      }
    }
    lock.lock();
    try {
      boundCondition.signalAll();
      acceptorClosedCondition.signalAll();
      socketCondition.signalAll();
    } finally {
      lock.unlock();
    }
    if (exception != null) {
      throw exception;
    }
  }

  private Acceptor[] grabAcceptors() {
    Acceptor[] oldAcceptors;
    lock.lock();
    try {
      oldAcceptors = acceptors.toArray(new Acceptor[0]);
      acceptors.clear();
      return oldAcceptors;
    } finally {
      lock.unlock();
    }
  }

  private Acceptor[] getAcceptors() {
    lock.lock();
    try {
      return acceptors.toArray(new Acceptor[0]);
    } finally {
      lock.unlock();
    }
  }

  // acceptor-stopped signaling is handled within Acceptor

  /**
   * Acceptor runnable that blocks on {@link ServerSocket#accept()}, applies the allow list, and
   * enqueues permitted client sockets.
   */
  private class Acceptor implements Runnable {

    /** The {@link ServerSocket} to listen on. */
    private final ServerSocket serverSocket;

    /** Whether this acceptor has been closed. */
    private boolean closed = false;

    /**
     * Creates a new acceptor for the specified server socket.
     *
     * @param serverSocket the unbound/bound server socket to listen on
     */
    public Acceptor(ServerSocket serverSocket) {
      this.serverSocket = serverSocket;
    }

    /**
     * Sets {@code SO_TIMEOUT} on this acceptor's server socket.
     *
     * @param timeout timeout in milliseconds; {@code 0} disables the socket-level timeout
     * @throws SocketException if the timeout cannot be applied
     * @see ServerSocket#setSoTimeout(int)
     */
    public void setSoTimeout(int timeout) throws SocketException {
      serverSocket.setSoTimeout(timeout);
    }

    /**
     * Closes this acceptor and the underlying server socket.
     *
     * @throws IOException if an I/O error occurs while closing
     * @see ServerSocket#close()
     */
    public void close() throws IOException {
      closed = true;
      serverSocket.close();
    }

    /** Main loop: accept, filter, and enqueue permitted client connections. */
    @Override
    public void run() {
      while (!closed) {
        try {
          Socket clientSocket = serverSocket.accept();
          InetAddress clientAddress = clientSocket.getInetAddress();
          if (LOG.isDebugEnabled()) LOG.debug("Connection from {}", clientAddress);
          handleAcceptedClient(clientSocket, clientAddress);
        } catch (SocketTimeoutException _) {
          // Expected when SO_TIMEOUT is set; continue accepting.
          if (LOG.isDebugEnabled()) LOG.debug("Timeout");
        } catch (IOException ioe1) {
          if (LOG.isDebugEnabled()) LOG.debug("Caught {}", String.valueOf(ioe1));
        }
      }
      notifyStopped();
    }

    private void handleAcceptedClient(Socket clientSocket, InetAddress clientAddress) {
      // Enqueue only when the remote address is permitted and the queue has capacity.
      if (allowedHosts.allowed(clientAddress) && acceptedSockets.size() <= MAX_QUEUE_LENGTH) {
        lock.lock();
        try {
          acceptedSockets.add(clientSocket);
          socketCondition.signalAll();
        } finally {
          lock.unlock();
        }
      } else {
        closeQuietly(clientSocket);
        LOG.info("Denied connection to {}", clientAddress);
      }
    }

    private void closeQuietly(Socket s) {
      try {
        s.close();
      } catch (IOException _) {
        // Best-effort close of a rejected/terminated client socket.
      }
    }

    private void notifyStopped() {
      lock.lock();
      try {
        runningAcceptors--;
        acceptorClosedCondition.signalAll();
      } finally {
        lock.unlock();
      }
    }
  }

  /**
   * Returns the current allow list as a canonicalized string.
   *
   * @return a comma-separated rule list; never {@code null}
   */
  public String getAllowedHosts() {
    return allowedHosts.getAllowedHosts();
  }

  /**
   * Returns whether at least one acceptor is currently bound and running.
   *
   * @return {@code true} if bound; {@code false} otherwise
   */
  public boolean isBound() {
    lock.lock();
    try {
      return !this.acceptors.isEmpty();
    } finally {
      lock.unlock();
    }
  }

  /**
   * Blocks the caller until the interface becomes bound or shutdown begins.
   *
   * <p>Returns immediately if already bound. The method wakes when at least one acceptor has
   * started, when {@link #close()} is called, or when the Wrapper shutdown hook is triggered.
   */
  public void waitBound() {
    lock.lock();
    try {
      if (!acceptors.isEmpty()) return;
      while (true) {
        LOG.error("Network interface isn't bound, waiting");
        boundCondition.awaitUninterruptibly();
        if (!acceptors.isEmpty()) {
          LOG.error("Finished waiting, network interface is now bound");
          return;
        }
        if (shutdown) return;
        if (WrapperManager.hasShutdownHookBeenTriggered()) return;
      }
    } finally {
      lock.unlock();
    }
  }
}
