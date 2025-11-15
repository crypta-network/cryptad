package network.crypta.clients.fcp;

import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ServerSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks all {@link FCPPluginConnectionImpl} instances that represent in-progress plugin client
 * connections so server plugins can retrieve a {@link UUID}-addressable handle whenever they need
 * to resume a long-running workflow.
 *
 * <p>The tracker sits between {@link ServerSideFCPMessageHandler} implementations and the {@link
 * PluginRespirator}: the latter still creates the connections, but once registered here a server
 * can safely persist only the identifier and later call {@link #getConnection(UUID)} to recover the
 * live channel. Connections are weakly referenced; when the client discards its strong reference,
 * the tracker observes the {@link WeakReference} cleanup and treats the peer as closed, avoiding
 * stale handles while still keeping lookup time logarithmic through the {@link TreeMap} index. The
 * approach is deliberately conservative—no persistence is attempted—because only the client knows
 * when state is safe to discard and because plugins may restart independently of the node.
 *
 * <p>Lifecycle-wise, callers instantiate the tracker early during plugin startup, immediately call
 * {@link #start()} to run the garbage-collection loop, and then invoke {@link
 * #registerConnection(FCPPluginConnectionImpl)} for every client-side channel handed to a server
 * handler. Shutdown requires no action because the supervising thread is a daemon. The class is
 * thread-safe through an internal {@link ReadWriteLock}, so lookups and automatic pruning can run
 * concurrently even under high churn.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> maintain a weak-reference index, expose lookups by ID,
 *       and prune connections whose clients disconnected or crashed.
 *   <li><strong>Threading:</strong> lookups use the read lock while the background thread holds the
 *       write lock for removals; registration holds the write lock briefly.
 *   <li><strong>Constraints:</strong> callers must not leak {@link FCPPluginConnectionImpl}
 *       references to server plugins; they should provide adapters via {@link
 *       FCPPluginConnectionImpl#getDefaultSendDirectionAdapter(SendDirection)} instead.
 * </ul>
 *
 * @see FCPPluginConnection
 * @see PluginRespirator
 * @author xor (xor@freenetproject.org)
 */
final class FCPPluginConnectionTracker extends NativeThread {
  /** Logger dedicated to reporting tracker activity and unexpected shutdown signals. */
  private static final Logger LOG = LoggerFactory.getLogger(FCPPluginConnectionTracker.class);

  /**
   * Backend table of {@link WeakReference}s to known client connections. Monitored by a {@link
   * ReferenceQueue} to automatically remove entries for connections which have been GCed.
   *
   * <p>Not a {@link ConcurrentHashMap} because the creation of connections is exposed to the FCP
   * network interface and thus DoS would be possible: Java HashMaps never shrink.
   */
  private final TreeMap<UUID, ConnectionWeakReference> connectionsByID = new TreeMap<>();

  /**
   * Lock to guard {@link #connectionsByID} against concurrent modification.<br>
   * A {@link ReadWriteLock} because the suspected usage pattern is mostly reads, very few writes -
   * {@link ReadWriteLock} can do that faster than a regular Lock.<br>
   * (A {@link ReentrantReadWriteLock} because that's the only implementation of {@link
   * ReadWriteLock}.)
   */
  private final ReadWriteLock connectionsByIDLock = new ReentrantReadWriteLock();

  /**
   * Queue which monitors nulled weak references in {@link #connectionsByID}.<br>
   * Monitored in {@link #realRun()}.
   */
  private final ReferenceQueue<FCPPluginConnectionImpl> closedConnectionsQueue =
      new ReferenceQueue<>();

  /**
   * Weak reference wrapper that remembers the {@link UUID} belonging to a tracked connection so the
   * enclosing tracker can erase map entries as soon as the referent becomes weakly reachable.
   *
   * <p>The {@link ReferenceQueue}-driven cleanup needs constant-time removal from the {@link
   * #connectionsByID} index. Capturing the identifier on construction avoids an additional lookup
   * or synchronization step when the queue is polled by {@link #realRun()}.
   */
  static final class ConnectionWeakReference extends WeakReference<FCPPluginConnectionImpl> {

    /**
     * Identifier copied from the referent to allow quick removal from {@link #connectionsByID}. The
     * value exactly mirrors {@link FCPPluginConnection#getID()} and never mutates, so log
     * statements and tree-map operations can correlate pruned entries with the plugin state that
     * recorded the identifier originally.
     */
    public final UUID connectionID;

    /**
     * Creates a weak reference for the supplied connection and immediately registers it with the
     * {@link ReferenceQueue} monitored by the background thread.
     *
     * @param referent live connection to monitor; same object retrieved through {@link
     *     #getConnection(UUID)}.
     * @param referenceQueue queue shared by the tracker; receives signal when the referent
     *     vanishes.
     */
    public ConnectionWeakReference(
        FCPPluginConnectionImpl referent, ReferenceQueue<FCPPluginConnectionImpl> referenceQueue) {

      super(referent, referenceQueue);
      connectionID = referent.getID();
    }
  }

  /**
   * Signals that the daemon garbage-collection thread received an interrupt even though it is
   * expected to run until JVM shutdown, allowing callers to preserve the cause.
   */
  private static final class TrackerInterruptedException extends IllegalStateException {
    /**
     * Wraps the original {@link InterruptedException} so logging retains the stack trace and
     * shutdown hooks can differentiate between graceful stops and misconfiguration.
     *
     * @param cause interrupt raised while polling the queue; preserved for diagnostics.
     */
    TrackerInterruptedException(InterruptedException cause) {
      super(
          "Thread interruption requested even though this is a daemon thread!"
              + " Exiting tracker thread.",
          cause);
    }
  }

  /**
   * Registers a newly created client connection so it can later be located by callers that only
   * know its {@link UUID}.
   *
   * <p>Server plugins must invoke this immediately after creating an {@link
   * FCPPluginConnectionImpl}, before handing the instance to {@link
   * ServerSideFCPMessageHandler#handlePluginFCPMessage(FCPPluginConnection, FCPPluginMessage)}. The
   * tracker retains only a {@link WeakReference}, so holding a strong reference remains the
   * client's responsibility. Duplicate registrations are harmless because {@link UUID}s are
   * randomly generated; a later registration simply overwrites the previous weak reference entry.
   * Explicit unregister operations are intentionally omitted because garbage collection provides
   * the correct lifetime semantics.
   *
   * @param connection newly created connection awaiting tracking; caller still retains strong
   *     reference.
   */
  void registerConnection(FCPPluginConnectionImpl connection) {
    connectionsByIDLock.writeLock().lock();
    try {
      // No duplicate checks needed: FCPPluginConnection.getID() is a random UUID.
      connectionsByID.put(
          connection.getID(), new ConnectionWeakReference(connection, closedConnectionsQueue));
    } finally {
      connectionsByIDLock.writeLock().unlock();
    }
  }

  /**
   * Returns the still-live connection whose identifier matches the supplied value so server-side
   * plugins can continue a dialogue that outlived the original handler invocation.
   *
   * <p>Only {@link ServerSideFCPMessageHandler} implementations should invoke this method. Clients
   * must keep their own strong reference via {@link PluginRespirator#connectToOtherPlugin(String,
   * ClientSideFCPMessageHandler)}; the tracker merely provides a lookup table backed by {@link
   * WeakReference}s. If a client stops referencing the {@link FCPPluginConnection}, garbage
   * collection removes it from the tracker and the lookup fails with {@link IOException}. Returned
   * connections should not be handed to untrusted plugin code; instead, wrap them immediately using
   * {@link FCPPluginConnectionImpl#getDefaultSendDirectionAdapter(SendDirection)} so consumers only
   * interact with lightweight direction-specific facades.
   *
   * <pre>{@code
   * var adapter = tracker.getConnection(clientId)
   *     .getDefaultSendDirectionAdapter(SendDirection.TO_CLIENT);
   * adapter.send(message);
   * }</pre>
   *
   * @param connectionID identifier retrieved via {@link FCPPluginConnection#getID()} that the
   *     plugin persisted for future reuse.
   * @return live connection instance; release promptly so garbage collection still detects
   *     disconnects.
   * @throws IOException if the tracker lacks the entry or the client released its reference.
   */
  public FCPPluginConnectionImpl getConnection(UUID connectionID) throws IOException {
    ConnectionWeakReference ref = getConnectionWeakReference(connectionID);

    FCPPluginConnectionImpl connection = ref.get();

    if (connection == null) {
      throw new IOException(
          "Client has closed the connection. " + "Connection ID = " + connectionID);
    }

    return connection;
  }

  /**
   * Provides access to the {@link WeakReference} entry associated with a connection ID so callers
   * can inspect reachability without creating a new strong reference.
   *
   * <p>This helper is primarily for advanced monitoring and should rarely be needed by plugin
   * authors. It mirrors {@link #getConnection(UUID)} but preserves the weak semantics: if the
   * referent has vanished, the returned reference already reports {@code null}, allowing the caller
   * to surface a disconnect without momentarily reviving the object. Obtaining the weak reference
   * still requires a {@link ReadWriteLock#readLock()} acquisition, so it is inexpensive even when
   * performed frequently.
   *
   * @param connectionID identifier registered via {@link
   *     #registerConnection(FCPPluginConnectionImpl)}; stale values signal disconnects.
   * @return weak reference mirroring the tracker entry; clears when the client disconnects.
   * @throws IOException if the identifier was never tracked or garbage collection removed the
   *     entry.
   */
  ConnectionWeakReference getConnectionWeakReference(UUID connectionID) throws IOException {

    connectionsByIDLock.readLock().lock();
    try {
      ConnectionWeakReference ref = connectionsByID.get(connectionID);
      if (ref != null) return ref;
    } finally {
      connectionsByIDLock.readLock().unlock();
    }

    throw new IOException(
        "FCPPluginConnection not found, maybe client has disconnected."
            + " Connection ID: "
            + connectionID);
  }

  /**
   * Creates a tracker configured with the lowest thread priority and daemon status so it runs in
   * the background without preventing JVM shutdown; callers must invoke {@link #start()}.
   */
  public FCPPluginConnectionTracker() {
    super(
        "FCPPluginConnectionTracker Garbage-collector",
        NativeThread.PriorityLevel.MIN_PRIORITY.value,
        true);
    setDaemon(true);
  }

  /**
   * Main loop of the tracker thread that blocks on {@link #closedConnectionsQueue}, removes stale
   * entries from the {@link #connectionsByID} map, and logs anomalies or interrupt requests.
   *
   * <p>Callers never invoke this method directly; {@link NativeThread#start()} arranges for it to
   * run on a dedicated daemon thread. The loop intentionally never terminates, relying on the JVM
   * to stop daemon threads during shutdown. Interrupts are promoted to {@link
   * TrackerInterruptedException} after the interrupt flag is restored so diagnostic tools can
   * capture the root cause. All other exceptions are logged and swallowed to keep the tracker alive
   * even if a plugin sends malformed data.
   */
  @Override
  public void realRun() {
    //noinspection InfiniteLoopStatement
    while (true) {
      try {
        ConnectionWeakReference closedConnection =
            (ConnectionWeakReference) closedConnectionsQueue.remove();

        connectionsByIDLock.writeLock().lock();
        try {
          ConnectionWeakReference removedFromTree =
              connectionsByID.remove(closedConnection.connectionID);

          assert (closedConnection == removedFromTree);
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Garbage-collecting closed connection: remaining connections = {}; connection ID ="
                    + " {}",
                connectionsByID.size(),
                closedConnection.connectionID);
          }
        } finally {
          connectionsByIDLock.writeLock().unlock();
        }
      } catch (InterruptedException e) {
        // We did setDaemon(true), which causes the JVM to exit even if the thread is still
        // running: Daemon threads are force terminated during shutdown.
        // Thus, this thread does not need an exit mechanism, it can be an infinite loop. So
        // nothing should try to terminate it by InterruptedException. If it does happen
        // nevertheless, we honor it by exiting the thread because interrupt requests
        // should never be ignored. Re-set the interrupted flag so callers can observe it and
        // propagate context for debugging.
        Thread.currentThread().interrupt();
        throw new TrackerInterruptedException(e);
      } catch (Exception e) {
        LOG.error("Error in thread {}", getName(), e);
      }
    }
  }
}
