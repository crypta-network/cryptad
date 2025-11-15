package network.crypta.clients.fcp;

import java.util.TreeMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.pluginmanager.PluginNotFoundException;

/**
 * Coordinates cached {@link FCPPluginConnection} instances per server plugin so a connection
 * handler does not thrash the server with redundant bridges. The registry lives inside {@link
 * FCPConnectionHandler} and brokers requests from the inbound FCP stream, ensuring each plugin name
 * resolves to one reusable {@link FCPPluginConnectionImpl} until the underlying server reports
 * itself as dead. A striped read/write lock guards the internal {@link TreeMap} so the common fast
 * path (reading an already healthy entry) avoids writer contention while the less frequent creation
 * path performs serialized maintenance.
 *
 * <p>Clients typically call {@link #get(String, FCPServer, FCPConnectionHandler)} every time they
 * need a connection, even during bursts, trusting the registry to hand back a stable object or
 * transparently rebuild it. The registry never proactively prunes entries; it removes them only
 * when the {@link FCPPluginConnectionImpl#isServerDead()} signal indicates the server side cannot
 * be reused. All returned references therefore stay valid until the owning handler closes or the
 * server plugin becomes unreachable, at which point the caller must request another instance.
 *
 * <ul>
 *   <li>Maintains a monotonically growing map keyed by canonical plugin name.
 *   <li>Enforces single-writer semantics whenever the server must allocate a new bridge.
 *   <li>Guarantees that concurrent readers always either reuse a healthy connection or block until
 *       a replacement is published.
 * </ul>
 *
 * @see FCPServer#createFCPPluginConnectionForNetworkedFCP(String, FCPConnectionHandler)
 */
final class PluginConnectionRegistry {
  private final TreeMap<String, FCPPluginConnectionImpl> connections = new TreeMap<>();
  private final ReadWriteLock lock = new ReentrantReadWriteLock();

  /**
   * Creates an empty registry scoped to a single {@link FCPConnectionHandler} instance so the
   * handler can manage per-plugin bridges without sharing mutable state globally.
   */
  PluginConnectionRegistry() {
    // Intentionally empty; field declarations already set up the map and lock.
  }

  /**
   * Looks up the connection for {@code serverPluginName}, creating and caching one if necessary,
   * while coordinating concurrent callers via an internal read/write lock.
   *
   * <p>The method first attempts a non-blocking read to keep the hot path inexpensive; if no
   * healthy entry exists it escalates to the write lock, double-checks the map, and then asks the
   * {@link FCPServer} to build a fresh {@link FCPPluginConnectionImpl}. Dead entries are purged
   * lazily. Callers should expect {@link PluginNotFoundException} if the server refuses to build a
   * bridge, and they must retry later once the plugin becomes available again.
   *
   * <pre>{@code
   * FCPPluginConnection connection =
   *     registry.get("ContentPlugin", server, handler);
   * connection.send(...);
   * }</pre>
   *
   * @param serverPluginName canonical plugin identifier, case-sensitive, never {@code null}.
   * @param server owning {@link FCPServer} that can mint new bridges when cache misses occur.
   * @param handler connection handler that will receive inbound client traffic for this bridge.
   * @return cached connection when alive, otherwise the freshly created replacement instance.
   * @throws PluginNotFoundException when the requested plugin is absent or declined by the server.
   */
  FCPPluginConnection get(String serverPluginName, FCPServer server, FCPConnectionHandler handler)
      throws PluginNotFoundException {
    lock.readLock().lock();
    try {
      FCPPluginConnectionImpl existing = connections.get(serverPluginName);
      if (existing != null && !existing.isServerDead()) {
        return existing;
      }
    } finally {
      lock.readLock().unlock();
    }

    lock.writeLock().lock();
    try {
      FCPPluginConnectionImpl oldConnection = connections.get(serverPluginName);
      if (oldConnection != null) {
        if (!oldConnection.isServerDead()) {
          return oldConnection;
        } else {
          connections.remove(serverPluginName);
        }
      }

      FCPPluginConnectionImpl newConnection =
          server.createFCPPluginConnectionForNetworkedFCP(serverPluginName, handler);
      connections.put(serverPluginName, newConnection);
      return newConnection;
    } finally {
      lock.writeLock().unlock();
    }
  }
}
