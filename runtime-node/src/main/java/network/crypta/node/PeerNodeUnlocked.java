package network.crypta.node;

import java.lang.ref.WeakReference;
import network.crypta.io.comm.PeerContext;
import network.crypta.keys.Key;

/**
 * Lightweight view of a {@code PeerNode} exposing operations that do not require acquiring the
 * node's heavier internal locks. This interface is primarily consumed by {@code FailureTableEntry}
 * and similar components that need to query peer state or provide small routing hints without
 * risking lock contention.
 *
 * <p>Implementations should ensure that calls are safe under concurrent access and avoid blocking
 * on long-lived locks. Returned values are snapshots of the underlying peer state and may change
 * immediately after the call.
 */
interface PeerNodeUnlocked {

  /**
   * Returns the peer's current routing location within the network keyspace.
   *
   * @return a coordinate used by the routing layer to compare proximity to keys and peers.
   */
  double getLocation();

  /**
   * Returns an opaque identifier associated with the peer's current runtime instance.
   *
   * <p>The identifier is suitable for equality checks and cache keys. No ordering or persistence
   * guarantees are implied.
   *
   * @return a process-lifetime identifier for the peer.
   */
  long getBootID();

  /**
   * Offers a key to the peer as a lightweight routing or caching hint.
   *
   * <p>Implementations may ignore the hint, enqueue it for later processing, or use it to update
   * local interest state. The call should return promptly and must be safe without holding the main
   * peer lock.
   *
   * @param key the {@link Key} being suggested to the peer; must not be {@code null}.
   */
  void offer(Key key);

  /**
   * Returns a weak reference to the backing peer context.
   *
   * <p>Use a weak reference when storing handles in auxiliary tables to avoid prolonging the
   * lifetime of the underlying peer. The reference may be cleared at any time by the garbage
   * collector.
   *
   * @return a {@link WeakReference} to the underlying {@link PeerContext}.
   */
  WeakReference<PeerContext> getWeakRef();

  /**
   * Returns a concise, human-readable description of the peer intended for logs and metrics.
   *
   * @return a short identifier string; never {@code null}.
   */
  String shortToString();

  /**
   * Indicates whether the peer currently maintains an active connection.
   *
   * @return {@code true} if connected; {@code false} otherwise.
   */
  boolean isConnected();
}
