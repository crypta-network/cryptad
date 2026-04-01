package network.crypta.client.async;

import network.crypta.node.RequestClient;
import network.crypta.support.io.ResumeFailedException;

/**
 * Callback contract for client-side components that initiate and manage requests.
 *
 * <p>Implementations represent higher-level clients such as the FCP bridge, FProxy, or the {@code
 * GlobalPersistentClient}. The node uses this interface to coordinate life‑cycle events for
 * persistent requests and to obtain a stable {@link network.crypta.node.RequestClient} identity for
 * scheduling. Typical usage is to implement this interface on a client object that owns one or more
 * requests and can therefore re‑establish any necessary persistent state after a restart.
 *
 * <p>When the node restarts, {@link #onResume(ClientContext)} is invoked so the client can
 * re-register with the persistence infrastructure (for example, the persistent-request coordinator,
 * persistent temporary buckets, or trackers) before normal processing continues. The returned
 * {@link #getRequestClient()} value is consulted by the schedulers to group related work and apply
 * per‑client limits, persistence, and real‑time flags. Implementations should be lightweight and
 * thread-safe for read access; the scheduler may call {@link #getRequestClient()} frequently.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Re-attach persistent requests and resources after a node restart.
 *   <li>Expose a stable {@link network.crypta.node.RequestClient} describing persistence and
 *       real-time characteristics for scheduling.
 * </ul>
 *
 * @see ClientContext
 * @see network.crypta.node.RequestClient
 */
public interface ClientBaseCallback {

  /**
   * Resumes a persistent request after a node restart.
   *
   * <p>This method is invoked during node recovery so the client can re-register any durable
   * resources and state needed by the request, such as persistent-request coordinator entries,
   * persistent temporary buckets, or file trackers. Implementations should treat repeated calls as
   * safe and avoid expensive work unless required to restore correctness. Heavy I/O or long‑running
   * computations should be minimized to keep the startup responsive.
   *
   * @param context Non-null execution context providing access to schedulers, persistence services,
   *     bucket factories, file trackers, and other services necessary to reattach state.
   * @throws network.crypta.support.io.ResumeFailedException If the persisted state is missing,
   *     incompatible, or corrupt such that the request cannot be safely resumed by this client.
   */
  void onResume(ClientContext context) throws ResumeFailedException;

  /**
   * Returns the scheduling identity for this client.
   *
   * <p>The returned {@link network.crypta.node.RequestClient} describes attributes used by the
   * scheduler to group and prioritize work, including whether requests are persistent and whether
   * they carry the real‑time flag. Implementations must return a stable instance whose properties
   * do not change over the lifetime of the associated requests. The value is read frequently and
   * should be inexpensive to obtain.
   *
   * @return Non-null {@link network.crypta.node.RequestClient} representing this client’s stable
   *     scheduling attributes used for grouping and prioritization.
   */
  RequestClient getRequestClient();
}
