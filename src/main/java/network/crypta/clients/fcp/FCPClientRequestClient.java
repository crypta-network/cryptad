package network.crypta.clients.fcp;

import network.crypta.node.RequestClient;

/**
 * Wraps a {@link PersistentRequestClient} so it participates in the {@link RequestClient} API used
 * by the node scheduling layer.
 *
 * <p>This adapter exists so the FCP layer can expose a stable, allocation-free identity that the
 * request scheduler understands, while still allowing the {@link PersistentRequestClient} to manage
 * network-linked state such as retries, progress listeners, or persistence metadata. Instances are
 * lightweight and effectively immutable once created; callers are encouraged to keep a single
 * instance per logical FCP client request and pass it to all queueing or retry operations. The
 * adapter communicates two key pieces of metadata: whether the request should be persisted across
 * node restarts and whether it should be treated as latency-sensitive real-time work. Neither flag
 * changes after construction, which keeps interactions predictable even when the underlying FCP
 * client mutates. The class is thread-safe for concurrent reads because it only holds final fields
 * and does not expose mutators. Consumers should still ensure that the wrapped {@link
 * PersistentRequestClient} can tolerate concurrent use if they share it across threads.
 *
 * <p>Typical usage involves constructing this adapter immediately before submitting a request via
 * an FCP command handler, then reusing it whenever the node needs to inspect persistence or
 * real-time preferences.
 */
public class FCPClientRequestClient implements RequestClient {

  /**
   * Reference to the FCP-facing client that originated the work; retained so callbacks can be
   * routed without reallocation. The reference is never null and should remain valid for the
   * lifetime of the adapter instance.
   */
  public final PersistentRequestClient client;

  /**
   * Indicates whether the originating client requested that its job survive node restarts. When
   * {@code true}, the scheduler may write additional metadata so the job can be replayed after
   * recovery, which can increase disk churn compared to ephemeral jobs.
   */
  public final boolean forever;

  /**
   * Stores the caller's expressed preference for real-time handling. A {@code true} value requests
   * low-latency routing even if it consumes more bandwidth, while {@code false} allows batch-style
   * handling focused on throughput and resource efficiency.
   */
  public final boolean realTimePreference;

  /**
   * Creates an adapter that links an existing {@link PersistentRequestClient} with persistence and
   * real-time metadata.
   *
   * <p>The constructor performs no defensive copies and trusts the caller to provide lifecycle-safe
   * collaborators. All parameters are required, and their values remain visible through the public
   * fields and query methods for the entire lifetime of the adapter.
   *
   * @param fcpClient underlying FCP-side client handle that will receive callbacks; must not be
   *     {@code null} and is expected to remain alive for the duration of the request.
   * @param forever2 set to {@code true} if the node should persist the request across restarts;
   *     {@code false} keeps the request ephemeral and eligible for early cleanup.
   * @param realTime flag indicating whether scheduling should favor latency over throughput; when
   *     {@code true}, the request may consume higher priority resources.
   */
  public FCPClientRequestClient(
      PersistentRequestClient fcpClient, boolean forever2, boolean realTime) {
    this.client = fcpClient;
    this.forever = forever2;
    this.realTimePreference = realTime;
  }

  /**
   * Reports whether this request should be treated as persistent work that survives a node restart.
   *
   * <p>The value mirrors the {@code forever2} flag supplied during construction and therefore
   * remains stable for the lifetime of the adapter. Schedulers can rely on this method to decide
   * whether to capture restart metadata, commit disk state, or include the job in recovery queues.
   *
   * @return {@code true} when persistence was requested and the node should save state; otherwise
   *     {@code false} to allow transient handling that discards state once complete.
   */
  @Override
  public boolean persistent() {
    return forever;
  }

  /**
   * Indicates whether the caller prefers real-time scheduling semantics for this request.
   *
   * <p>The value is a simple hint; downstream components may still downgrade the priority if
   * resources are constrained. Callers can use this signal to differentiate latency-sensitive user
   * flows from batch backfills. The setting is immutable and aligns with the {@code realTime}
   * argument passed to the constructor.
   *
   * @return {@code true} when the request should target low latency despite potential overhead;
   *     {@code false} when throughput-oriented bulk handling is acceptable.
   */
  @Override
  public boolean realTimeFlag() {
    return realTimePreference;
  }
}
