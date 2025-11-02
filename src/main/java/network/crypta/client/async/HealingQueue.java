package network.crypta.client.async;

import network.crypta.support.api.Bucket;

/**
 * Queue for background healing inserts initiated by the client layer.
 *
 * <p>This interface abstracts a lightweight handoff mechanism used by higher-level components to
 * enqueue data that should be re-inserted into the network for resiliency (for example after a
 * fetch reveals missing or weakly-available blocks). Implementations are expected to persist or
 * otherwise durably stage the queued work according to the surrounding {@link ClientContext},
 * performing the actual insert asynchronously so callers do not block. Typical usage is to pass a
 * {@link Bucket} containing the payload plus cryptographic material required to prepare a CHK and
 * allow the queue to manage scheduling and resource usage.
 *
 * <p>Thread-safety is implementation-defined; callers should assume that method invocations may be
 * concurrent and that the queue may internally synchronize or delegate onto worker executors.
 * Supplied arguments must remain valid until ownership is clearly transferred by the implementation
 * (for example, after the queue has copied or consumed stream content). No guarantees are made
 * about immediate execution order; queues may coalesce, throttle, or reorder tasks to protect node
 * health.
 */
public interface HealingQueue {

  /**
   * Enqueue a payload for asynchronous CHK insertion as part of healing.
   *
   * <p>This method records a unit of work that re-publishes content into the datastore using
   * content-hash keys (CHK). The call should return quickly; the actual encryption, encoding, and
   * network transmission occur later under the queue's control. Implementations may persist the
   * task if the {@link ClientContext} implies durability, or keep it in memory otherwise. Inputs
   * are validated minimally at the boundary; detailed failures surface during background
   * processing. Re-queuing the same payload is typically idempotent at the network layer because
   * CHKs derive from content, but duplicate work may still be scheduled locally.
   *
   * @param data the {@link Bucket} holding the content to insert; must remain readable until the
   *     queue takes ownership or completes a defensive copy; size may be large.
   * @param cryptoKey symmetric key material used for preparing the CHK; byte array length and
   *     format must match the algorithm specified; never {@code null}.
   * @param cryptoAlgorithm identifier of the algorithm/variant for key usage; values map to
   *     implementation-defined constants and must be supported by the queue.
   * @param context operational context with scheduling, persistence, and resource policies; used to
   *     decide durability, priority, and executors for the queued task.
   */
  void queue(Bucket data, byte[] cryptoKey, byte cryptoAlgorithm, ClientContext context);
}
