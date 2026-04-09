package network.crypta.client.async.persistence;

import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.io.ResumeFailedException;

/**
 * Minimal durable-request contract used by {@code ClientLayerPersister}.
 *
 * <p>Implementations expose only the lifecycle and recovery operations that the client-layer
 * persister needs to save and restore durable requests. The contract is deliberately narrower than
 * any endpoint-specific request API: it does not expose protocol messages, request queues, or UI
 * state. That keeps persistence control flow in {@code network.crypta.client.async} while letting
 * runtime-owned adapters decide how a concrete request is enumerated, resumed, canceled, or
 * restarted.
 *
 * <p>A typical lifecycle is: list handles from {@link PersistentRequestCatalog}, write their
 * identifiers and recovery data during a checkpoint, deserialize or rebuild them during startup,
 * invoke {@link #onResume(PersistentRequestRuntimeContext)}, and then call {@link
 * #start(PersistentRequestRuntimeContext)} when the restored request should continue running.
 * Implementations should remain robust when these hooks are invoked after partial failures or
 * repeated startup attempts.
 */
public interface PersistentRequestHandle {

  /**
   * Returns the stable identifier used for duplicate detection and recovery.
   *
   * <p>The returned identifier must remain stable for the lifetime of the durable request and must
   * use the same queue and request-type semantics that the runtime expects during restart. The
   * persister writes it ahead of any serialized state so the startup can avoid rebuilding requests
   * that are already present.
   *
   * @return immutable persistent-request identifier for this durable request instance
   */
  PersistentRequestIdentifier getPersistentRequestIdentifier();

  /**
   * Reattaches this request to the live runtime context after deserialization or restart.
   *
   * <p>This hook gives the implementation a chance to recreate transient collaborators, reconnect
   * to schedulers, and re-register itself with runtime-owned request registries before further work
   * resumes. It may be invoked after either Java deserialization or compact recovery-data
   * reconstruction.
   *
   * @param context client-owned runtime context seam that supplies whatever runtime services the
   *     implementation needs during resume
   * @throws ResumeFailedException if the request cannot be safely reattached to the running node
   */
  void onResume(PersistentRequestRuntimeContext context) throws ResumeFailedException;

  /**
   * Starts the request after successful recovery.
   *
   * <p>Implementations are responsible for creating the underlying work item, scheduling it on the
   * appropriate queues, and updating any status caches. This method may be called again after a
   * restart request but should avoid duplicating work when already running.
   *
   * @param context client-owned runtime context seam used to schedule the request and attach any
   *     new work to the node
   */
  void start(PersistentRequestRuntimeContext context);

  /**
   * Cancels the request after a failed resuming or restart.
   *
   * <p>The persister calls this after a restore path has failed badly enough that the partially
   * reconstructed request should not remain registered. Implementations should release runtime
   * resources and propagate cancellation to any underlying requester when one exists.
   *
   * @param context client-owned runtime context seam used to propagate cancellation and release
   *     resources
   */
  void cancel(PersistentRequestRuntimeContext context);

  /**
   * Gives the request one final chance to flush state before persistence during shutdown.
   *
   * <p>This hook runs only on shutdown-triggered checkpoints. Implementations can use it to push
   * transient state into fields that are persisted normally, or to ask nested requesters to flush
   * state that improves restart quality.
   *
   * @param context client-owned runtime context seam available during the node shutdown save path
   */
  void onShutdown(PersistentRequestRuntimeContext context);

  /**
   * Writes compact recovery data that can rebuild the request when Java serialization fails.
   *
   * <p>The record written here should contain only the minimum durable information needed to
   * reconstruct or restart the request when the regular serialized form cannot be read. The
   * persister wraps this stream with length framing and checksums, so implementations should focus
   * on request-specific payload layout rather than outer framing.
   *
   * @param dos destination stream for the request-specific recovery payload
   * @param checker checksum helper supplied by the persistence layer for request-specific restart
   *     logic
   * @throws IOException if the request cannot write its recovery payload to the supplied stream
   */
  void writeRecoveryData(DataOutputStream dos, ChecksumChecker checker) throws IOException;

  /**
   * Returns whether recovery restored the request fully without restarting underlying work.
   *
   * <p>Implementations can use this to distinguish fast resumes that reused on-disk state from
   * slower fallback paths that reconstructed work from compact recovery data.
   *
   * @return {@code true} when the request resumed fully from stored state without a restart-style
   *     rebuild
   */
  boolean fullyResumed();
}
