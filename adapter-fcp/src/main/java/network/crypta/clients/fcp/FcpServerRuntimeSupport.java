package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.support.api.BucketFactory;

/**
 * Narrow runtime support seam for server-owned FCP infrastructure.
 *
 * <p>This adapter keeps connection handling, persistent request plumbing, and inbound message
 * parsing independent of direct {@code NodeClientCore} access while preserving the current runtime
 * behavior. It exposes only the live client context, persistence-availability check, bucket
 * factories, and secure randomness currently required by the FCP server's infrastructure classes.
 *
 * <p>The seam remains owned by {@code clients.fcp} even though core-backed implementations now live
 * under runtime bootstrap wiring. It is public only, so those runtime-owned adapters can implement
 * it from outside this package. It is not a new shared platform API; callers should add methods
 * only when a later refactoring needs another demonstrably server-infrastructure-specific
 * capability.
 */
public interface FcpServerRuntimeSupport {

  /**
   * Returns the detached runtime context used by server-owned persistent request flows.
   *
   * @return detached runtime context backed by the current live daemon runtime
   */
  PersistentRequestRuntimeContext persistentRequestRuntimeContext();

  /**
   * Queues detached persistent work on the live runtime-owned persistent job runner.
   *
   * @param job detached persistent job to execute
   * @param priority queue priority for the underlying runtime job runner
   * @throws PersistenceDisabledException if persistent storage is unavailable
   */
  void queuePersistentJob(FcpPersistentJob job, int priority) throws PersistenceDisabledException;

  /** Requests an immediate persistence checkpoint from the live runtime. */
  void setCheckpointASAP();

  /**
   * Returns the live client context used for request lifecycle and persistent job work.
   *
   * @return current client context backing the owning FCP server
   */
  ClientContext clientContext();

  /**
   * Reports whether forever-persistent storage is currently unavailable.
   *
   * @return {@code true} when persistent storage has been disabled or torn down
   */
  boolean persistenceDisabled();

  /**
   * Returns the temporary bucket factory used for non-persistent payloads and cache copies.
   *
   * @return temporary bucket factory owned by the current runtime
   */
  BucketFactory tempBucketFactory();

  /**
   * Returns the persistent temporary bucket factory used for forever-persistent inbound payloads.
   *
   * @return persistent bucket factory owned by the current runtime
   */
  BucketFactory persistentTempBucketFactory();

  /**
   * Fills the supplied byte array with secure random data from the owning runtime.
   *
   * @param bytes destination array to populate with secure random bytes
   */
  void fillSecureRandom(byte[] bytes);
}
