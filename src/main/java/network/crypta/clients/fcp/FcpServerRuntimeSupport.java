package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.PersistentTempBucketFactory;

/**
 * Narrow runtime support seam for server-owned FCP infrastructure.
 *
 * <p>This package-local adapter keeps connection handling, persistent request plumbing, and inbound
 * message parsing independent of direct {@code NodeClientCore} access while preserving the current
 * runtime behavior. It exposes only the live client context, persistence-availability check, bucket
 * factories, and secure randomness currently required by the FCP server's infrastructure classes.
 *
 * <p>The seam is intentionally local to {@code clients.fcp}. It is not a new shared platform API;
 * callers should add methods only when a later refactoring needs another demonstrably
 * server-infrastructure-specific capability.
 */
interface FcpServerRuntimeSupport {

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
   * @return persistent temporary bucket factory owned by the current runtime
   */
  PersistentTempBucketFactory persistentTempBucketFactory();

  /**
   * Fills the supplied byte array with secure random data from the owning runtime.
   *
   * @param bytes destination array to populate with secure random bytes
   */
  void fillSecureRandom(byte[] bytes);
}
