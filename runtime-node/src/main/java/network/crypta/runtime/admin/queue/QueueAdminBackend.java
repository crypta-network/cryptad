package network.crypta.runtime.admin.queue;

import network.crypta.runtime.spi.RequestQueueUnavailableException;

/**
 * Defines the runtime-owned backend seam for the remaining legacy queue administration work.
 *
 * <p>This interface keeps runtime-admin detached from protocol-specific queue implementations while
 * the broader queue extraction is still in progress. Callers use it to ask whether queue-backed
 * administration is available, inspect the current global request list, and apply the small set of
 * blocking mutations that the legacy HTTP adapters still expose.
 *
 * <p>The seam is intentionally narrow. It is not a full queue-management API, and it does not try
 * to normalize every backend detail. Instead, it carries only the data and operations that the
 * diagnostics, support, and mutation adapters currently need. Backends may resolve their live
 * implementation lazily, but callers should treat each method as consulting the current queue state
 * rather than a cached snapshot.
 */
public interface QueueAdminBackend {
  /**
   * Reports whether queue-backed administration is currently available.
   *
   * <p>This is a lightweight availability check used by runtime-admin before it renders queue pages
   * or offers queue mutations. Returning {@code false} means callers should treat the queue backend
   * as unavailable for administrative work at this moment, typically because the endpoint is
   * disabled or absent.
   *
   * @return {@code true} when the live queue backend is currently enabled for admin operations
   */
  boolean isEnabled();

  /**
   * Returns the current global request statuses.
   *
   * <p>The returned array is a point-in-time view of the global queue as exposed by the backend.
   * Callers should not assume the contents remain current after the method returns. Implementations
   * may return an empty array when the queue is reachable but has no visible requests.
   *
   * @return runtime-owned status views describing the requests currently visible in the global
   *     queue
   * @throws RequestQueueUnavailableException if the persistent queue exists but cannot be queried
   *     for status information
   */
  QueueRequestStatusView[] getGlobalRequests() throws RequestQueueUnavailableException;

  /**
   * Removes a single global request by identifier.
   *
   * <p>This operation is synchronous from the caller's perspective. Implementations perform the
   * backend mutation before returning so runtime-admin can report deterministic results to the HTTP
   * layer. An identifier that no longer exists is treated as a normal miss rather than a transport
   * failure.
   *
   * @param identifier stable queue identifier for the request that should be removed
   * @return {@code true} when the backend found a matching request and removed it
   * @throws RequestQueueUnavailableException if the persistent queue cannot process the removal
   *     request
   */
  boolean removeGlobalRequestBlocking(String identifier) throws RequestQueueUnavailableException;

  /**
   * Restarts a single global request by identifier.
   *
   * <p>The backend applies the restart immediately and returns only after the request has been
   * handed back to the queue implementation. The {@code disableFilterData} flag is forwarded
   * unchanged so protocol-specific backends can preserve their existing restart semantics.
   *
   * @param identifier stable queue identifier for the request that should be restarted
   * @param disableFilterData whether the restarted request should disable filter-data handling
   * @return {@code true} when the backend found a matching request and restarted it
   * @throws RequestQueueUnavailableException if the persistent queue cannot process the restart
   *     request
   */
  @SuppressWarnings("UnusedReturnValue")
  boolean restartBlocking(String identifier, boolean disableFilterData)
      throws RequestQueueUnavailableException;

  /**
   * Updates the token and priority of a single global request.
   *
   * <p>This method lets runtime-admin apply the small set of existing queue mutations without
   * importing backend-specific request classes. Passing {@code null} for {@code newToken} keeps the
   * current token, while {@code newPriority} is interpreted in the backend's native priority scale.
   *
   * @param identifier stable queue identifier for the request that should be modified
   * @param newToken replacement token, or {@code null} when the current token should be preserved
   * @param newPriority replacement priority value in the backend's native priority scale
   * @return {@code true} when the backend found a matching request and applied the mutation
   * @throws RequestQueueUnavailableException if the persistent queue cannot process the requested
   *     mutation
   */
  @SuppressWarnings("UnusedReturnValue")
  boolean modifyGlobalRequestBlocking(String identifier, String newToken, short newPriority)
      throws RequestQueueUnavailableException;
}
