package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.Semaphore;

/**
 * Coordinates catalog mutations with authorizations retained through an AppHost commit.
 *
 * <p>Ordinary catalog and trust mutations acquire every permit from a fair semaphore. Install and
 * rollback paths acquire one permit to verify an exact catalog subject and retain that decision
 * until the caller closes the returned authorization. A failed authorization releases its permit
 * before propagating the failure; a successful authorization transfers sole release responsibility
 * to the returned lease. This keeps the unusual cross-method fence lifetime out of the catalog
 * orchestration class and makes that ownership explicit.
 */
final class CatalogMutationFence {
  /** Complete permit count acquired by an exclusive mutation. */
  private static final int MUTATION_PERMITS = Integer.MAX_VALUE;

  /** Fair permit fence that orders retained authorizations ahead of exclusive mutations. */
  private final Semaphore fence = new Semaphore(MUTATION_PERMITS, true);

  /** Single-use authorization backed by one retained fence permit. */
  private static final class PermitAuthorization
      implements AppCatalogManager.CatalogTrustAuthorization {
    /** Fence receiving the retained permit when the authorization closes. */
    private final Semaphore fence;

    /** Whether this single-use authorization has already been released. */
    private boolean closed;

    /** Creates an authorization for one permit already acquired from {@code fence}. */
    private PermitAuthorization(Semaphore fence) {
      this.fence = Objects.requireNonNull(fence, "fence");
    }

    @Override
    public synchronized void close() {
      if (closed) {
        throw new IllegalStateException("catalog authorization lease is already closed");
      }
      closed = true;
      fence.release();
    }
  }

  /** Creates an independent fair fence for one catalog manager. */
  CatalogMutationFence() {
    // The semaphore is initialized with the instance and carries no external configuration.
  }

  /**
   * One catalog operation that may propagate a filesystem or trust-store failure.
   *
   * @param <T> operation result type
   */
  @FunctionalInterface
  interface IoOperation<T> {
    /**
     * Performs the operation while the caller owns the appropriate fence side.
     *
     * @return operation result transferred to the caller
     * @throws IOException if catalog persistence or verification fails
     */
    T run() throws IOException;
  }

  /** One catalog mutation that returns no result. */
  @FunctionalInterface
  interface IoAction {
    /**
     * Performs the mutation while the caller owns the exclusive fence.
     *
     * @throws IOException if catalog persistence fails
     */
    void run() throws IOException;
  }

  /**
   * Result produced under the shared fence plus the authorization that retains it.
   *
   * @param value non-null value produced by exact authorization
   * @param authorization lease that releases the retained shared permit
   * @param <T> authorized result type
   */
  record Authorized<T>(T value, AppCatalogManager.CatalogTrustAuthorization authorization) {
    /** Validates that both the authorized result and its lease are present. */
    Authorized {
      Objects.requireNonNull(value, "value");
      Objects.requireNonNull(authorization, "authorization");
    }
  }

  /**
   * Runs one exact authorization and retains a shared permit on success.
   *
   * @param operation authorization operation to execute
   * @param <T> authorized result type
   * @return result and lease whose close operation releases the shared permit
   * @throws IOException if authorization cannot read or verify its catalog state
   */
  <T> Authorized<T> authorizeRead(IoOperation<T> operation) throws IOException {
    fence.acquireUninterruptibly();
    AppCatalogManager.CatalogTrustAuthorization authorization = new PermitAuthorization(fence);
    boolean retained = false;
    try {
      T value = Objects.requireNonNull(operation, "operation").run();
      Authorized<T> authorized = new Authorized<>(value, authorization);
      retained = true;
      return authorized;
    } finally {
      if (!retained) {
        authorization.close();
      }
    }
  }

  /**
   * Runs one catalog mutation under the exclusive write fence.
   *
   * @param operation mutation to execute exclusively
   * @param <T> mutation result type
   * @return exact result produced by the mutation
   * @throws IOException if catalog persistence or verification fails
   */
  <T> T withWriteLock(IoOperation<T> operation) throws IOException {
    fence.acquireUninterruptibly(MUTATION_PERMITS);
    try {
      return Objects.requireNonNull(operation, "operation").run();
    } finally {
      fence.release(MUTATION_PERMITS);
    }
  }

  /**
   * Runs one result-free catalog mutation under the exclusive write fence.
   *
   * @param action mutation to execute exclusively
   * @throws IOException if catalog persistence fails
   */
  void withWriteLock(IoAction action) throws IOException {
    fence.acquireUninterruptibly(MUTATION_PERMITS);
    try {
      Objects.requireNonNull(action, "action").run();
    } finally {
      fence.release(MUTATION_PERMITS);
    }
  }
}
