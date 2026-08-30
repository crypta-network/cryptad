package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Coordinates catalog mutations with authorizations retained through an AppHost commit.
 *
 * <p>Ordinary catalog and trust mutations run under the write side of a fair read-write lock.
 * Install and rollback paths use the read side to verify an exact catalog subject and retain that
 * decision until the caller closes the returned authorization. A failed authorization releases the
 * read lock before propagating the failure; a successful authorization transfers sole release
 * responsibility to the returned lease. This keeps the unusual cross-method lock lifetime out of
 * the catalog orchestration class and makes that ownership explicit.
 */
final class CatalogMutationFence {
  /** Fair lock that orders retained authorizations ahead of later exclusive mutations. */
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

  /** Creates an independent fair fence for one catalog manager. */
  CatalogMutationFence() {
    // The lock is initialized with the instance and carries no external configuration.
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

  /**
   * Result produced under the read fence plus the authorization that retains it.
   *
   * @param value non-null value produced by exact authorization
   * @param authorization lease that releases the retained read fence
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
   * Runs one exact authorization and retains the read fence on success.
   *
   * @param operation authorization operation to execute
   * @param <T> authorized result type
   * @return result and lease whose close operation releases the read fence
   * @throws IOException if authorization cannot read or verify its catalog state
   */
  <T> Authorized<T> authorizeRead(IoOperation<T> operation) throws IOException {
    ReentrantReadWriteLock.ReadLock readLock = lock.readLock();
    readLock.lock();
    try {
      T value = Objects.requireNonNull(operation, "operation").run();
      return new Authorized<>(value, readLock::unlock);
    } catch (IOException | RuntimeException | Error failure) {
      readLock.unlock();
      throw failure;
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
    ReentrantReadWriteLock.WriteLock writeLock = lock.writeLock();
    writeLock.lock();
    try {
      return Objects.requireNonNull(operation, "operation").run();
    } finally {
      writeLock.unlock();
    }
  }
}
