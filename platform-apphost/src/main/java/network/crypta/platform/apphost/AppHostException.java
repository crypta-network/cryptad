package network.crypta.platform.apphost;

import java.io.IOException;

/**
 * Signals AppHost validation or lifecycle failures.
 *
 * <p>{@code AppHostException} is the checked failure type used for host-specific problems such as
 * invalid manifests, unsafe filesystem layouts, startup failures, and shutdown timeouts.
 * Implementations throw this exception when the failure is part of the AppHost contract rather than
 * an unexpected unchecked programming error.
 *
 * <p>The type extends {@link IOException} so callers that already treat filesystem and process
 * lifecycle work as checked I/O can handle AppHost failures in the same control flow while still
 * distinguishing them by concrete type when needed.
 */
public class AppHostException extends IOException {
  /** Signals that an AppHost cannot coordinate catalog provenance with bundle mutations. */
  public static final class CatalogOriginPersistenceUnsupportedException extends AppHostException {
    /** Creates the bounded unsupported-capability failure. */
    public CatalogOriginPersistenceUnsupportedException() {
      super("coordinated catalog origin persistence is not supported by this AppHost");
    }
  }

  /**
   * Signals that a conditional catalog update observed a different current provenance revision.
   *
   * <p>Callers should require a fresh source-switch preview instead of retrying the stale
   * transition. The exception is intentionally typed so operator APIs can return a bounded conflict
   * without parsing diagnostic text.
   */
  public static final class CatalogOriginChangedException extends AppHostException {
    /** Creates the stale-origin failure. */
    public CatalogOriginChangedException() {
      super("installed catalog origin changed before the update committed");
    }
  }

  /** Signals that current local federation policy rejected a retained catalog rollback origin. */
  public static final class CatalogRollbackAuthorizationException extends AppHostException {
    /** Creates a bounded authorization failure without exposing local policy storage details. */
    public CatalogRollbackAuthorizationException() {
      super("catalog rollback origin is not authorized by current local trust policy");
    }

    /** Creates a bounded authorization failure while retaining its private diagnostic cause. */
    public CatalogRollbackAuthorizationException(Throwable cause) {
      super("catalog rollback origin is not authorized by current local trust policy", cause);
    }
  }

  /**
   * Creates an exception with a message.
   *
   * @param message human-readable failure detail that explains the rejected operation or invalid
   *     state
   */
  public AppHostException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a message and cause.
   *
   * @param message human-readable failure detail that explains the rejected operation or invalid
   *     state
   * @param cause underlying cause that triggered this host-level failure classification
   */
  public AppHostException(String message, Throwable cause) {
    super(message, cause);
  }
}
