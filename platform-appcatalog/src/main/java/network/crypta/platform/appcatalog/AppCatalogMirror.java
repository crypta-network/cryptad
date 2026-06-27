package network.crypta.platform.appcatalog;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/**
 * Local transport endpoint for one signed catalog.
 *
 * <p>A catalog always has one primary endpoint. Additional enabled mirror endpoints are tried only
 * after the primary fails. The source URI is validated with the same policy as the primary source,
 * and callers must still verify every fetched catalog before persisting it.
 *
 * @param id local path-safe endpoint id
 * @param role primary or mirror
 * @param source validated catalog source URI
 * @param priority positive ordering value for mirrors
 * @param enabled whether refresh should try this endpoint
 * @param addedAt local timestamp when the endpoint was configured
 */
public record AppCatalogMirror(
    AppCatalogMirrorId id,
    AppCatalogSourceRole role,
    AppCatalogSource source,
    int priority,
    boolean enabled,
    Instant addedAt) {
  /** Priority used for the primary endpoint. */
  public static final int PRIMARY_PRIORITY = 0;

  /**
   * Creates a validated endpoint.
   *
   * @throws AppCatalogException if a mirror priority is not positive, or primary invariants fail
   */
  public AppCatalogMirror {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(role, "role");
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(addedAt, "addedAt");
    if (role == AppCatalogSourceRole.PRIMARY) {
      if (!AppCatalogMirrorId.PRIMARY.equals(id)) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE, "primary source id must be primary");
      }
      priority = PRIMARY_PRIORITY;
      enabled = true;
    } else if (priority <= 0) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "mirror priority must be positive");
    }
  }

  /**
   * Creates the primary endpoint for an existing source record.
   *
   * @param source configured primary source
   * @param addedAt source creation timestamp
   * @return primary endpoint
   */
  public static AppCatalogMirror primary(AppCatalogSource source, Instant addedAt) {
    return new AppCatalogMirror(
        AppCatalogMirrorId.PRIMARY,
        AppCatalogSourceRole.PRIMARY,
        source,
        PRIMARY_PRIORITY,
        true,
        addedAt);
  }

  /**
   * Returns the normalized URI used by the fetcher.
   *
   * @return endpoint source URI
   */
  public URI sourceUri() {
    return source.uri();
  }

  /**
   * Returns the transport family for UI/API status metadata.
   *
   * @return source transport kind
   */
  public AppCatalogSourceKind sourceKind() {
    return source.kind();
  }
}
