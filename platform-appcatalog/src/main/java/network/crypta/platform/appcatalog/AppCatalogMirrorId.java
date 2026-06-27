package network.crypta.platform.appcatalog;

import org.jetbrains.annotations.NotNull;

/**
 * Path-safe local identifier for one catalog transport endpoint.
 *
 * <p>Mirror ids are local operational labels, not trust roots. They are used in source-store
 * sidecars, API paths, Web Shell controls, and rollback/audit metadata, so they deliberately reuse
 * the signed-bundle id grammar through {@link AppCatalog#normalizeCatalogId(String)}.
 */
public record AppCatalogMirrorId(String value) {
  /** Stable id reserved for the configured primary catalog source. */
  public static final AppCatalogMirrorId PRIMARY = new AppCatalogMirrorId("primary");

  /**
   * Creates a normalized mirror id.
   *
   * @param value raw mirror id
   * @throws AppCatalogException if the id is not path-safe
   */
  public AppCatalogMirrorId {
    value = AppCatalog.normalizeCatalogId(value);
  }

  /**
   * Parses a caller supplied id.
   *
   * @param value raw id
   * @return normalized mirror id
   */
  public static AppCatalogMirrorId parse(String value) {
    return new AppCatalogMirrorId(value);
  }

  @Override
  public @NotNull String toString() {
    return value;
  }
}
