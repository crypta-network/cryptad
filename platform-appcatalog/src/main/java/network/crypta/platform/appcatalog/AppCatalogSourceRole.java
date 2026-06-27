package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Local transport role for a configured catalog endpoint.
 *
 * <p>The role controls refresh ordering only. A mirror is never a catalog trust authority; every
 * fetched candidate still has to pass signed-catalog verification and catalog-id matching.
 */
public enum AppCatalogSourceRole {
  /** Operator-configured primary catalog source. */
  PRIMARY("primary"),

  /** Operator-configured fallback transport source. */
  MIRROR("mirror");

  private final String metadataValue;

  AppCatalogSourceRole(String metadataValue) {
    this.metadataValue = metadataValue;
  }

  /**
   * Returns the stable metadata token.
   *
   * @return lowercase role token
   */
  public String metadataValue() {
    return metadataValue;
  }

  /**
   * Parses a persisted role token.
   *
   * @param value raw role token
   * @return matching role
   */
  static AppCatalogSourceRole parse(String value) {
    String normalized =
        AppCatalogSidecars.requireNonBlankSingleLine(
                value, "mirror.role", AppCatalogSidecars.INVALID_CATALOG_SOURCE)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogSourceRole role : values()) {
      if (role.metadataValue.equals(normalized)) {
        return role;
      }
    }
    throw new AppCatalogException(
        AppCatalogSidecars.INVALID_CATALOG_SOURCE, "unsupported mirror.role: " + value);
  }
}
