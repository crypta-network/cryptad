package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Last observed refresh-attempt status for a configured signed app catalog source.
 *
 * <p>The value is written to catalog-source metadata and surfaced through the Platform API so the
 * Web Shell can distinguish a healthy source from a source whose most recent refresh failed. It is
 * intentionally about the last attempt, not about catalog trust. A source can report {@link
 * #FAILED} while the previously verified catalog remains installed, listable, and usable.
 *
 * <p>The enum stores a stable lowercase metadata token rather than relying on Java enum names in
 * files. That keeps on-disk metadata and API display text consistent even though Java callers use
 * conventional uppercase constants.
 */
public enum AppCatalogFetchStatus {
  /**
   * The most recent refresh attempt fetched and verified signed catalog sidecars.
   *
   * <p>This status means both catalog bytes and signature bytes passed the normal signed-catalog
   * verification path. It does not make the transport trusted; catalog keys and signatures remain
   * the authority for catalog authenticity.
   */
  SUCCESS("success"),

  /**
   * The most recent refresh attempt failed before replacing the last verified sidecars.
   *
   * <p>This status preserves the distinction between a failed sync and a bad cache. The source may
   * still have a valid prior catalog snapshot, and callers should keep showing that snapshot while
   * also reporting the failed attempt metadata.
   */
  FAILED("failed"),

  /**
   * The endpoint was not attempted during the last refresh pass.
   *
   * <p>This is used for disabled mirrors and mirrors that were not needed because an earlier
   * endpoint produced an accepted verified catalog.
   */
  SKIPPED("skipped"),

  /**
   * The endpoint produced a verified catalog that was older than the current active revision.
   *
   * <p>Stale candidates are not persisted as the active catalog unless an operator executes an
   * explicit rollback to a retained verified revision.
   */
  STALE("stale");

  /** Lowercase token persisted in source metadata and exposed as UI-facing status text. */
  private final String metadataValue;

  /**
   * Creates one status with its stable serialized metadata token.
   *
   * @param metadataValue lowercase token written into {@code catalog-source.properties}
   */
  AppCatalogFetchStatus(String metadataValue) {
    this.metadataValue = metadataValue;
  }

  /**
   * Returns the stable token used in persisted source metadata.
   *
   * @return lowercase value written to and read from catalog-source metadata
   */
  public String metadataValue() {
    return metadataValue;
  }

  /**
   * Parses a persisted fetch-status token.
   *
   * <p>The parser accepts the lowercase metadata values produced by {@link #metadataValue()} and
   * rejects blank, multiline, or unknown values with the same stable catalog-source error used for
   * malformed source metadata. Callers use this when reading source state from disk.
   *
   * @param value persisted {@code source.lastFetchStatus} text to parse
   * @return matching status enum for the persisted metadata token
   */
  static AppCatalogFetchStatus parse(String value) {
    String normalized =
        AppCatalogSidecars.requireNonBlankSingleLine(
                value, "source.lastFetchStatus", AppCatalogSidecars.INVALID_CATALOG_SOURCE)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogFetchStatus status : values()) {
      if (status.metadataValue.equals(normalized)) {
        return status;
      }
    }
    throw new AppCatalogException(
        AppCatalogSidecars.INVALID_CATALOG_SOURCE, "unsupported source.lastFetchStatus: " + value);
  }
}
