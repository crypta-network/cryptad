package network.crypta.platform.appcatalog;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/**
 * Optional changelog metadata displayed before app install or update.
 *
 * <p>A catalog entry may use this value to attach release information to the exact bundle version
 * advertised by the signed catalog. The metadata is intentionally small: a single-line summary for
 * card/detail views and an optional URI for longer release notes hosted by the publisher. Catalog
 * verification authenticates that the publisher supplied these fields, but the fields remain
 * advisory operator-facing text. They do not affect artifact download policy, bundle signature
 * verification, install eligibility, or update ordering.
 *
 * <p>Instances are immutable and normalize their input during construction. Text is trimmed,
 * bounded, and rejected if it spans multiple lines. The URI uses the catalog metadata URI policy,
 * which permits HTTPS and loopback HTTP while rejecting fragments, user-info, local files, and
 * arbitrary remote HTTP. The Web Shell can therefore render a link without turning the shell into a
 * remote asset fetcher.
 *
 * @param summary optional single-line change summary for the catalog version
 * @param uri optional public URI with detailed release notes for operators
 * @see AppCatalogEntry#changelog()
 * @see AppCatalogWriter#serialize(AppCatalog)
 */
public record AppCatalogChangelog(Optional<String> summary, Optional<URI> uri) {
  private static final int MAX_CHANGELOG_SUMMARY_CHARS = 512;

  /**
   * Empty changelog metadata used by catalogs that do not declare release text.
   *
   * <p>Writers use this value when older descriptor files omit changelog properties. API responses
   * still expose a stable changelog object, but both fields serialize as absent or {@code null}.
   */
  public static final AppCatalogChangelog EMPTY =
      new AppCatalogChangelog(Optional.empty(), Optional.empty());

  /**
   * Creates validated changelog metadata.
   *
   * <p>The constructor performs all validation required by signed-catalog parsing and descriptor
   * authoring. An absent summary or URI is valid, which keeps existing minimal catalogs compatible.
   * A present summary must fit the display bound after trimming. A present URI must be safe
   * metadata, not a fetchable artifact URI; catalog installers still rely only on bundle digest and
   * signed-bundle verification.
   *
   * @param summary optional short summary associated with this catalog entry version
   * @param uri optional HTTPS or loopback HTTP URI for longer release notes
   * @throws NullPointerException if either optional wrapper is {@code null}
   * @throws AppCatalogException if text is blank or multi-line, or URI metadata is unsafe
   */
  public AppCatalogChangelog {
    Objects.requireNonNull(summary, "summary");
    Objects.requireNonNull(uri, "uri");
    summary =
        summary.map(
            rawSummary ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    rawSummary,
                    "changelog.summary",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_CHANGELOG_SUMMARY_CHARS));
    uri = uri.map(rawUri -> AppCatalogSidecars.requireSafeMetadataUri(rawUri, "changelog.uri"));
  }

  /**
   * Returns whether the catalog omits all changelog metadata.
   *
   * <p>This helper lets writers decide whether a descriptor produced any changelog fields without
   * inspecting the individual optionals at each call site. A summary-only or URI-only value is not
   * empty; both shapes are valid for metadata-capable catalogs.
   *
   * @return {@code true} when both optional changelog fields are absent
   */
  public boolean isEmpty() {
    return summary.isEmpty() && uri.isEmpty();
  }
}
