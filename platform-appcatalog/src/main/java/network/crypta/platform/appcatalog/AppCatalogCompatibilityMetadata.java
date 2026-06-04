package network.crypta.platform.appcatalog;

import java.util.Objects;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;

/**
 * Advisory compatibility metadata for a catalog app.
 *
 * <p>This record carries the compatibility hint that a catalog publisher can attach to an app: the
 * minimum and maximum Cryptad build or version labels the publisher expects operators to run plus
 * optional Platform API contract hints. The fields are authenticated by the signed catalog sidecar
 * when present, but they are not trust decisions, and they are not runtime gates. Install and
 * update still depend on catalog signature verification, artifact digest checks, signed-bundle
 * verification, and AppHost validation.
 *
 * <p>Platform API responses compare this value with the local node's comparable version string when
 * the two values can be parsed safely. Integer Cryptad build labels are the preferred comparable
 * form because Cryptad releases are build-numbered. Dotted numeric labels can still be reported for
 * compatibility with early descriptors. Ambiguous values are preserved for display and produce an
 * advisory {@code unknown} status rather than blocking the operator.
 *
 * <p>Instances are immutable. Construction trims present values, rejects blank or multi-line
 * values, and bounds the length so catalog metadata cannot smuggle long free-form review text into
 * the compatibility field.
 *
 * @param minimumCryptaVersion minimum Cryptad build or version label from the catalog publisher, or
 *     {@code null} when the catalog does not declare one
 * @param maximumCryptaVersion maximum Cryptad build or version label from the catalog publisher, or
 *     {@code null} when the catalog does not declare one
 * @param apiCompatibility optional Platform API contract metadata summarized by the catalog
 * @see AppCatalogEntry#compatibility()
 */
public record AppCatalogCompatibilityMetadata(
    String minimumCryptaVersion,
    String maximumCryptaVersion,
    AppApiCompatibilityMetadata apiCompatibility) {
  private static final int MAX_VERSION_CHARS = 96;

  /**
   * Empty compatibility metadata used by catalogs that do not declare a minimum version.
   *
   * <p>This value preserves backward compatibility with the original minimal catalog format. API
   * clients should treat it as {@code not_declared}, not as evidence that every node version was
   * reviewed by the publisher.
   */
  public static final AppCatalogCompatibilityMetadata EMPTY =
      new AppCatalogCompatibilityMetadata(null, null, AppApiCompatibilityMetadata.undeclared());

  /**
   * Creates metadata with only the original Cryptad build/version hint.
   *
   * <p>This overload preserves source compatibility for callers that predate Platform API contract
   * hints in catalog metadata.
   *
   * @param minimumCryptaVersion minimum Cryptad build or version label to display, or {@code null}
   */
  public AppCatalogCompatibilityMetadata(String minimumCryptaVersion) {
    this(minimumCryptaVersion, null, AppApiCompatibilityMetadata.undeclared());
  }

  /**
   * Creates metadata with Cryptad version hints and no Platform API contract hints.
   *
   * @param minimumCryptaVersion minimum Cryptad build or version label to display, or {@code null}
   * @param maximumCryptaVersion maximum Cryptad build or version label to display, or {@code null}
   */
  public AppCatalogCompatibilityMetadata(String minimumCryptaVersion, String maximumCryptaVersion) {
    this(minimumCryptaVersion, maximumCryptaVersion, AppApiCompatibilityMetadata.undeclared());
  }

  /**
   * Creates metadata with the original minimum-version hint plus API compatibility hints.
   *
   * @param minimumCryptaVersion minimum Cryptad build or version label to display, or {@code null}
   * @param apiCompatibility optional Platform API contract metadata summarized by the catalog
   */
  public AppCatalogCompatibilityMetadata(
      String minimumCryptaVersion, AppApiCompatibilityMetadata apiCompatibility) {
    this(minimumCryptaVersion, null, apiCompatibility);
  }

  /**
   * Creates validated compatibility metadata.
   *
   * <p>The constructor validates only the shape of the advisory metadata. It does not parse,
   * compare, or normalize version ordering because comparison depends on the caller's current node
   * version and may remain unavailable for non-numeric publisher labels. A present value is stored
   * after trimming so writers and API responses use the same canonical text.
   *
   * @param minimumCryptaVersion minimum Cryptad build or version label to display, or {@code null}
   * @param maximumCryptaVersion maximum Cryptad build or version label to display, or {@code null}
   * @param apiCompatibility optional Platform API contract metadata summarized by the catalog
   * @throws AppCatalogException if the value is blank, multi-line, or too long
   */
  public AppCatalogCompatibilityMetadata {
    apiCompatibility =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    if (minimumCryptaVersion != null) {
      minimumCryptaVersion =
          AppCatalogSidecars.requireBoundedSingleLine(
              minimumCryptaVersion,
              "minimumCryptaVersion",
              AppCatalogSidecars.INVALID_CATALOG_ENTRY,
              MAX_VERSION_CHARS);
    }
    if (maximumCryptaVersion != null) {
      maximumCryptaVersion =
          AppCatalogSidecars.requireBoundedSingleLine(
              maximumCryptaVersion,
              "maximumCryptaVersion",
              AppCatalogSidecars.INVALID_CATALOG_ENTRY,
              MAX_VERSION_CHARS);
    }
  }
}
