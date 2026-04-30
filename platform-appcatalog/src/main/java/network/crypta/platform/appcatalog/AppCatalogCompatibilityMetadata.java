package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Advisory compatibility metadata for a catalog app.
 *
 * <p>This record carries the compatibility hint that a catalog publisher can attach to an app: the
 * minimum Cryptad build or version label the publisher expects operators to run. The field is
 * authenticated by the signed catalog sidecar when present, but it is not a trust decision, and it
 * is not a runtime gate. Install and update still depend on catalog signature verification,
 * artifact digest checks, signed-bundle verification, and AppHost validation.
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
 * @param minimumCryptaVersion optional minimum Cryptad build or version label from the catalog
 *     publisher
 * @see AppCatalogEntry#compatibility()
 */
public record AppCatalogCompatibilityMetadata(Optional<String> minimumCryptaVersion) {
  private static final int MAX_VERSION_CHARS = 96;

  /**
   * Empty compatibility metadata used by catalogs that do not declare a minimum version.
   *
   * <p>This value preserves backward compatibility with the original minimal catalog format. API
   * clients should treat it as {@code not_declared}, not as evidence that every node version was
   * reviewed by the publisher.
   */
  public static final AppCatalogCompatibilityMetadata EMPTY =
      new AppCatalogCompatibilityMetadata(Optional.empty());

  /**
   * Creates validated compatibility metadata.
   *
   * <p>The constructor validates only the shape of the advisory metadata. It does not parse,
   * compare, or normalize version ordering because comparison depends on the caller's current node
   * version and may remain unavailable for non-numeric publisher labels. A present value is stored
   * after trimming so writers and API responses use the same canonical text.
   *
   * @param minimumCryptaVersion optional minimum Cryptad build or version label to display
   * @throws NullPointerException if the optional wrapper is {@code null}
   * @throws AppCatalogException if the value is blank, multi-line, or too long
   */
  public AppCatalogCompatibilityMetadata {
    Objects.requireNonNull(minimumCryptaVersion, "minimumCryptaVersion");
    minimumCryptaVersion =
        minimumCryptaVersion.map(
            rawVersion ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    rawVersion,
                    "minimumCryptaVersion",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_VERSION_CHARS));
  }
}
