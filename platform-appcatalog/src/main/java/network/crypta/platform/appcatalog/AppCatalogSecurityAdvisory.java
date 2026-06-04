package network.crypta.platform.appcatalog;

import java.net.URI;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One bounded security-advisory reference from signed catalog metadata.
 *
 * <p>Catalog entries can carry advisory ids and metadata URIs so operators, release-certification
 * tooling, and Platform API clients can connect a shipped app version with relevant security notes.
 * The id is also embedded in catalog property names, so it is limited to a short token alphabet
 * that remains safe for signed properties and deterministic parser diagnostics.
 *
 * <p>The advisory URI is a metadata reference, not executable policy. It may point at release
 * notes, a vulnerability advisory, or another operator-facing document, but this record does not
 * implement revocation, deny-listing, vulnerability scoring, or automatic remediation. Install and
 * update flows still rely on catalog signatures, artifact digests, signed bundles, trusted review
 * receipts, and app-update policy for enforcement decisions.
 *
 * <p>Instances are immutable and thread-safe. Parsers preserve advisory order at the surrounding
 * {@link AppCatalogProductionMetadata} level while this record validates each individual id and
 * URI.
 *
 * @param id advisory identifier from {@code app.<id>.securityAdvisories}, suitable for use in
 *     matching {@code securityAdvisory.<advisoryId>.uri} property names
 * @param uri safe metadata URI for operator display and release evidence
 */
public record AppCatalogSecurityAdvisory(String id, URI uri) {
  private static final Pattern ADVISORY_ID_PATTERN =
      Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?");
  private static final int MAX_ADVISORY_ID_CHARS = 128;

  /**
   * Creates a validated advisory reference.
   *
   * <p>The constructor trims and validates the advisory id as bounded single-line catalog text,
   * then validates the URI through the same safe metadata policy used by other catalog display
   * links. Equality and hashing therefore operate on normalized values, which lets production
   * metadata deduplicate advisories by id before exposing them through writers or API summaries.
   *
   * @param id bounded advisory id suitable for use in catalog property names
   * @param uri safe metadata URI for operator display and release evidence
   * @throws NullPointerException if the URI is {@code null}
   * @throws AppCatalogException if the id or URI is unsafe for signed catalog metadata
   */
  public AppCatalogSecurityAdvisory {
    id = normalizeId(id, "security advisory id");
    uri =
        AppCatalogSidecars.requireSafeMetadataUri(
            Objects.requireNonNull(uri, "uri"), "security advisory uri");
  }

  /**
   * Normalizes an advisory id from catalog or descriptor input.
   *
   * <p>The normalized value remains case-preserving so publishers can use externally assigned
   * advisory ids such as {@code CRYPTA-2026-0001}, while validation rejects whitespace, path-like
   * separators, and trailing punctuation that would make property keys ambiguous.
   *
   * @param id raw advisory id from a comma-separated advisory list or developer-tool flag
   * @param fieldName field name used in parser or descriptor diagnostics
   * @return normalized advisory id suitable for property-key interpolation
   * @throws AppCatalogException if the id is blank, multi-line, too long, or malformed
   */
  static String normalizeId(String id, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
            id, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, MAX_ADVISORY_ID_CHARS);
    if (!ADVISORY_ID_PATTERN.matcher(normalized).matches()) {
      throw AppCatalogSidecars.invalidEntry("invalid " + fieldName + ": " + normalized);
    }
    return normalized;
  }
}
