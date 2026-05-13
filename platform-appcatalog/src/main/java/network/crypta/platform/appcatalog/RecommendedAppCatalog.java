package network.crypta.platform.appcatalog;

import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Describes one operator-facing catalog recommendation without configuring it.
 *
 * <p>The model is intentionally separate from {@link AppCatalogSourceStore}. A recommended catalog
 * is an onboarding hint shown by the API and Web Shell; it becomes a configured catalog only after
 * an operator explicitly adds it and the normal signed-catalog verification path succeeds. This
 * keeps recommendation metadata out of the verified source store and avoids treating a default card
 * as trust by itself.
 *
 * <p>The descriptor is immutable after construction. It is safe to share between request handlers,
 * Web Shell bootstrap code, and release-certification checks because it contains only normalized
 * strings and an optional {@link AppCatalogSource}. It does not open files, fetch Crypta content,
 * inspect trusted-key stores, or cache mutable runtime state.
 *
 * <p>The optional source is parsed with the same policy as manual catalog sources, so unsupported
 * schemes fail early. The trusted key and reviewer policy fields are identifiers or short hints,
 * not key material. Runtime/API layers may use them to report configuration readiness, but catalog
 * signatures, bundle signatures, review receipts, digest checks, sandbox checks, permission review,
 * and API compatibility checks remain separate install/update gates.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>A missing source is represented as {@link Optional#empty()}, not as a placeholder URI.
 *   <li>The {@code channel} value is normalized to lowercase for stable JSON output.
 *   <li>Display APIs should redact {@link #sourceDisplayUri()} before exposing local paths or
 *       Crypta keys outside trusted operator surfaces.
 * </ul>
 *
 * @param catalogId normalized catalog id expected after signed-catalog verification succeeds
 * @param name short display name shown to node operators in onboarding surfaces
 * @param description short description of the catalog's purpose, ownership, and release channel
 * @param channel release channel label such as {@code beta}, normalized to lowercase
 * @param source optional configured catalog source for the recommendation add flow
 * @param trustedCatalogKeyId optional trusted catalog signing key id hint, never key material
 * @param reviewerPolicyHint optional short reviewer policy hint for display and release evidence
 * @see RecommendedAppCatalogs
 * @see AppCatalogManager#addSource(String, String)
 */
public record RecommendedAppCatalog(
    String catalogId,
    String name,
    String description,
    String channel,
    Optional<AppCatalogSource> source,
    Optional<String> trustedCatalogKeyId,
    Optional<String> reviewerPolicyHint) {
  private static final int MAX_NAME_CHARS = 128;
  private static final int MAX_DESCRIPTION_CHARS = 512;
  private static final int MAX_CHANNEL_CHARS = 64;
  private static final int MAX_HINT_CHARS = 128;

  /**
   * Creates a normalized recommendation descriptor.
   *
   * <p>The constructor validates only display and configuration metadata. It does not fetch catalog
   * bytes, read trusted keys, or mutate local source state. Callers that add a recommendation must
   * still call {@link AppCatalogManager#addSource(String, String)} so the signed catalog id is
   * bound to the operator-selected recommendation before persistence. Blank optional hints are
   * normalized away, while non-blank hints are bounded to short single-line values for API and
   * certification output.
   *
   * @param catalogId expected signed catalog id for the recommendation being displayed
   * @param name operator-facing display name used in catalog onboarding cards
   * @param description operator-facing description of catalog purpose and maintenance ownership
   * @param channel release channel label used for grouping, filtering, and display
   * @param source optional validated catalog source, absent when packaging is not configured
   * @param trustedCatalogKeyId optional trusted catalog key id hint, not public key bytes
   * @param reviewerPolicyHint optional reviewer policy display hint for operator context
   * @throws AppCatalogException if any recommendation field is malformed or too long
   */
  public RecommendedAppCatalog {
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    name =
        AppCatalogSidecars.requireBoundedSingleLine(
            name,
            "recommended catalog name",
            AppCatalogSidecars.INVALID_CATALOG_SOURCE,
            MAX_NAME_CHARS);
    description =
        AppCatalogSidecars.requireBoundedSingleLine(
            description,
            "recommended catalog description",
            AppCatalogSidecars.INVALID_CATALOG_SOURCE,
            MAX_DESCRIPTION_CHARS);
    channel =
        AppCatalogSidecars.requireBoundedSingleLine(
                channel,
                "recommended catalog channel",
                AppCatalogSidecars.INVALID_CATALOG_SOURCE,
                MAX_CHANNEL_CHARS)
            .toLowerCase(Locale.ROOT);
    source = Objects.requireNonNull(source, "source").map(RecommendedAppCatalog::requireSource);
    trustedCatalogKeyId =
        normalizeOptionalHint(
            Objects.requireNonNull(trustedCatalogKeyId, "recommended catalog trusted key id")
                .orElse(null),
            "recommended catalog trusted key id");
    reviewerPolicyHint =
        normalizeOptionalHint(
            Objects.requireNonNull(reviewerPolicyHint, "recommended catalog reviewer policy hint")
                .orElse(null),
            "recommended catalog reviewer policy hint");
  }

  /**
   * Creates a descriptor from raw optional source text.
   *
   * <p>This factory is useful for runtime configuration where the source may be absent. Blank
   * source and hint values are treated as not configured. Non-blank source values are parsed
   * through {@link AppCatalogSource#parse(String)} and therefore support the same path, HTTPS,
   * loopback HTTP, and {@code crypta:} forms as manual catalog add. The factory is intentionally
   * side-effect free: it does not check whether the source is reachable and does not require a
   * trusted key to be present. API handlers perform those readiness checks against live runtime
   * collaborators before they enable the add action.
   *
   * @param catalogId expected signed catalog id for the recommendation being configured
   * @param name operator-facing display name shown in recommended-catalog UI
   * @param description operator-facing description of catalog purpose and project ownership
   * @param channel release channel label for grouping, filtering, and display
   * @param rawSource optional source text from runtime or packaging configuration
   * @param trustedCatalogKeyId optional trusted catalog key id hint from configuration
   * @param reviewerPolicyHint optional reviewer policy display hint from configuration
   * @return normalized recommendation descriptor ready for API readiness checks
   */
  public static RecommendedAppCatalog fromRawSource(
      String catalogId,
      String name,
      String description,
      String channel,
      String rawSource,
      String trustedCatalogKeyId,
      String reviewerPolicyHint) {
    return new RecommendedAppCatalog(
        catalogId,
        name,
        description,
        channel,
        optionalSource(rawSource),
        Optional.ofNullable(trustedCatalogKeyId),
        Optional.ofNullable(reviewerPolicyHint));
  }

  /**
   * Returns the configured source transport kind for display and readiness checks.
   *
   * <p>The value is derived from the parsed {@link AppCatalogSource} and is therefore normalized to
   * one of the source model's supported transport families, such as {@code crypta}, {@code https},
   * {@code http}, or {@code file}. Absence means the recommendation is intentionally visible but
   * cannot be added until packaging or runtime configuration supplies a source.
   *
   * @return lowercase source kind when a source is configured, otherwise an empty value
   */
  public Optional<String> sourceKind() {
    return source.map(value -> value.kind().name().toLowerCase(Locale.ROOT));
  }

  /**
   * Returns the configured source URI text exactly as the source model stores it.
   *
   * <p>Callers that expose this value through operator APIs should apply their own redaction policy
   * for local paths and Crypta keys. The recommendation model preserves the normalized source so
   * add-source flows can use the same verified manager path as manual catalog onboarding. This
   * method is appropriate for internal add-source calls and controlled diagnostics; user-facing
   * JSON should normally collapse {@code file:} paths and {@code crypta:} keys to a configured/not
   * configured state.
   *
   * @return normalized source URI text when a source is configured, otherwise an empty value
   */
  public Optional<String> sourceDisplayUri() {
    return source.map(AppCatalogSource::displayUri);
  }

  /**
   * Returns whether this recommendation has a source configured.
   *
   * <p>This is a readiness hint, not a trust decision. A configured source may still fail trusted
   * key checks, catalog fetch, signature verification, expected-id matching, or later app install
   * gates. It is useful for deciding whether the Web Shell should show a missing-source message
   * before attempting a signed-catalog add.
   *
   * @return {@code true} when runtime configuration supplied a parsable catalog source
   */
  public boolean configured() {
    return source.isPresent();
  }

  private static AppCatalogSource requireSource(AppCatalogSource source) {
    return Objects.requireNonNull(source, "source value");
  }

  private static Optional<String> normalizeOptionalHint(String value, String fieldName) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(
        AppCatalogSidecars.requireBoundedSingleLine(
            value, fieldName, AppCatalogSidecars.INVALID_CATALOG_SOURCE, MAX_HINT_CHARS));
  }

  private static Optional<AppCatalogSource> optionalSource(String rawSource) {
    if (rawSource == null || rawSource.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(AppCatalogSource.parse(rawSource));
  }
}
