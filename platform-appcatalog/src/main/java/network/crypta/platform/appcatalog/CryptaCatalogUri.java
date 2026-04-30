package network.crypta.platform.appcatalog;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Objects;

/**
 * Parsed {@code crypta:} catalog source with explicit catalog and signature fetch keys.
 *
 * <p>The {@code crypta:} prefix is a catalog-source transport marker. It is not passed to the
 * runtime content layer; callers use {@link #catalogFetchKey()} and {@link #signatureFetchKey()} to
 * obtain the underlying Crypta keys. The original display URI is retained so source metadata and
 * API responses can show the operator-configured value.
 *
 * <p>Crypta catalog sources deliberately keep Crypta keys outside {@link URI#resolve(String)}.
 * Freenet-style keys are opaque to the JDK URI resolver, so signature sidecar resolution is
 * specified directly here. USK and SSK catalog keys must be slash-delimited path-like keys and use
 * the sibling {@link AppCatalogSignature#SIGNATURE_FILE_NAME}. CHK catalog keys are immutable and
 * ambiguous as bare values, so they require an explicit {@code ?signature=CHK@...} companion.
 *
 * @param catalogFetchKey bare Crypta key used to fetch catalog properties bytes
 * @param signatureFetchKey bare Crypta key used to fetch signature sidecar bytes
 * @param displayUri normalized {@code crypta:} URI shown in source metadata
 */
public record CryptaCatalogUri(
    String catalogFetchKey, String signatureFetchKey, String displayUri) {
  /** Scheme marker used by operator-facing catalog source URIs. */
  private static final String SCHEME_PREFIX = "crypta:";

  /** Diagnostic field name used for operator-facing Crypta catalog source URIs. */
  private static final String CATALOG_SOURCE_FIELD = "crypta catalog source";

  /** Query fragment that introduces an explicit CHK signature sidecar companion. */
  private static final String SIGNATURE_QUERY_PREFIX = "?signature=";

  /** Prefix used by immutable Crypta content keys. */
  private static final String CHK_PREFIX = "CHK@";

  /** Prefix used by signed-subspace Crypta keys. */
  private static final String SSK_PREFIX = "SSK@";

  /** Prefix used by updatable signed-subspace Crypta keys. */
  private static final String USK_PREFIX = "USK@";

  /**
   * Creates a validated Crypta catalog URI value.
   *
   * <p>The canonical constructor enforces the same invariants as {@link #parse(String)} for callers
   * that construct the value directly. Fetch keys must be bare Crypta keys without URI query or
   * fragment text, and the display URI plus derived signature display URI must be accepted by the
   * JDK URI parser. Invalid values fail closed with {@code invalid_catalog_source}.
   */
  public CryptaCatalogUri {
    catalogFetchKey = requireKey(catalogFetchKey, "catalog Crypta key");
    signatureFetchKey = requireKey(signatureFetchKey, "catalog signature Crypta key");
    displayUri =
        AppCatalogSidecars.requireNonBlankSingleLine(
            displayUri, CATALOG_SOURCE_FIELD, AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    if (!displayUri.toLowerCase(Locale.ROOT).startsWith(SCHEME_PREFIX)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          CATALOG_SOURCE_FIELD + " must use the crypta scheme");
    }
    requireUriSyntax(displayUri, CATALOG_SOURCE_FIELD);
    requireUriSyntax(SCHEME_PREFIX + signatureFetchKey, "crypta catalog signature source");
  }

  /**
   * Parses one operator-provided {@code crypta:} catalog source.
   *
   * <p>The parser accepts {@code crypta:USK@...}, {@code crypta:SSK@...}, and the explicit CHK
   * companion form {@code crypta:CHK@...?signature=CHK@...}. It rejects fragments, extra query
   * parameters, bare CHK sources without a signature companion, and malformed URI syntax. The
   * returned value contains bare fetch keys suitable for the runtime content-fetch port.
   *
   * @param rawSource catalog source text supplied by an operator or API request
   * @return parsed value with explicit catalog and signature fetch keys
   */
  static CryptaCatalogUri parse(String rawSource) {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
            rawSource, "source", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    if (!value.toLowerCase(Locale.ROOT).startsWith(SCHEME_PREFIX)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          CATALOG_SOURCE_FIELD + " must use the crypta scheme");
    }
    String body = value.substring(SCHEME_PREFIX.length());
    if (body.indexOf('#') >= 0) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          CATALOG_SOURCE_FIELD + " must not include a fragment");
    }
    int signatureQueryIndex = body.indexOf(SIGNATURE_QUERY_PREFIX);
    String catalogKey = signatureQueryIndex >= 0 ? body.substring(0, signatureQueryIndex) : body;
    String signatureKey =
        signatureQueryIndex >= 0
            ? body.substring(signatureQueryIndex + SIGNATURE_QUERY_PREFIX.length())
            : null;
    validateNoExtraQuery(catalogKey, signatureKey);
    if (catalogKey.startsWith(CHK_PREFIX)) {
      if (signatureKey == null || !signatureKey.startsWith(CHK_PREFIX)) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE,
            "crypta CHK catalog source requires a CHK signature companion");
      }
      return new CryptaCatalogUri(catalogKey, signatureKey, value);
    }
    if (catalogKey.startsWith(USK_PREFIX) || catalogKey.startsWith(SSK_PREFIX)) {
      if (signatureKey != null) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE,
            "crypta USK/SSK catalog source must not include a signature query");
      }
      return new CryptaCatalogUri(catalogKey, siblingSignatureKey(catalogKey), value);
    }
    throw new AppCatalogException(
        AppCatalogSidecars.INVALID_CATALOG_SOURCE,
        CATALOG_SOURCE_FIELD + " must start with USK@, SSK@, or CHK@");
  }

  /**
   * Returns the operator-facing catalog source URI.
   *
   * <p>This URI keeps the {@code crypta:} transport marker. It is useful for source metadata,
   * diagnostics, and API responses, but callers should not pass it directly to the runtime fetch
   * layer because that layer expects the bare Crypta key.
   *
   * @return validated display URI for the catalog source
   */
  URI toUri() {
    return requireUriSyntax(displayUri, CATALOG_SOURCE_FIELD);
  }

  /**
   * Returns the display URI for the resolved catalog signature sidecar.
   *
   * <p>USK and SSK sources use the sibling signature filename. CHK sources return the explicit
   * signature companion supplied in the source query. The URI is for catalog-source metadata and
   * sidecar diagnostics; fetchers use {@link #signatureFetchKey()} for the runtime request.
   *
   * @return validated {@code crypta:} URI for the signature sidecar source
   */
  URI signatureUri() {
    return requireUriSyntax(SCHEME_PREFIX + signatureFetchKey, "crypta catalog signature source");
  }

  /**
   * Rejects unsupported query shapes before deriving fetch keys.
   *
   * @param catalogKey parsed catalog key portion before any signature companion
   * @param signatureKey parsed signature key companion, or {@code null} when absent
   */
  private static void validateNoExtraQuery(String catalogKey, String signatureKey) {
    if (catalogKey.indexOf('?') >= 0
        || (signatureKey != null
            && (signatureKey.indexOf('?') >= 0
                || signatureKey.indexOf('&') >= 0
                || signatureKey.isBlank()))) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid " + CATALOG_SOURCE_FIELD + " query");
    }
  }

  /**
   * Derives the USK or SSK signature key from the catalog key path.
   *
   * <p>The derivation is intentionally simple and fail-closed: only path-like keys with a final
   * slash-delimited filename have an unambiguous sibling. Bare keys or keys ending in a slash are
   * rejected so the fetcher never silently skips signature verification or guesses a sidecar.
   *
   * @param catalogKey bare USK or SSK key for the catalog properties file
   * @return sibling key that points to {@link AppCatalogSignature#SIGNATURE_FILE_NAME}
   */
  private static String siblingSignatureKey(String catalogKey) {
    int slashIndex = catalogKey.lastIndexOf('/');
    if (slashIndex <= 0 || slashIndex == catalogKey.length() - 1) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "crypta USK/SSK catalog source must include a path-like key");
    }
    return catalogKey.substring(0, slashIndex + 1) + AppCatalogSignature.SIGNATURE_FILE_NAME;
  }

  /**
   * Normalizes and validates one bare Crypta fetch key.
   *
   * @param value raw key value to validate
   * @param fieldName diagnostic field name used in thrown catalog exceptions
   * @return nonblank single-line key without URI query or fragment text
   */
  private static String requireKey(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireNonBlankSingleLine(
            Objects.requireNonNull(value, fieldName),
            fieldName,
            AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    if (normalized.indexOf('#') >= 0 || normalized.indexOf('?') >= 0) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, fieldName + " must be a bare Crypta key");
    }
    return normalized;
  }

  /**
   * Validates URI syntax and converts JDK parser failures to catalog errors.
   *
   * @param value URI text to validate
   * @param fieldName diagnostic field name used in thrown catalog exceptions
   * @return parsed URI when the syntax is accepted by {@link URI}
   */
  private static URI requireUriSyntax(String value, String fieldName) {
    try {
      return new URI(value);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid " + fieldName, exception);
    }
  }
}
