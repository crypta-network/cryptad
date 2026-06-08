package network.crypta.platform.trustgraph;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;

/**
 * Shared normalization helpers for local Trust Graph RC stores and audit records.
 *
 * <p>The helpers define the storage boundary for source metadata. Store implementations call them
 * before writing records and again when loading persisted records, so the same rules protect both
 * newly supplied app input and state from a previous process. The methods accept only bounded
 * public metadata, content-key-shaped Trust Graph source URIs, redacted URI summaries, stable
 * hashes, and short audit labels.
 *
 * <p>This class does not parse or fetch network content. It only prepares values that are safe to
 * persist beside an already parsed trust statement. Raw fetched bodies, raw request bodies, private
 * insert URIs, tokens, local paths, and exception text should never be passed here as audit or
 * source-summary values.
 */
final class TrustGraphStoreSanitizer {
  /** Scheme prefix accepted by app-facing routes for Crypta content fetch inputs. */
  private static final String CRYPTA_SCHEME_PREFIX = "crypta:";

  /** Content-hash key prefix accepted for one-shot fetched trust statements. */
  private static final String CHK_PREFIX = "CHK@";

  /** Signed-subspace key prefix accepted for fetched trust statements. */
  private static final String SSK_PREFIX = "SSK@";

  /** Updateable signed key prefix accepted for fetched statements and subscriptions. */
  private static final String USK_PREFIX = "USK@";

  /** Keyword-signed key prefix accepted by the generic content fetch workflow. */
  private static final String KSK_PREFIX = "KSK@";

  /** Prevents construction of this stateless helper class. */
  private TrustGraphStoreSanitizer() {}

  /**
   * Normalizes the source type associated with a trust statement import.
   *
   * <p>A missing value defaults to {@code manual}. Non-null values are trimmed and bounded through
   * the same text validator used by the trust statement model. The returned value is stored in
   * statement metadata and may be exposed in app-facing summaries, so callers should use stable
   * workflow labels rather than raw operator input.
   *
   * @param source optional source type supplied by the import workflow
   * @return normalized source type, or {@code manual} when no source is supplied
   * @throws TrustGraphException when the source text exceeds the field bound or contains unsafe
   *     characters
   */
  static String normalizeSource(String source) {
    String normalized = TrustStatementValidator.optionalText("source", source, 32);
    return normalized == null ? "manual" : normalized;
  }

  /**
   * Normalizes a caller-facing source label.
   *
   * <p>The label is optional display metadata, not authority. It can help an app distinguish
   * pasted, fetched, subscribed, and locally published statements, but scoring and idempotency use
   * the statement document and anchor state instead.
   *
   * @param sourceLabel optional short label supplied by the caller
   * @return trimmed source label, or {@code null} when the field is absent or blank
   * @throws TrustGraphException when the label is too long or contains unsafe characters
   */
  static String normalizeSourceLabel(String sourceLabel) {
    return TrustStatementValidator.optionalText("sourceLabel", sourceLabel, 120);
  }

  /**
   * Normalizes an optional content-subscription id for statement source metadata.
   *
   * <p>The value is a local app-platform identifier, not a source URI and not an authority signal.
   * It may be returned in statement summaries so operators can correlate an import with an
   * app-owned bounded content subscription without exposing raw fetched content or private keys.
   *
   * @param subscriptionId optional subscription id associated with an import workflow
   * @return normalized id, or {@code null} when absent
   * @throws TrustGraphException when the id is too long or contains unsafe characters
   */
  static String normalizeSubscriptionId(String subscriptionId) {
    String normalized = TrustStatementValidator.optionalText("subscriptionId", subscriptionId, 128);
    if (normalized == null) {
      return null;
    }
    if (!normalized.matches("[A-Za-z0-9._:-]{1,128}")) {
      throw new TrustGraphException(
          "invalid_trust_statement", "Field 'subscriptionId' is invalid.");
    }
    return normalized;
  }

  /**
   * Normalizes an optional source URI into a safe Crypta content-key form.
   *
   * <p>The accepted inputs are {@code CHK@}, {@code SSK@}, {@code USK@}, and {@code KSK@} content
   * keys, optionally wrapped in the case-insensitive {@code crypta:} scheme. Whitespace, query
   * strings, fragments, absolute local paths, Windows-style paths, and other URI schemes are
   * rejected so source metadata cannot become a token, filesystem path, or external web link.
   *
   * @param sourceUri optional source URI associated with a fetched or subscribed statement
   * @return normalized URI with a lowercase {@code crypta:} wrapper when one was supplied
   * @throws TrustGraphException when the URI is not a bounded Crypta content URI
   */
  static String normalizeSourceUri(String sourceUri) {
    String normalized = TrustStatementValidator.optionalText("sourceUri", sourceUri, 1024);
    if (normalized == null) {
      return null;
    }
    if (normalized.isEmpty()
        || containsWhitespace(normalized)
        || normalized.indexOf('?') >= 0
        || normalized.indexOf('#') >= 0) {
      throw invalidSourceUri();
    }
    String runtimeUri = runtimeFetchUri(normalized);
    if (runtimeUri.isEmpty()
        || containsWhitespace(runtimeUri)
        || runtimeUri.indexOf('?') >= 0
        || runtimeUri.indexOf('#') >= 0
        || runtimeUri.startsWith("/")
        || runtimeUri.startsWith("\\")
        || hasDisallowedScheme(runtimeUri)
        || isUnsupportedContentKey(runtimeUri)) {
      throw invalidSourceUri();
    }
    if (normalized.regionMatches(true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return CRYPTA_SCHEME_PREFIX + runtimeUri;
    }
    return runtimeUri;
  }

  /**
   * Normalizes a persisted source URI hash.
   *
   * <p>Hashes are stored as lowercase SHA-256 hex strings. This method is used when loading
   * persisted statement records so malformed metadata is ignored rather than returned through API
   * summaries.
   *
   * @param sourceUriHash optional persisted SHA-256 hex value
   * @return normalized lowercase hash, or {@code null} when absent
   * @throws TrustGraphException when the value is not exactly 64 lowercase hex characters
   */
  static String normalizeSourceUriHash(String sourceUriHash) {
    String normalized = TrustStatementValidator.optionalText("sourceUriHash", sourceUriHash, 64);
    if (normalized == null) {
      return null;
    }
    if (!normalized.matches("[0-9a-f]{64}")) {
      throw invalidSourceUri();
    }
    return normalized;
  }

  /**
   * Normalizes a redacted source URI summary loaded from persisted storage.
   *
   * <p>Valid summaries are generated by {@link #redactedUriSummary(String)} and contain only a
   * content-key prefix plus a short hash, for example {@code CHK@sha256:0123456789abcdef}. The
   * method rejects path separators, whitespace, control characters, and summaries that do not carry
   * the {@code sha256:} marker.
   *
   * @param sourceUriSummary optional redacted URI summary from a statement record
   * @return validated summary, or {@code null} when absent
   * @throws TrustGraphException when the persisted summary is malformed or unsafe
   */
  static String normalizeSourceUriSummary(String sourceUriSummary) {
    String normalized = TrustStatementValidator.optionalText("sourceUri", sourceUriSummary, 80);
    if (normalized == null) {
      return null;
    }
    if (!normalized.contains("sha256:")
        || normalized.indexOf('/') >= 0
        || normalized.indexOf('\\') >= 0
        || containsWhitespace(normalized)
        || containsUnsafeControl(normalized)
        || !normalized.matches("[A-Za-z0-9_@:-]{1,80}")) {
      throw invalidSourceUri();
    }
    return normalized;
  }

  /**
   * Hashes a normalized source URI for durable metadata and audit summaries.
   *
   * <p>The input is first validated by {@link #normalizeSourceUri(String)}. A blank or missing URI
   * therefore produces no hash, while unsafe URI forms fail with the same public error code as
   * source URI normalization.
   *
   * @param sourceUri optional raw source URI supplied by a workflow
   * @return lowercase SHA-256 hex hash of the normalized URI, or {@code null} when absent
   * @throws TrustGraphException when the source URI is unsupported or unsafe
   */
  static String sourceUriHash(String sourceUri) {
    String normalized = normalizeSourceUri(sourceUri);
    return normalized == null ? null : hashText(normalized);
  }

  /**
   * Returns a stable redacted source URI kind for imported statement metadata.
   *
   * <p>The value identifies only the public key family and optional {@code crypta:} wrapper, such
   * as {@code crypta-usk} or {@code chk}. It is safe for status and statement summaries because it
   * does not contain the raw URI body, edition, filename, query text, or a local path.
   *
   * @param sourceUri optional raw source URI supplied by a workflow
   * @return redacted source kind, or {@code null} when no source URI is present
   * @throws TrustGraphException when the source URI is unsupported or unsafe
   */
  static String sourceUriKind(String sourceUri) {
    String normalized = normalizeSourceUri(sourceUri);
    if (normalized == null) {
      return null;
    }
    boolean cryptaWrapped =
        normalized.regionMatches(true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length());
    String runtimeUri = runtimeFetchUri(normalized);
    String family;
    if (startsWithContentKeyPrefix(runtimeUri, CHK_PREFIX)) {
      family = "chk";
    } else if (startsWithContentKeyPrefix(runtimeUri, SSK_PREFIX)) {
      family = "ssk";
    } else if (startsWithContentKeyPrefix(runtimeUri, USK_PREFIX)) {
      family = "usk";
    } else if (startsWithContentKeyPrefix(runtimeUri, KSK_PREFIX)) {
      family = "ksk";
    } else {
      family = "unknown";
    }
    return cryptaWrapped ? "crypta-" + family : family;
  }

  /**
   * Converts an app-facing source URI into the runtime fetch URI form.
   *
   * <p>The method removes a case-insensitive {@code crypta:} wrapper and trims the remaining text.
   * It does not perform full validation by itself; callers that persist or fetch the value should
   * use {@link #normalizeSourceUri(String)} first.
   *
   * @param requestedUri source URI as supplied to an app-facing import or fetch workflow
   * @return runtime content URI without the optional {@code crypta:} scheme prefix
   */
  static String runtimeFetchUri(String requestedUri) {
    if (requestedUri.regionMatches(
        true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return requestedUri.substring(CRYPTA_SCHEME_PREFIX.length()).trim();
    }
    return requestedUri;
  }

  /**
   * Returns whether a URI lacks a supported Crypta content-key prefix.
   *
   * <p>The comparison is case-insensitive and only checks the key prefix. Callers still need the
   * other validation performed by {@link #normalizeSourceUri(String)} before accepting the value.
   *
   * @param uri runtime content URI to check
   * @return {@code true} when the URI is not a CHK, SSK, USK, or KSK content key
   */
  static boolean isUnsupportedContentKey(String uri) {
    return !(startsWithContentKeyPrefix(uri, CHK_PREFIX)
        || startsWithContentKeyPrefix(uri, SSK_PREFIX)
        || startsWithContentKeyPrefix(uri, USK_PREFIX)
        || startsWithContentKeyPrefix(uri, KSK_PREFIX));
  }

  /**
   * Serializes a trust statement document into its canonical persisted JSON form.
   *
   * <p>The returned text is derived from the parsed model, not copied from the original request or
   * fetched body. File-backed stores use this value to compute stored byte counts and to rehydrate
   * statement documents after restart.
   *
   * @param document parsed trust statement document to serialize
   * @return canonical JSON representation of the public document
   */
  static String canonicalDocumentJson(TrustStatementDocument document) {
    return TrustJson.write(document.toJson());
  }

  /**
   * Computes a lowercase SHA-256 hex digest for a text value.
   *
   * <p>The helper uses UTF-8 bytes and returns {@code null} for {@code null} input so optional
   * source metadata can be transformed without separate null checks at each call site.
   *
   * @param value text value to hash, or {@code null}
   * @return lowercase SHA-256 hex digest, or {@code null} when the input is {@code null}
   */
  static String hashText(String value) {
    if (value == null) {
      return null;
    }
    return TrustStatementFingerprint.sha256Hex(value.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Builds a redacted display summary for a source URI.
   *
   * <p>The summary keeps only the content-key family and the first 16 hex characters of an SHA-256
   * hash of the normalized URI. It is safe for API responses and audit evidence because it omits
   * the original key body, path components, edition, and filename.
   *
   * @param uri optional raw source URI supplied by a workflow
   * @return redacted URI summary, or {@code null} when no URI is supplied
   * @throws TrustGraphException when the source URI is unsupported or unsafe
   */
  static String redactedUriSummary(String uri) {
    String normalized = normalizeSourceUri(uri);
    if (normalized == null) {
      return null;
    }
    String runtimeUri = runtimeFetchUri(normalized);
    int at = runtimeUri.indexOf('@');
    String prefix = at > 0 ? runtimeUri.substring(0, at).toUpperCase(Locale.ROOT) + "@" : "uri:";
    return prefix + "sha256:" + hashText(normalized).substring(0, 16);
  }

  /**
   * Creates a collision-resistant file identifier for an audit event.
   *
   * <p>The identifier starts with the event timestamp for deterministic directory scans and
   * includes a short hash over event fields plus {@link System#nanoTime()} so duplicate events
   * created under a fixed or coarse clock can still be retained as separate files.
   *
   * @param timestamp event timestamp used as the sortable prefix
   * @param event audit event whose stable public fields contribute to the hash material
   * @return filename-safe identifier without a file extension
   */
  static String eventFileId(Instant timestamp, TrustGraphAuditEvent event) {
    String material =
        timestamp
            + "\n"
            + event.eventType()
            + "\n"
            + event.documentFingerprint()
            + "\n"
            + event.payloadHash()
            + "\n"
            + event.statusCode()
            + "\n"
            + System.nanoTime();
    return timestamp.toString().replace(':', '-').replace('.', '-')
        + "-"
        + hashText(material).substring(0, 16);
  }

  /**
   * Validates and trims a required audit text field.
   *
   * @param fieldName logical field name used in safe validation errors
   * @param value candidate audit field value
   * @param maxLength maximum accepted character count after trimming
   * @return trimmed audit field value
   * @throws TrustGraphException when the value is blank, too long, or contains unsafe controls
   */
  static String requiredAuditText(String fieldName, String value, int maxLength) {
    return auditText(fieldName, value, maxLength, true);
  }

  /**
   * Validates and trims an optional audit text field.
   *
   * @param fieldName logical field name used in safe validation errors
   * @param value candidate audit field value
   * @param maxLength maximum accepted character count after trimming
   * @return trimmed audit field value, or {@code null} when absent or blank
   * @throws TrustGraphException when the value is too long or contains unsafe controls
   */
  static String optionalAuditText(String fieldName, String value, int maxLength) {
    return auditText(fieldName, value, maxLength, false);
  }

  /**
   * Validates one audit string field with shared required/optional behavior.
   *
   * @param fieldName logical field name used in safe validation errors
   * @param value candidate field value
   * @param maxLength maximum accepted character count after trimming
   * @param required whether blank or missing values should be rejected
   * @return trimmed value, or {@code null} for missing optional fields
   * @throws TrustGraphException when validation fails
   */
  private static String auditText(String fieldName, String value, int maxLength, boolean required) {
    if (value == null || value.isBlank()) {
      if (required) {
        throw new TrustGraphException(
            "invalid_trust_audit_event", "Audit field '" + fieldName + "' is required.");
      }
      return null;
    }
    String text = value.trim();
    if (text.length() > maxLength || containsUnsafeControl(text)) {
      throw new TrustGraphException(
          "invalid_trust_audit_event", "Audit field '" + fieldName + "' is invalid.");
    }
    return text;
  }

  /**
   * Checks whether a URI begins with a content-key prefix.
   *
   * @param uri runtime URI candidate to inspect
   * @param prefix expected content-key prefix including {@code @}
   * @return {@code true} when the URI starts with the prefix ignoring case
   */
  private static boolean startsWithContentKeyPrefix(String uri, String prefix) {
    return uri.regionMatches(true, 0, prefix, 0, prefix.length());
  }

  /**
   * Detects URI schemes that appear before any content-key separator.
   *
   * <p>Crypta content keys use {@code @} before path-like material. A colon before that separator
   * indicates an external scheme such as {@code http:} or {@code file:}, which source metadata must
   * reject.
   *
   * @param uri runtime URI candidate to inspect
   * @return {@code true} when a disallowed scheme-like prefix is present
   */
  private static boolean hasDisallowedScheme(String uri) {
    int colon = uri.indexOf(':');
    int at = uri.indexOf('@');
    return colon >= 0 && (at < 0 || colon < at);
  }

  /**
   * Detects any Unicode whitespace character in a candidate metadata value.
   *
   * @param value text value to inspect
   * @return {@code true} when the value contains whitespace
   */
  private static boolean containsWhitespace(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isWhitespace(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }

  /**
   * Detects ISO control characters that are unsafe for persisted summaries.
   *
   * @param value text value to inspect
   * @return {@code true} when the value contains a control character or delete character
   */
  private static boolean containsUnsafeControl(String value) {
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      if (Character.isISOControl(ch)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Builds the public exception used for unsafe source URI metadata.
   *
   * @return trust graph exception with a stable app-facing error code and safe message
   */
  private static TrustGraphException invalidSourceUri() {
    return new TrustGraphException(
        "invalid_trust_statement", "Field 'sourceUri' must be a Crypta content URI.");
  }
}
