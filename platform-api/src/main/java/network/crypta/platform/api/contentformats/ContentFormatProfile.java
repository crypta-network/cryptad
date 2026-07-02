package network.crypta.platform.api.contentformats;

import java.util.Objects;

/**
 * Immutable descriptor for one Crypta app ecosystem content format profile.
 *
 * <p>A profile descriptor names the canonical document identifier, MIME type, filename, status,
 * size limits, signing domain, canonicalization behavior, and version policy used by first-party
 * apps and release certification. It is metadata only; parser-specific validation stays with the
 * route or app that owns the document body. Callers should treat instances as read-only registry
 * values and pass them around instead of duplicating string constants in routes, staged apps, or
 * release evidence probes.
 *
 * <p>The descriptor enforces the cross-field invariants that matter before a document body is
 * parsed: signed profiles must declare a signing domain and signed-payload limit, unsigned profiles
 * must not, and every profile must define a positive document-size limit. It is safe to share
 * across threads because records are immutable and the contained policy objects are immutable as
 * well.
 *
 * @param id canonical type or schema identifier, such as {@code crypta.profile.v1}
 * @param majorVersion positive major version number extracted from the profile id
 * @param contentType MIME type used for app-generated inserts or fetched documents
 * @param defaultFilename default target filename, or {@code null} when the profile has none
 * @param status app ecosystem profile lifecycle status used by validation warnings
 * @param maxDocumentBytes maximum accepted full document size in UTF-8 bytes
 * @param maxSignedPayloadBytes maximum signed payload size, or {@code null} for unsigned profiles
 * @param signed whether the profile has a fixed signing and verification contract
 * @param signingDomain fixed signing domain or purpose, or {@code null} for unsigned profiles
 * @param canonicalizationKind short label for the canonical byte contract
 * @param versionPolicy conservative version and deprecation behavior for the profile
 * @param replacementProfileId replacement profile id when deprecated, or {@code null}
 */
public record ContentFormatProfile(
    String id,
    int majorVersion,
    String contentType,
    String defaultFilename,
    ContentFormatProfileStatus status,
    int maxDocumentBytes,
    Integer maxSignedPayloadBytes,
    boolean signed,
    String signingDomain,
    String canonicalizationKind,
    ContentFormatVersionPolicy versionPolicy,
    String replacementProfileId) {
  /**
   * Creates one validated immutable profile descriptor.
   *
   * <p>The compact constructor normalizes nullable text fields by trimming blanks to {@code null}
   * and rejects inconsistent signing metadata before a descriptor can enter the registry. These
   * checks keep route validation and release evidence simple because every registered profile has
   * already passed the same invariant checks.
   */
  public ContentFormatProfile {
    id = requireText("id", id);
    if (majorVersion <= 0) {
      throw new IllegalArgumentException("majorVersion must be positive.");
    }
    contentType = requireText("contentType", contentType);
    defaultFilename = trimNullable(defaultFilename);
    Objects.requireNonNull(status, "status");
    if (maxDocumentBytes <= 0) {
      throw new IllegalArgumentException("maxDocumentBytes must be positive.");
    }
    if (maxSignedPayloadBytes != null && maxSignedPayloadBytes <= 0) {
      throw new IllegalArgumentException("maxSignedPayloadBytes must be positive when present.");
    }
    signingDomain = trimNullable(signingDomain);
    if (signed && signingDomain == null) {
      throw new IllegalArgumentException("signed profiles require a signingDomain.");
    }
    if (!signed && signingDomain != null) {
      throw new IllegalArgumentException("unsigned profiles must not define a signingDomain.");
    }
    if (!signed && maxSignedPayloadBytes != null) {
      throw new IllegalArgumentException(
          "unsigned profiles must not define maxSignedPayloadBytes.");
    }
    canonicalizationKind = requireText("canonicalizationKind", canonicalizationKind);
    Objects.requireNonNull(versionPolicy, "versionPolicy");
    replacementProfileId = trimNullable(replacementProfileId);
  }

  /**
   * Validates basic metadata for a document claimed to match this profile.
   *
   * <p>This method intentionally checks only redaction-safe metadata: claimed type, byte count, and
   * profile lifecycle status. It does not parse or retain raw document content, inspect signatures,
   * or canonicalize payloads. Route-specific parsers should call this before deeper validation and
   * then enforce their own required fields, unknown-field policy, and signed-byte checks.
   *
   * @param claimedId type or schema read by a caller-specific parser from redaction-safe metadata
   * @param documentBytes UTF-8 byte count of the document before body retention or logging
   * @return accepted, warning, or rejected profile validation result with safe diagnostic text
   */
  public ContentFormatValidationResult validateMetadata(String claimedId, long documentBytes) {
    if (documentBytes > maxDocumentBytes) {
      return ContentFormatValidationResult.rejected(
          "oversized_document", id, "Document exceeds the maximum byte size for this profile.");
    }
    if (!id.equals(claimedId)) {
      return ContentFormatValidationResult.rejected(
          "unsupported_version",
          id,
          "Document type is not supported by this content format profile.");
    }
    if (status == ContentFormatProfileStatus.DEPRECATED) {
      return ContentFormatValidationResult.acceptedWithWarning(
          "deprecated_version", id, "Document profile version is deprecated.");
    }
    return ContentFormatValidationResult.acceptedResult();
  }

  private static String requireText(String name, String value) {
    String text = Objects.requireNonNull(value, name).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be blank.");
    }
    return text;
  }

  private static String trimNullable(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return value.trim();
  }
}
