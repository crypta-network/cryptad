package network.crypta.platform.api.contentformats;

import java.util.Objects;

/**
 * Immutable descriptor for one Crypta app ecosystem content format profile.
 *
 * <p>A profile descriptor names the canonical document identifier, MIME type, filename, status,
 * size limits, signing domain, canonicalization behavior, and version policy used by first-party
 * apps and release certification. It is metadata only; parser-specific validation stays with the
 * route or app that owns the document body.
 *
 * @param id canonical type or schema identifier, such as {@code crypta.profile.v1}
 * @param majorVersion major version number extracted from the profile id
 * @param contentType MIME type used for app-generated inserts or fetched documents
 * @param defaultFilename default target filename, or {@code null} when the profile has none
 * @param status app ecosystem profile lifecycle status
 * @param maxDocumentBytes maximum accepted full document size in UTF-8 bytes
 * @param maxSignedPayloadBytes maximum signed payload size, or {@code null} for unsigned profiles
 * @param signed whether the profile has a fixed signing contract
 * @param signingDomain fixed signing domain or purpose, or {@code null} for unsigned profiles
 * @param canonicalizationKind short label for the canonical byte contract
 * @param versionPolicy conservative version/deprecation behavior for the profile
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
  /** Creates one validated immutable profile descriptor. */
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
   * profile lifecycle status. It does not parse or retain raw document content.
   *
   * @param claimedId type or schema read by a caller-specific parser
   * @param documentBytes UTF-8 byte count of the document
   * @return accepted, warning, or rejected profile validation result
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
