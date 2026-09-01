package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.jetbrains.annotations.NotNull;

/**
 * One locally retained, explicitly pending catalog discovery recommendation.
 *
 * <p>The record retains only authenticated public descriptor and direct-endorsement documents plus
 * bounded local verification metadata. It cannot activate catalog, publisher, or reviewer trust,
 * configure a source, or follow an endorsement chain. Its self-digest protects the complete local
 * persistence envelope from unnoticed substitution; callers may reverify the signed documents
 * against current issuer lifecycle policy before displaying active evidence.
 *
 * <p>Instances are immutable and safe to share between operator-facing readers. The import time and
 * all verification times describe the original local import; current display code should use {@link
 * #reverifyDescriptor(TrustedAppKeys, Instant)} and {@link #reverifyEndorsements(TrustedAppKeys,
 * Instant)} when issuer lifecycle or document freshness may have changed. Reverification returns
 * evidence only and cannot change this pending record.
 *
 * @param schemaVersion closed local persistence schema, currently {@value #SCHEMA_VERSION}
 * @param descriptorVerification authenticated descriptor result fixed in the pending state
 * @param endorsementVerifications zero to eight authenticated direct endorsement results
 * @param importedAt local instant shared by the original document verification results
 * @param selfDigestSha256 lowercase SHA-256 digest of the canonical persistence envelope
 */
public record PendingCatalogDiscoveryRecommendation(
    int schemaVersion,
    CatalogDiscoveryImportResult descriptorVerification,
    List<CatalogEndorsementVerification> endorsementVerifications,
    Instant importedAt,
    String selfDigestSha256) {
  /** Supported closed local persistence schema. */
  public static final int SCHEMA_VERSION = 1;

  /** Maximum direct endorsement records retained with one descriptor. */
  public static final int MAX_ENDORSEMENTS = 8;

  /** Persistence never grants local trust. */
  public static final boolean TRUST_GRANTED = false;

  /** Persistence never configures a catalog source. */
  public static final boolean SOURCE_CONFIGURED = false;

  /** Retained endorsements are always direct and non-transitive. */
  public static final boolean TRANSITIVE = false;

  static final String INVALID_STORE = "invalid_catalog_discovery_store";
  private static final String STATUS_FIELD = "status";
  private static final String IMPORTED_AT_FIELD = "importedAt";
  private static final String DESCRIPTOR_VERIFICATION_FIELD = "descriptorVerification";
  private static final String ENDORSEMENT_VERIFICATIONS_FIELD = "endorsementVerifications";
  private static final String SELF_DIGEST_SHA256_FIELD = "selfDigestSha256";
  private static final String VERIFIED_AT_FIELD = "verifiedAt";
  private static final String ISSUER_KEY_FINGERPRINT_SHA256_FIELD = "issuerKeyFingerprintSha256";
  private static final String DOCUMENT_FIELD = "document";
  private static final String PENDING_STATUS = "pending";
  private static final Set<String> ROOT_REQUIRED =
      Set.of(
          "schemaVersion",
          STATUS_FIELD,
          IMPORTED_AT_FIELD,
          DESCRIPTOR_VERIFICATION_FIELD,
          ENDORSEMENT_VERIFICATIONS_FIELD,
          SELF_DIGEST_SHA256_FIELD);
  private static final Set<String> VERIFICATION_REQUIRED =
      Set.of(STATUS_FIELD, VERIFIED_AT_FIELD, ISSUER_KEY_FINGERPRINT_SHA256_FIELD, DOCUMENT_FIELD);

  /** Validates and defensively copies an immutable pending recommendation. */
  public PendingCatalogDiscoveryRecommendation {
    if (schemaVersion != SCHEMA_VERSION) {
      throw invalid("unsupported pending discovery schema version");
    }
    Objects.requireNonNull(descriptorVerification, DESCRIPTOR_VERIFICATION_FIELD);
    if (descriptorVerification.status() != CatalogDiscoveryImportResult.Status.PENDING) {
      throw invalid("discovery descriptor must remain pending");
    }
    endorsementVerifications =
        List.copyOf(
            Objects.requireNonNull(endorsementVerifications, ENDORSEMENT_VERIFICATIONS_FIELD));
    if (endorsementVerifications.size() > MAX_ENDORSEMENTS) {
      throw invalid("pending discovery endorsement count exceeds the retention limit");
    }
    Objects.requireNonNull(importedAt, IMPORTED_AT_FIELD);
    if (!descriptorVerification.verifiedAt().equals(importedAt)) {
      throw invalid("descriptor verification time must equal the import time");
    }
    requireCoherentEndorsements(
        descriptorVerification.descriptor(), endorsementVerifications, importedAt);
    String computed =
        CatalogSignedDocumentSupport.sha256(
            canonicalWithoutDigest(
                schemaVersion, descriptorVerification, endorsementVerifications, importedAt));
    if (selfDigestSha256 == null || selfDigestSha256.isBlank()) {
      selfDigestSha256 = computed;
    } else {
      selfDigestSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              selfDigestSha256, SELF_DIGEST_SHA256_FIELD, INVALID_STORE);
      if (!computed.equals(selfDigestSha256)) {
        throw invalid("pending discovery self-digest mismatch");
      }
    }
  }

  /**
   * Creates a self-digested record from fresh direct verification results.
   *
   * <p>The descriptor verification time becomes the record import time. Every endorsement must have
   * been verified at that same instant and must bind the descriptor's exact catalog ID,
   * catalog-signer fingerprint, and descriptor digest. The result remains pending regardless of how
   * many active endorsements are supplied.
   *
   * @param descriptorVerification fresh authenticated descriptor result in the pending state
   * @param endorsementVerifications bounded direct evidence for the exact descriptor subject
   * @return immutable pending record with a newly calculated persistence self-digest
   */
  public static PendingCatalogDiscoveryRecommendation create(
      CatalogDiscoveryImportResult descriptorVerification,
      List<CatalogEndorsementVerification> endorsementVerifications) {
    CatalogDiscoveryImportResult checked =
        Objects.requireNonNull(descriptorVerification, DESCRIPTOR_VERIFICATION_FIELD);
    return new PendingCatalogDiscoveryRecommendation(
        SCHEMA_VERSION, checked, endorsementVerifications, checked.verifiedAt(), null);
  }

  /**
   * Returns the stable public descriptor identifier.
   *
   * @return bounded descriptor ID authenticated by the signed public document
   */
  public String descriptorId() {
    return descriptorVerification.descriptor().content().descriptorId();
  }

  /**
   * Returns the exact normalized subject catalog identifier.
   *
   * @return normalized catalog ID named by the authenticated discovery descriptor
   */
  public String catalogId() {
    return descriptorVerification.descriptor().catalogId();
  }

  /**
   * Reverifies the retained descriptor against current local issuer lifecycle and freshness.
   *
   * @param trustedIssuerKeys current local public issuer registry
   * @param now current verification instant
   * @return a fresh pending result that still grants no trust
   */
  public CatalogDiscoveryImportResult reverifyDescriptor(
      TrustedAppKeys trustedIssuerKeys, Instant now) {
    return CatalogDiscoveryVerifier.verifyForImport(
        descriptorVerification.descriptor(), trustedIssuerKeys, now);
  }

  /**
   * Reverifies each retained direct endorsement without following any endorsement chain.
   *
   * <p>Issuer revocation or expiry therefore changes only that endorsement's current contribution
   * and never alters the recommendation or another catalog.
   *
   * @param trustedIssuerKeys current local public issuer registry for direct verification
   * @param now current instant used for issuer lifecycle and endorsement freshness
   * @return immutable direct verification results in the original retained order
   */
  public List<CatalogEndorsementVerification> reverifyEndorsements(
      TrustedAppKeys trustedIssuerKeys, Instant now) {
    return endorsementVerifications.stream()
        .map(
            verification ->
                CatalogEndorsementVerifier.verifyDirect(
                    verification.endorsement(), trustedIssuerKeys, now))
        .toList();
  }

  /**
   * Produces current, non-transitive evidence while preserving inactive issuers for display.
   *
   * @param trustedIssuerKeys current local public issuer registry
   * @param now current verification instant
   * @return immutable current evidence in retained order
   */
  List<CatalogEndorsementVerification> currentEndorsementEvidence(
      TrustedAppKeys trustedIssuerKeys, Instant now) {
    return endorsementVerifications.stream()
        .map(verification -> currentEndorsementEvidence(verification, trustedIssuerKeys, now))
        .toList();
  }

  /**
   * Reverifies one retained endorsement or marks only its issuer contribution inactive.
   *
   * @param retained retained direct endorsement verification
   * @param trustedIssuerKeys current local public issuer registry
   * @param now current verification instant
   * @return current bounded evidence result
   */
  private static CatalogEndorsementVerification currentEndorsementEvidence(
      CatalogEndorsementVerification retained, TrustedAppKeys trustedIssuerKeys, Instant now) {
    try {
      return CatalogEndorsementVerifier.verifyDirect(
          retained.endorsement(), trustedIssuerKeys, now);
    } catch (AppCatalogException _) {
      return new CatalogEndorsementVerification(
          retained.endorsement(),
          CatalogEndorsementVerification.Status.INACTIVE_ISSUER,
          now,
          retained.issuerKeyFingerprintSha256());
    }
  }

  /**
   * Serializes the complete pending envelope including its self-digest.
   *
   * @return canonical UTF-8 JSON record bytes
   */
  byte[] canonicalRecordBytes() {
    LinkedHashMap<String, Object> json =
        canonicalWithoutDigestValue(
            schemaVersion, descriptorVerification, endorsementVerifications, importedAt);
    json.put(SELF_DIGEST_SHA256_FIELD, selfDigestSha256);
    return CatalogSignedDocumentSupport.jsonBytes(json);
  }

  /**
   * Parses and validates one closed canonical pending-discovery envelope.
   *
   * @param bytes serialized UTF-8 JSON record bytes
   * @return validated pending recommendation
   */
  static PendingCatalogDiscoveryRecommendation parse(byte[] bytes) {
    Map<String, Object> root =
        CatalogSignedDocumentSupport.parseObject(bytes, "pending discovery record", INVALID_STORE);
    CatalogSignedDocumentSupport.requireClosedObject(
        root, ROOT_REQUIRED, Set.of(), "pending discovery record", INVALID_STORE);
    int version = CatalogSignedDocumentSupport.requireVersion(root, INVALID_STORE);
    if (!PENDING_STATUS.equals(
        CatalogSignedDocumentSupport.requireString(
            root, STATUS_FIELD, STATUS_FIELD, INVALID_STORE))) {
      throw invalid("pending discovery status must equal pending");
    }
    Instant importedAt =
        CatalogSignedDocumentSupport.requireInstant(
            root, IMPORTED_AT_FIELD, IMPORTED_AT_FIELD, INVALID_STORE);
    CatalogDiscoveryImportResult descriptor =
        parseDescriptorVerification(
            CatalogSignedDocumentSupport.requireObject(
                root, DESCRIPTOR_VERIFICATION_FIELD, DESCRIPTOR_VERIFICATION_FIELD, INVALID_STORE));
    List<CatalogEndorsementVerification> endorsements =
        parseEndorsementVerifications(root.get(ENDORSEMENT_VERIFICATIONS_FIELD));
    String digest =
        CatalogSignedDocumentSupport.requireString(
            root, SELF_DIGEST_SHA256_FIELD, SELF_DIGEST_SHA256_FIELD, INVALID_STORE);
    return new PendingCatalogDiscoveryRecommendation(
        version, descriptor, endorsements, importedAt, digest);
  }

  /**
   * Parses the retained descriptor verification and authenticates its self-digest.
   *
   * @param json closed descriptor-verification object
   * @return validated pending descriptor result
   */
  private static CatalogDiscoveryImportResult parseDescriptorVerification(
      Map<String, Object> json) {
    CatalogSignedDocumentSupport.requireClosedObject(
        json, VERIFICATION_REQUIRED, Set.of(), DESCRIPTOR_VERIFICATION_FIELD, INVALID_STORE);
    if (!PENDING_STATUS.equals(
        CatalogSignedDocumentSupport.requireString(
            json,
            STATUS_FIELD,
            DESCRIPTOR_VERIFICATION_FIELD + '.' + STATUS_FIELD,
            INVALID_STORE))) {
      throw invalid("descriptor verification status must equal pending");
    }
    CatalogDiscoveryDescriptor descriptor =
        CatalogDiscoveryDescriptor.parse(
            CatalogSignedDocumentSupport.jsonBytes(
                CatalogSignedDocumentSupport.requireObject(
                    json,
                    DOCUMENT_FIELD,
                    DESCRIPTOR_VERIFICATION_FIELD + '.' + DOCUMENT_FIELD,
                    INVALID_STORE)));
    requireDocumentSelfDigest(descriptor);
    return new CatalogDiscoveryImportResult(
        descriptor,
        CatalogDiscoveryImportResult.Status.PENDING,
        CatalogSignedDocumentSupport.requireInstant(
            json,
            VERIFIED_AT_FIELD,
            DESCRIPTOR_VERIFICATION_FIELD + '.' + VERIFIED_AT_FIELD,
            INVALID_STORE),
        CatalogSignedDocumentSupport.requireString(
            json,
            ISSUER_KEY_FINGERPRINT_SHA256_FIELD,
            DESCRIPTOR_VERIFICATION_FIELD + '.' + ISSUER_KEY_FINGERPRINT_SHA256_FIELD,
            INVALID_STORE));
  }

  /**
   * Parses the bounded retained direct-endorsement verification array.
   *
   * @param value JSON array value
   * @return immutable validated direct verifications
   */
  private static List<CatalogEndorsementVerification> parseEndorsementVerifications(Object value) {
    if (!(value instanceof List<?> items) || items.size() > MAX_ENDORSEMENTS) {
      throw invalid(ENDORSEMENT_VERIFICATIONS_FIELD + " must be a bounded array");
    }
    List<CatalogEndorsementVerification> verifications = new ArrayList<>(items.size());
    for (Object item : items) {
      if (!(item instanceof Map<?, ?> raw)) {
        throw invalid(ENDORSEMENT_VERIFICATIONS_FIELD + " must contain objects");
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> json = (Map<String, Object>) raw;
      CatalogSignedDocumentSupport.requireClosedObject(
          json, VERIFICATION_REQUIRED, Set.of(), "endorsementVerification", INVALID_STORE);
      CatalogEndorsement endorsement =
          CatalogEndorsement.parse(
              CatalogSignedDocumentSupport.jsonBytes(
                  CatalogSignedDocumentSupport.requireObject(
                      json, DOCUMENT_FIELD, "endorsementVerification.document", INVALID_STORE)));
      requireDocumentSelfDigest(endorsement);
      verifications.add(
          new CatalogEndorsementVerification(
              endorsement,
              parseEndorsementStatus(
                  CatalogSignedDocumentSupport.requireString(
                      json, STATUS_FIELD, "endorsementVerification.status", INVALID_STORE)),
              CatalogSignedDocumentSupport.requireInstant(
                  json, VERIFIED_AT_FIELD, "endorsementVerification.verifiedAt", INVALID_STORE),
              CatalogSignedDocumentSupport.requireString(
                  json,
                  ISSUER_KEY_FINGERPRINT_SHA256_FIELD,
                  "endorsementVerification.issuerKeyFingerprintSha256",
                  INVALID_STORE)));
    }
    return List.copyOf(verifications);
  }

  /**
   * Parses a retained closed endorsement-verification status.
   *
   * @param value serialized status text
   * @return parsed verification status
   */
  private static CatalogEndorsementVerification.Status parseEndorsementStatus(String value) {
    try {
      return CatalogEndorsementVerification.Status.valueOf(value.toUpperCase(Locale.ROOT));
    } catch (RuntimeException exception) {
      throw invalidEndorsementStatus(exception);
    }
  }

  /**
   * Requires every direct endorsement to bind the exact descriptor and import event.
   *
   * @param descriptor retained discovery descriptor
   * @param verifications retained direct endorsement results
   * @param importedAt exact shared import timestamp
   */
  private static void requireCoherentEndorsements(
      CatalogDiscoveryDescriptor descriptor,
      List<CatalogEndorsementVerification> verifications,
      Instant importedAt) {
    Set<String> endorsementIds = new HashSet<>();
    for (CatalogEndorsementVerification verification : verifications) {
      Objects.requireNonNull(verification, "endorsement verification");
      if (!verification.verifiedAt().equals(importedAt)) {
        throw invalid("endorsement verification time must equal the import time");
      }
      CatalogEndorsement endorsement = verification.endorsement();
      CatalogEndorsement.Subject subject = endorsement.content().subject();
      if (!endorsementIds.add(endorsement.content().endorsementId())) {
        throw invalid("duplicate retained endorsement id");
      }
      if (!subject.catalogId().equals(descriptor.catalogId())
          || !subject
              .signerFingerprintSha256()
              .equals(descriptor.content().subject().signerFingerprintSha256())
          || !subject
              .descriptorDigestSha256()
              .equals(descriptor.authentication().selfDigestSha256())) {
        throw invalid("endorsement subject does not match the exact discovery descriptor");
      }
    }
  }

  /**
   * Serializes the canonical pending envelope covered by its record digest.
   *
   * @param schemaVersion closed record schema version
   * @param descriptor retained pending descriptor verification
   * @param endorsements retained direct endorsement verifications
   * @param importedAt exact import timestamp
   * @return canonical UTF-8 JSON digest subject
   */
  private static byte[] canonicalWithoutDigest(
      int schemaVersion,
      CatalogDiscoveryImportResult descriptor,
      List<CatalogEndorsementVerification> endorsements,
      Instant importedAt) {
    return CatalogSignedDocumentSupport.jsonBytes(
        canonicalWithoutDigestValue(schemaVersion, descriptor, endorsements, importedAt));
  }

  /**
   * Builds the insertion-ordered JSON value covered by the record digest.
   *
   * @param schemaVersion closed record schema version
   * @param descriptor retained pending descriptor verification
   * @param endorsements retained direct endorsement verifications
   * @param importedAt exact import timestamp
   * @return ordered canonical JSON object
   */
  private static LinkedHashMap<String, Object> canonicalWithoutDigestValue(
      int schemaVersion,
      CatalogDiscoveryImportResult descriptor,
      List<CatalogEndorsementVerification> endorsements,
      Instant importedAt) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("schemaVersion", schemaVersion);
    json.put(STATUS_FIELD, PENDING_STATUS);
    json.put(IMPORTED_AT_FIELD, importedAt.toString());
    json.put(DESCRIPTOR_VERIFICATION_FIELD, descriptorVerificationJson(descriptor));
    json.put(
        ENDORSEMENT_VERIFICATIONS_FIELD,
        endorsements.stream().map(PendingCatalogDiscoveryRecommendation::endorsementJson).toList());
    return json;
  }

  /**
   * Builds the canonical retained descriptor-verification object.
   *
   * @param verification pending descriptor verification
   * @return ordered JSON-compatible object
   */
  private static Map<String, Object> descriptorVerificationJson(
      CatalogDiscoveryImportResult verification) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(STATUS_FIELD, PENDING_STATUS);
    json.put(VERIFIED_AT_FIELD, verification.verifiedAt().toString());
    json.put(ISSUER_KEY_FINGERPRINT_SHA256_FIELD, verification.issuerKeyFingerprintSha256());
    json.put(DOCUMENT_FIELD, verification.descriptor().toJsonValue());
    return json;
  }

  /**
   * Builds the canonical retained direct-endorsement verification object.
   *
   * @param verification direct endorsement verification
   * @return ordered JSON-compatible object
   */
  private static Map<String, Object> endorsementJson(CatalogEndorsementVerification verification) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(STATUS_FIELD, verification.status().name().toLowerCase(Locale.ROOT));
    json.put(VERIFIED_AT_FIELD, verification.verifiedAt().toString());
    json.put(ISSUER_KEY_FINGERPRINT_SHA256_FIELD, verification.issuerKeyFingerprintSha256());
    json.put(DOCUMENT_FIELD, verification.endorsement().toJsonValue());
    return json;
  }

  /**
   * Recomputes the retained discovery descriptor's content digest.
   *
   * @param descriptor retained signed descriptor
   */
  private static void requireDocumentSelfDigest(CatalogDiscoveryDescriptor descriptor) {
    CatalogSignedDocumentSupport.requireSelfDigest(
        descriptor.authentication().selfDigestSha256(),
        descriptor.canonicalContentBytes(),
        INVALID_STORE);
  }

  /**
   * Recomputes the retained endorsement's content digest.
   *
   * @param endorsement retained signed direct endorsement
   */
  private static void requireDocumentSelfDigest(CatalogEndorsement endorsement) {
    CatalogSignedDocumentSupport.requireSelfDigest(
        endorsement.authentication().selfDigestSha256(),
        endorsement.canonicalContentBytes(),
        INVALID_STORE);
  }

  /**
   * Creates the stable invalid-pending-record failure.
   *
   * @param message bounded validation explanation
   * @return catalog exception with the stable pending-store error code
   */
  private static AppCatalogException invalid(String message) {
    return new AppCatalogException(INVALID_STORE, message);
  }

  /**
   * Creates the stable invalid-status failure with its parse cause.
   *
   * @param cause status parsing failure
   * @return catalog exception with the stable pending-store error code
   */
  private static AppCatalogException invalidEndorsementStatus(Exception cause) {
    return new AppCatalogException(INVALID_STORE, "invalid retained endorsement status", cause);
  }

  /** Returns a bounded summary that deliberately excludes documents, URIs, and signatures. */
  @Override
  public @NotNull String toString() {
    return "PendingCatalogDiscoveryRecommendation[descriptorId="
        + descriptorId()
        + ", catalogId="
        + catalogId()
        + ", endorsementCount="
        + endorsementVerifications.size()
        + ", "
        + IMPORTED_AT_FIELD
        + '='
        + importedAt
        + ", "
        + SELF_DIGEST_SHA256_FIELD
        + '='
        + selfDigestSha256
        + ']';
  }
}
