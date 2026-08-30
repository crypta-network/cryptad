package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Closed signed direct endorsement of one catalog discovery descriptor.
 *
 * <p>An endorsement is informative local evidence only. It cannot configure a source, install a
 * key, activate catalog or publisher trust, follow another endorsement, or contribute to a global
 * score. Verification resolves only this record's issuer against caller-supplied local keys.
 *
 * <p>Parsing applies a closed schema, bounded labels and reason text, canonical timestamps, and
 * exact digest grammar. Canonical serializers produce the same content and signature subjects used
 * by runtime verification and certification. All nested values are immutable, and collection
 * accessors return copies. The record represents one direct issuer-to-subject statement; callers
 * must not interpret it as a chain or use it to modify unrelated catalog policy.
 *
 * @param content bounded direct endorsement content covered by the self-digest
 * @param authentication self-digest and detached Ed25519 signature
 */
public record CatalogEndorsement(Content content, Authentication authentication) {
  /** Supported closed endorsement schema version. */
  public static final int SCHEMA_VERSION = 1;

  private static final String ENDORSEMENT_ID_FIELD = "endorsementId";
  private static final String SUBJECT_FIELD = "subject";
  private static final String EVIDENCE_FIELD = "evidence";
  private static final String VALIDITY_FIELD = "validity";
  private static final String ISSUER_FIELD = "issuer";
  private static final String SELF_DIGEST_SHA256_FIELD = "selfDigestSha256";
  private static final String SIGNATURE_FIELD = "signature";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String SIGNER_FINGERPRINT_SHA256_FIELD = "signerFingerprintSha256";
  private static final String DESCRIPTOR_DIGEST_SHA256_FIELD = "descriptorDigestSha256";
  private static final String LABELS_FIELD = "labels";
  private static final String REVIEWER_SET_DIGEST_SHA256_FIELD = "reviewerSetDigestSha256";
  private static final String PUBLISHER_POLICY_DIGEST_SHA256_FIELD = "publisherPolicyDigestSha256";
  private static final String REASON_FIELD = "reason";
  private static final String ISSUED_AT_FIELD = "issuedAt";
  private static final String EXPIRES_AT_FIELD = "expiresAt";
  private static final String ISSUER_ID_FIELD = "issuerId";
  private static final String KEY_ID_FIELD = "keyId";
  private static final String KEY_FINGERPRINT_SHA256_FIELD = "keyFingerprintSha256";
  private static final String ALGORITHM_FIELD = "algorithm";
  private static final String VALUE_BASE64_FIELD = "valueBase64";

  private static final Set<String> ROOT_REQUIRED =
      Set.of(
          "schemaVersion",
          ENDORSEMENT_ID_FIELD,
          SUBJECT_FIELD,
          EVIDENCE_FIELD,
          VALIDITY_FIELD,
          ISSUER_FIELD,
          SELF_DIGEST_SHA256_FIELD,
          SIGNATURE_FIELD);

  /** Validates a complete endorsement without evaluating issuer trust. */
  public CatalogEndorsement {
    Objects.requireNonNull(content, "content");
    Objects.requireNonNull(authentication, "authentication");
  }

  /**
   * Parses exact bounded UTF-8 endorsement JSON using a closed schema.
   *
   * @param bytes exact endorsement document bytes
   * @return structurally validated signed endorsement
   */
  public static CatalogEndorsement parse(byte[] bytes) {
    Map<String, Object> root =
        CatalogSignedDocumentSupport.parseObject(
            bytes, "catalog endorsement", CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    CatalogSignedDocumentSupport.requireClosedObject(
        root,
        ROOT_REQUIRED,
        Set.of(),
        "catalog endorsement",
        CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    Content content =
        new Content(
            CatalogSignedDocumentSupport.requireVersion(
                root, CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
            CatalogSignedDocumentSupport.requireString(
                root,
                ENDORSEMENT_ID_FIELD,
                ENDORSEMENT_ID_FIELD,
                CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
            Subject.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    SUBJECT_FIELD,
                    SUBJECT_FIELD,
                    CatalogSignedDocumentSupport.INVALID_ENDORSEMENT)),
            Evidence.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    EVIDENCE_FIELD,
                    EVIDENCE_FIELD,
                    CatalogSignedDocumentSupport.INVALID_ENDORSEMENT)),
            Validity.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    VALIDITY_FIELD,
                    VALIDITY_FIELD,
                    CatalogSignedDocumentSupport.INVALID_ENDORSEMENT)),
            Issuer.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    ISSUER_FIELD,
                    ISSUER_FIELD,
                    CatalogSignedDocumentSupport.INVALID_ENDORSEMENT)));
    Authentication authentication =
        Authentication.parse(
            CatalogSignedDocumentSupport.requireString(
                root,
                SELF_DIGEST_SHA256_FIELD,
                SELF_DIGEST_SHA256_FIELD,
                CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
            CatalogSignedDocumentSupport.requireObject(
                root,
                SIGNATURE_FIELD,
                SIGNATURE_FIELD,
                CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    return new CatalogEndorsement(content, authentication);
  }

  /**
   * Returns deterministic content bytes used to calculate the self-digest.
   *
   * @return fresh canonical UTF-8 JSON content bytes
   */
  public byte[] canonicalContentBytes() {
    return CatalogSignedDocumentSupport.jsonBytes(content.toJsonValue());
  }

  /**
   * Returns deterministic bytes covered by the detached Ed25519 signature.
   *
   * @return fresh canonical signature-payload bytes
   */
  public byte[] canonicalSignaturePayloadBytes() {
    LinkedHashMap<String, Object> signed = content.toJsonValue();
    signed.put(SELF_DIGEST_SHA256_FIELD, authentication.selfDigestSha256());
    return CatalogSignedDocumentSupport.jsonBytes(signed);
  }

  /**
   * Returns deterministic complete JSON bytes including signature metadata.
   *
   * @return fresh canonical complete endorsement bytes
   */
  public byte[] canonicalDocumentBytes() {
    return CatalogSignedDocumentSupport.jsonBytes(toJsonValue());
  }

  /**
   * Returns a deterministic JSON-compatible endorsement object.
   *
   * @return insertion-ordered complete endorsement representation
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = content.toJsonValue();
    json.put(SELF_DIGEST_SHA256_FIELD, authentication.selfDigestSha256());
    json.put(SIGNATURE_FIELD, authentication.signatureJson());
    return json;
  }

  /**
   * Returns the direct issuer key ID resolved during verification.
   *
   * @return exact declared endorsement issuer key identifier
   */
  public String issuerKeyId() {
    return content.issuer().keyId();
  }

  /**
   * Public endorsement content independent of its digest and signature values.
   *
   * @param schemaVersion closed signed-endorsement schema version
   * @param endorsementId stable public identifier for this endorsement
   * @param subject exact catalog signer and descriptor being discussed
   * @param evidence bounded non-authoritative labels and policy references
   * @param validity interval during which the direct evidence is fresh
   * @param issuer public identity that signed the endorsement
   */
  public record Content(
      int schemaVersion,
      String endorsementId,
      Subject subject,
      Evidence evidence,
      Validity validity,
      Issuer issuer) {
    /** Validates and normalizes public endorsement content. */
    public Content {
      if (schemaVersion != SCHEMA_VERSION) {
        throw CatalogSignedDocumentSupport.invalid(
            CatalogSignedDocumentSupport.INVALID_ENDORSEMENT, "schemaVersion must equal 1");
      }
      endorsementId =
          CatalogSignedDocumentSupport.requireId(
              endorsementId,
              ENDORSEMENT_ID_FIELD,
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      Objects.requireNonNull(subject, SUBJECT_FIELD);
      Objects.requireNonNull(evidence, EVIDENCE_FIELD);
      Objects.requireNonNull(validity, VALIDITY_FIELD);
      Objects.requireNonNull(issuer, ISSUER_FIELD);
    }

    /**
     * Returns canonical endorsement content without authentication fields.
     *
     * @return insertion-ordered JSON-compatible content map
     */
    LinkedHashMap<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
      json.put("schemaVersion", schemaVersion);
      json.put(ENDORSEMENT_ID_FIELD, endorsementId);
      json.put(SUBJECT_FIELD, subject.toJsonValue());
      json.put(EVIDENCE_FIELD, evidence.toJsonValue());
      json.put(VALIDITY_FIELD, validity.toJsonValue());
      json.put(ISSUER_FIELD, issuer.toJsonValue());
      return json;
    }
  }

  /**
   * Exact catalog signer and descriptor digest named by this endorsement.
   *
   * @param catalogId normalized subject catalog identifier
   * @param signerFingerprintSha256 canonical subject catalog signer fingerprint
   * @param descriptorDigestSha256 exact discovery-descriptor digest being endorsed
   */
  public record Subject(
      String catalogId, String signerFingerprintSha256, String descriptorDigestSha256) {
    private static final Set<String> REQUIRED =
        Set.of(CATALOG_ID_FIELD, SIGNER_FINGERPRINT_SHA256_FIELD, DESCRIPTOR_DIGEST_SHA256_FIELD);

    /** Validates the exact endorsed subject. */
    public Subject {
      catalogId =
          CatalogSignedDocumentSupport.requireCatalogId(
              catalogId, CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      signerFingerprintSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              signerFingerprintSha256,
              "subject.signerFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      descriptorDigestSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              descriptorDigestSha256,
              "subject.descriptorDigestSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    }

    /**
     * Parses the closed endorsed-catalog subject.
     *
     * @param json parsed JSON-compatible subject object
     * @return validated immutable endorsement subject
     */
    static Subject parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json,
          REQUIRED,
          Set.of(),
          SUBJECT_FIELD,
          CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      return new Subject(
          CatalogSignedDocumentSupport.requireString(
              json,
              CATALOG_ID_FIELD,
              "subject.catalogId",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireString(
              json,
              SIGNER_FINGERPRINT_SHA256_FIELD,
              "subject.signerFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireString(
              json,
              DESCRIPTOR_DIGEST_SHA256_FIELD,
              "subject.descriptorDigestSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    }

    /**
     * Returns the canonical subject representation.
     *
     * @return insertion-ordered JSON-compatible subject map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(SIGNER_FINGERPRINT_SHA256_FIELD, signerFingerprintSha256);
      json.put(DESCRIPTOR_DIGEST_SHA256_FIELD, descriptorDigestSha256);
      return json;
    }
  }

  /**
   * Optional policy digests and bounded human-readable direct endorsement labels.
   *
   * @param reviewerSetDigestSha256 optional public reviewer-set evidence digest
   * @param publisherPolicyDigestSha256 optional public publisher-policy evidence digest
   * @param labels bounded labels supplied by the direct issuer
   * @param reason optional bounded plain-text reason supplied by the issuer
   */
  public record Evidence(
      Optional<String> reviewerSetDigestSha256,
      Optional<String> publisherPolicyDigestSha256,
      List<String> labels,
      Optional<String> reason) {
    private static final Set<String> REQUIRED = Set.of(LABELS_FIELD);
    private static final Set<String> OPTIONAL =
        Set.of(
            REVIEWER_SET_DIGEST_SHA256_FIELD, PUBLISHER_POLICY_DIGEST_SHA256_FIELD, REASON_FIELD);

    /** Validates optional evidence without promoting it to local trust. */
    public Evidence {
      reviewerSetDigestSha256 =
          CatalogSignedDocumentSupport.optionalSha256(
              Objects.requireNonNull(reviewerSetDigestSha256, REVIEWER_SET_DIGEST_SHA256_FIELD)
                  .orElse(null),
              "evidence.reviewerSetDigestSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      publisherPolicyDigestSha256 =
          CatalogSignedDocumentSupport.optionalSha256(
              Objects.requireNonNull(
                      publisherPolicyDigestSha256, PUBLISHER_POLICY_DIGEST_SHA256_FIELD)
                  .orElse(null),
              "evidence.publisherPolicyDigestSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      labels = CatalogSignedDocumentSupport.requireEndorsementLabels(labels);
      reason =
          Objects.requireNonNull(reason, REASON_FIELD)
              .map(
                  value ->
                      CatalogSignedDocumentSupport.requireBoundedLine(
                          value,
                          "evidence.reason",
                          CatalogSignedDocumentSupport.MAX_REASON_CHARS,
                          CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    }

    /**
     * Returns an immutable copy of the bounded direct-endorsement labels.
     *
     * @return immutable direct-evidence labels
     */
    @Override
    public List<String> labels() {
      return List.copyOf(labels);
    }

    /**
     * Parses the bounded direct-evidence object.
     *
     * @param json parsed JSON-compatible evidence object
     * @return validated immutable endorsement evidence
     */
    static Evidence parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json,
          REQUIRED,
          OPTIONAL,
          EVIDENCE_FIELD,
          CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      return new Evidence(
          CatalogSignedDocumentSupport.optionalString(
              json,
              REVIEWER_SET_DIGEST_SHA256_FIELD,
              "evidence.reviewerSetDigestSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.optionalString(
              json,
              PUBLISHER_POLICY_DIGEST_SHA256_FIELD,
              "evidence.publisherPolicyDigestSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireStrings(
              json,
              LABELS_FIELD,
              "evidence.labels",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.optionalString(
              json,
              REASON_FIELD,
              "evidence.reason",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    }

    /**
     * Returns the canonical evidence representation.
     *
     * @return insertion-ordered JSON-compatible evidence map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
      reviewerSetDigestSha256.ifPresent(value -> json.put(REVIEWER_SET_DIGEST_SHA256_FIELD, value));
      publisherPolicyDigestSha256.ifPresent(
          value -> json.put(PUBLISHER_POLICY_DIGEST_SHA256_FIELD, value));
      json.put(LABELS_FIELD, labels);
      reason.ifPresent(value -> json.put(REASON_FIELD, value));
      return json;
    }
  }

  /**
   * Bounded issue and expiry instants for active evidence.
   *
   * @param issuedAt timestamp at which the issuer created this endorsement
   * @param expiresAt timestamp after which the evidence is inactive
   */
  public record Validity(Instant issuedAt, Instant expiresAt) {
    private static final Set<String> REQUIRED = Set.of(ISSUED_AT_FIELD, EXPIRES_AT_FIELD);

    /** Validates the bounded half-open evidence interval. */
    public Validity {
      CatalogSignedDocumentSupport.requireValidity(
          issuedAt, expiresAt, CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    }

    /**
     * Parses the endorsement freshness interval.
     *
     * @param json parsed JSON-compatible validity object
     * @return validated immutable validity interval
     */
    static Validity parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json,
          REQUIRED,
          Set.of(),
          VALIDITY_FIELD,
          CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      return new Validity(
          CatalogSignedDocumentSupport.requireInstant(
              json,
              ISSUED_AT_FIELD,
              "validity.issuedAt",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireInstant(
              json,
              EXPIRES_AT_FIELD,
              "validity.expiresAt",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    }

    /**
     * Returns the canonical validity representation.
     *
     * @return insertion-ordered JSON-compatible validity map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put(ISSUED_AT_FIELD, issuedAt.toString());
      json.put(EXPIRES_AT_FIELD, expiresAt.toString());
      return json;
    }
  }

  /**
   * Public direct issuer identity resolved only through local trusted key material.
   *
   * @param issuerId stable public identifier for the direct issuer
   * @param keyId issuer key identifier resolved through local trusted material
   * @param keyFingerprintSha256 canonical fingerprint of the issuer public key
   */
  public record Issuer(String issuerId, String keyId, String keyFingerprintSha256) {
    private static final Set<String> REQUIRED =
        Set.of(ISSUER_ID_FIELD, KEY_ID_FIELD, KEY_FINGERPRINT_SHA256_FIELD);

    /** Validates issuer identifiers and declared fingerprint. */
    public Issuer {
      issuerId =
          CatalogSignedDocumentSupport.requireId(
              issuerId, "issuer.issuerId", CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      keyId =
          CatalogSignedDocumentSupport.requireId(
              keyId, "issuer.keyId", CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      keyFingerprintSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              keyFingerprintSha256,
              "issuer.keyFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    }

    /**
     * Parses the closed public issuer identity.
     *
     * @param json parsed JSON-compatible issuer object
     * @return validated immutable issuer identity
     */
    static Issuer parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json, REQUIRED, Set.of(), ISSUER_FIELD, CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      return new Issuer(
          CatalogSignedDocumentSupport.requireString(
              json,
              ISSUER_ID_FIELD,
              "issuer.issuerId",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireString(
              json, KEY_ID_FIELD, "issuer.keyId", CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireString(
              json,
              KEY_FINGERPRINT_SHA256_FIELD,
              "issuer.keyFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    }

    /**
     * Returns the canonical issuer representation.
     *
     * @return insertion-ordered JSON-compatible issuer map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(ISSUER_ID_FIELD, issuerId);
      json.put(KEY_ID_FIELD, keyId);
      json.put(KEY_FINGERPRINT_SHA256_FIELD, keyFingerprintSha256);
      return json;
    }
  }

  /**
   * Self-digest plus detached Ed25519 signature metadata.
   *
   * @param selfDigestSha256 digest of the canonical endorsement content
   * @param signatureAlgorithm closed signature algorithm identifier
   * @param signatureValueBase64 bounded Base64-encoded detached signature value
   */
  public record Authentication(
      String selfDigestSha256, String signatureAlgorithm, String signatureValueBase64) {
    private static final Set<String> REQUIRED = Set.of(ALGORITHM_FIELD, VALUE_BASE64_FIELD);

    /** Validates digest, algorithm, and signature encoding. */
    public Authentication {
      selfDigestSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              selfDigestSha256,
              SELF_DIGEST_SHA256_FIELD,
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      signatureAlgorithm =
          CatalogSignedDocumentSupport.requireAlgorithm(
              signatureAlgorithm, CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      signatureValueBase64 =
          CatalogSignedDocumentSupport.requireSignatureBase64(
              signatureValueBase64, CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    }

    /**
     * Parses the content digest and closed detached-signature object.
     *
     * @param digest declared canonical content digest
     * @param signature parsed JSON-compatible signature object
     * @return validated immutable authentication metadata
     */
    static Authentication parse(String digest, Map<String, Object> signature) {
      CatalogSignedDocumentSupport.requireClosedObject(
          signature,
          REQUIRED,
          Set.of(),
          SIGNATURE_FIELD,
          CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
      return new Authentication(
          digest,
          CatalogSignedDocumentSupport.requireString(
              signature,
              ALGORITHM_FIELD,
              "signature.algorithm",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT),
          CatalogSignedDocumentSupport.requireString(
              signature,
              VALUE_BASE64_FIELD,
              "signature.valueBase64",
              CatalogSignedDocumentSupport.INVALID_ENDORSEMENT));
    }

    /**
     * Returns the canonical detached-signature representation.
     *
     * @return insertion-ordered JSON-compatible signature map
     */
    Map<String, Object> signatureJson() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put(ALGORITHM_FIELD, signatureAlgorithm);
      json.put(VALUE_BASE64_FIELD, signatureValueBase64);
      return json;
    }

    /**
     * Returns a fresh decoded signature byte array.
     *
     * @return decoded detached Ed25519 signature bytes
     */
    public byte[] signatureBytes() {
      return Base64.getDecoder().decode(signatureValueBase64);
    }
  }
}
