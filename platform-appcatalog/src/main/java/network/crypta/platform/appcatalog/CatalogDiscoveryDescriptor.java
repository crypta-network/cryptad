package network.crypta.platform.appcatalog;

import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Closed signed descriptor that recommends one public app catalog without granting local trust.
 *
 * <p>The descriptor contains public, bounded discovery metadata only. Its Ed25519 signature proves
 * that the configured issuer authenticated the canonical descriptor; it does not add a catalog
 * source, install issuer or catalog key material, authorize publishers or reviewers, or activate a
 * local catalog trust binding. Callers must pass a verified descriptor through a separate explicit
 * local-trust action before it can authorize catalog refresh, installation, or update.
 *
 * <p>Parsing applies a closed JSON schema, strict text and collection bounds, public-source URI
 * policy, and canonical timestamp handling. Canonical serializers preserve the exact digest and
 * signature subjects used by runtime import and release certification. The record and all nested
 * values are immutable; collection accessors return copies. Descriptor verification remains a
 * separate operation so a structurally valid document cannot be mistaken for an authenticated or
 * locally approved recommendation.
 *
 * @param content bounded public descriptor content covered by the self-digest
 * @param authentication self-digest and detached signature over the canonical signed payload
 */
public record CatalogDiscoveryDescriptor(Content content, Authentication authentication) {
  /** Supported closed descriptor schema version. */
  public static final int SCHEMA_VERSION = 1;

  private static final String DESCRIPTOR_ID_FIELD = "descriptorId";
  private static final String SUBJECT_FIELD = "subject";
  private static final String DISPLAY_FIELD = "display";
  private static final String TRANSPARENCY_FIELD = "transparency";
  private static final String VALIDITY_FIELD = "validity";
  private static final String ISSUER_FIELD = "issuer";
  private static final String SELF_DIGEST_SHA256_FIELD = "selfDigestSha256";
  private static final String SIGNATURE_FIELD = "signature";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String SIGNER_KEY_ID_FIELD = "signerKeyId";
  private static final String SIGNER_FINGERPRINT_SHA256_FIELD = "signerFingerprintSha256";
  private static final String SOURCE_HINTS_FIELD = "sourceHints";
  private static final String CHANNELS_FIELD = "channels";
  private static final String SUMMARY_FIELD = "summary";
  private static final String PROVIDER_ID_FIELD = "providerId";
  private static final String REVIEWER_SET_DIGEST_SHA256_FIELD = "reviewerSetDigestSha256";
  private static final String REVIEWER_SET_URI_FIELD = "reviewerSetUri";
  private static final String PUBLISHER_POLICY_DIGEST_SHA256_FIELD = "publisherPolicyDigestSha256";
  private static final String PUBLISHER_POLICY_URI_FIELD = "publisherPolicyUri";
  private static final String ISSUED_AT_FIELD = "issuedAt";
  private static final String EXPIRES_AT_FIELD = "expiresAt";
  private static final String PREDECESSOR_DIGEST_SHA256_FIELD = "predecessorDigestSha256";
  private static final String SUCCESSOR_DIGEST_SHA256_FIELD = "successorDigestSha256";
  private static final String ISSUER_ID_FIELD = "issuerId";
  private static final String KEY_ID_FIELD = "keyId";
  private static final String KEY_FINGERPRINT_SHA256_FIELD = "keyFingerprintSha256";
  private static final String ALGORITHM_FIELD = "algorithm";
  private static final String VALUE_BASE64_FIELD = "valueBase64";

  private static final Set<String> ROOT_REQUIRED =
      Set.of(
          "schemaVersion",
          DESCRIPTOR_ID_FIELD,
          SUBJECT_FIELD,
          DISPLAY_FIELD,
          TRANSPARENCY_FIELD,
          VALIDITY_FIELD,
          ISSUER_FIELD,
          SELF_DIGEST_SHA256_FIELD,
          SIGNATURE_FIELD);

  /** Validates a complete descriptor without evaluating local issuer trust. */
  public CatalogDiscoveryDescriptor {
    Objects.requireNonNull(content, "content");
    Objects.requireNonNull(authentication, "authentication");
  }

  /**
   * Parses an exact bounded UTF-8 JSON descriptor using a closed schema.
   *
   * @param bytes exact descriptor bytes
   * @return structurally validated descriptor
   * @throws AppCatalogException if JSON, fields, bounds, or URI policy are invalid
   */
  public static CatalogDiscoveryDescriptor parse(byte[] bytes) {
    Map<String, Object> root =
        CatalogSignedDocumentSupport.parseObject(
            bytes, "catalog discovery descriptor", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    CatalogSignedDocumentSupport.requireClosedObject(
        root,
        ROOT_REQUIRED,
        Set.of(),
        "catalog discovery descriptor",
        CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    int version =
        CatalogSignedDocumentSupport.requireVersion(
            root, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    String descriptorId =
        CatalogSignedDocumentSupport.requireString(
            root,
            DESCRIPTOR_ID_FIELD,
            DESCRIPTOR_ID_FIELD,
            CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    Content content =
        new Content(
            version,
            descriptorId,
            Subject.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    SUBJECT_FIELD,
                    SUBJECT_FIELD,
                    CatalogSignedDocumentSupport.INVALID_DESCRIPTOR)),
            Display.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    DISPLAY_FIELD,
                    DISPLAY_FIELD,
                    CatalogSignedDocumentSupport.INVALID_DESCRIPTOR)),
            Transparency.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    TRANSPARENCY_FIELD,
                    TRANSPARENCY_FIELD,
                    CatalogSignedDocumentSupport.INVALID_DESCRIPTOR)),
            Validity.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    VALIDITY_FIELD,
                    VALIDITY_FIELD,
                    CatalogSignedDocumentSupport.INVALID_DESCRIPTOR)),
            Issuer.parse(
                CatalogSignedDocumentSupport.requireObject(
                    root,
                    ISSUER_FIELD,
                    ISSUER_FIELD,
                    CatalogSignedDocumentSupport.INVALID_DESCRIPTOR)));
    Authentication authentication =
        Authentication.parse(
            CatalogSignedDocumentSupport.requireString(
                root,
                SELF_DIGEST_SHA256_FIELD,
                SELF_DIGEST_SHA256_FIELD,
                CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
            CatalogSignedDocumentSupport.requireObject(
                root,
                SIGNATURE_FIELD,
                SIGNATURE_FIELD,
                CatalogSignedDocumentSupport.INVALID_DESCRIPTOR));
    return new CatalogDiscoveryDescriptor(content, authentication);
  }

  /**
   * Returns deterministic content bytes used to calculate {@code selfDigestSha256}.
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
   * Returns deterministic complete JSON bytes, including the detached signature metadata.
   *
   * @return fresh canonical complete descriptor bytes
   */
  public byte[] canonicalDocumentBytes() {
    return CatalogSignedDocumentSupport.jsonBytes(toJsonValue());
  }

  /**
   * Returns a deterministic JSON-compatible descriptor object.
   *
   * @return insertion-ordered descriptor representation
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> document = content.toJsonValue();
    document.put(SELF_DIGEST_SHA256_FIELD, authentication.selfDigestSha256());
    document.put(SIGNATURE_FIELD, authentication.signatureJson());
    return document;
  }

  /**
   * Returns the exact normalized catalog ID recommended by this descriptor.
   *
   * @return normalized subject catalog identifier
   */
  public String catalogId() {
    return content.subject().catalogId();
  }

  /**
   * Returns the issuer key ID that must be resolved through local trusted key material.
   *
   * @return exact declared descriptor issuer key identifier
   */
  public String issuerKeyId() {
    return content.issuer().keyId();
  }

  /**
   * Public descriptor content independent of its digest and signature values.
   *
   * @param schemaVersion closed signed-descriptor schema version
   * @param descriptorId stable public identifier for this descriptor
   * @param subject exact catalog identity and bounded source hints
   * @param display bounded human-facing catalog description
   * @param transparency optional public policy-transparency references
   * @param validity descriptor freshness interval and optional digest lineage
   * @param issuer public identity that signed the descriptor
   */
  public record Content(
      int schemaVersion,
      String descriptorId,
      Subject subject,
      Display display,
      Transparency transparency,
      Validity validity,
      Issuer issuer) {
    /** Validates and normalizes public descriptor content. */
    public Content {
      if (schemaVersion != SCHEMA_VERSION) {
        throw CatalogSignedDocumentSupport.invalid(
            CatalogSignedDocumentSupport.INVALID_DESCRIPTOR, "schemaVersion must equal 1");
      }
      descriptorId =
          CatalogSignedDocumentSupport.requireId(
              descriptorId, DESCRIPTOR_ID_FIELD, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      Objects.requireNonNull(subject, SUBJECT_FIELD);
      Objects.requireNonNull(display, DISPLAY_FIELD);
      Objects.requireNonNull(transparency, TRANSPARENCY_FIELD);
      Objects.requireNonNull(validity, VALIDITY_FIELD);
      Objects.requireNonNull(issuer, ISSUER_FIELD);
    }

    /**
     * Returns the canonical content representation excluding authentication fields.
     *
     * @return insertion-ordered JSON-compatible content map
     */
    LinkedHashMap<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
      json.put("schemaVersion", schemaVersion);
      json.put(DESCRIPTOR_ID_FIELD, descriptorId);
      json.put(SUBJECT_FIELD, subject.toJsonValue());
      json.put(DISPLAY_FIELD, display.toJsonValue());
      json.put(TRANSPARENCY_FIELD, transparency.toJsonValue());
      json.put(VALIDITY_FIELD, validity.toJsonValue());
      json.put(ISSUER_FIELD, issuer.toJsonValue());
      return json;
    }
  }

  /**
   * Exact catalog identity, signing identity, public read hints, and supported channels.
   *
   * @param catalogId normalized catalog identifier being recommended
   * @param signerKeyId declared catalog signing-key identifier
   * @param signerFingerprintSha256 canonical catalog signing-key fingerprint
   * @param sourceHints bounded public read-only locations selected by the operator
   * @param channels bounded catalog channels advertised by the descriptor
   */
  public record Subject(
      String catalogId,
      String signerKeyId,
      String signerFingerprintSha256,
      List<URI> sourceHints,
      List<String> channels) {
    private static final Set<String> REQUIRED =
        Set.of(
            CATALOG_ID_FIELD,
            SIGNER_KEY_ID_FIELD,
            SIGNER_FINGERPRINT_SHA256_FIELD,
            SOURCE_HINTS_FIELD,
            CHANNELS_FIELD);

    /** Validates the descriptor subject without granting trust to the declared signer. */
    public Subject {
      catalogId =
          CatalogSignedDocumentSupport.requireCatalogId(
              catalogId, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      signerKeyId =
          CatalogSignedDocumentSupport.requireId(
              signerKeyId, "subject.signerKeyId", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      signerFingerprintSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              signerFingerprintSha256,
              "subject.signerFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      sourceHints = CatalogSignedDocumentSupport.requireSourceHints(sourceHints);
      channels =
          CatalogSignedDocumentSupport.requireUniqueLines(
              channels,
              "subject.channels",
              CatalogSignedDocumentSupport.MAX_CHANNELS,
              32,
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    }

    /**
     * Returns an immutable copy of the bounded public source hints.
     *
     * @return immutable public read-only source hints
     */
    @Override
    public List<URI> sourceHints() {
      return List.copyOf(sourceHints);
    }

    /**
     * Returns an immutable copy of the advertised catalog channels.
     *
     * @return immutable advertised channel values
     */
    @Override
    public List<String> channels() {
      return List.copyOf(channels);
    }

    /**
     * Parses the closed descriptor subject object.
     *
     * @param json parsed JSON-compatible subject object
     * @return validated immutable catalog subject
     */
    static Subject parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json, REQUIRED, Set.of(), SUBJECT_FIELD, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      List<URI> hints =
          CatalogSignedDocumentSupport.requireStrings(
                  json,
                  SOURCE_HINTS_FIELD,
                  "subject.sourceHints",
                  CatalogSignedDocumentSupport.INVALID_DESCRIPTOR)
              .stream()
              .map(CatalogSignedDocumentSupport::requireSourceHintUriText)
              .toList();
      return new Subject(
          CatalogSignedDocumentSupport.requireString(
              json,
              CATALOG_ID_FIELD,
              "subject.catalogId",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              json,
              SIGNER_KEY_ID_FIELD,
              "subject.signerKeyId",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              json,
              SIGNER_FINGERPRINT_SHA256_FIELD,
              "subject.signerFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          hints,
          CatalogSignedDocumentSupport.requireStrings(
              json,
              CHANNELS_FIELD,
              "subject.channels",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR));
    }

    /**
     * Returns the canonical descriptor-subject representation.
     *
     * @return insertion-ordered JSON-compatible subject map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(SIGNER_KEY_ID_FIELD, signerKeyId);
      json.put(SIGNER_FINGERPRINT_SHA256_FIELD, signerFingerprintSha256);
      json.put(SOURCE_HINTS_FIELD, sourceHints.stream().map(URI::toString).toList());
      json.put(CHANNELS_FIELD, channels);
      return json;
    }
  }

  /**
   * Bounded human-facing descriptor metadata with no contact or credential fields.
   *
   * @param name short catalog name shown to the local operator
   * @param summary bounded plain-text explanation of the catalog
   * @param providerId stable public provider identifier suitable for local display
   */
  public record Display(String name, String summary, String providerId) {
    private static final Set<String> REQUIRED = Set.of("name", SUMMARY_FIELD, PROVIDER_ID_FIELD);

    /** Validates the bounded display strings. */
    public Display {
      name =
          CatalogSignedDocumentSupport.requireBoundedLine(
              name,
              "display.name",
              CatalogSignedDocumentSupport.MAX_NAME_CHARS,
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      summary =
          CatalogSignedDocumentSupport.requireBoundedLine(
              summary,
              "display.summary",
              CatalogSignedDocumentSupport.MAX_SUMMARY_CHARS,
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      providerId =
          CatalogSignedDocumentSupport.requireId(
              providerId, "display.providerId", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    }

    /**
     * Parses the closed bounded display object.
     *
     * @param json parsed JSON-compatible display object
     * @return validated immutable display metadata
     */
    static Display parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json, REQUIRED, Set.of(), DISPLAY_FIELD, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      return new Display(
          CatalogSignedDocumentSupport.requireString(
              json, "name", "display.name", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              json,
              SUMMARY_FIELD,
              "display.summary",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              json,
              PROVIDER_ID_FIELD,
              "display.providerId",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR));
    }

    /**
     * Returns the canonical display representation.
     *
     * @return insertion-ordered JSON-compatible display map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put("name", name);
      json.put(SUMMARY_FIELD, summary);
      json.put(PROVIDER_ID_FIELD, providerId);
      return json;
    }
  }

  /**
   * Optional public reviewer-set and publisher-policy transparency references.
   *
   * @param reviewerSetDigestSha256 optional digest of public reviewer-set evidence
   * @param reviewerSetUri optional public read-only reviewer-set reference
   * @param publisherPolicyDigestSha256 optional digest of public publisher-policy evidence
   * @param publisherPolicyUri optional public read-only publisher-policy reference
   */
  public record Transparency(
      Optional<String> reviewerSetDigestSha256,
      Optional<URI> reviewerSetUri,
      Optional<String> publisherPolicyDigestSha256,
      Optional<URI> publisherPolicyUri) {
    private static final Set<String> OPTIONAL =
        Set.of(
            REVIEWER_SET_DIGEST_SHA256_FIELD,
            REVIEWER_SET_URI_FIELD,
            PUBLISHER_POLICY_DIGEST_SHA256_FIELD,
            PUBLISHER_POLICY_URI_FIELD);

    /** Validates optional public transparency evidence without accepting it as local policy. */
    public Transparency {
      reviewerSetDigestSha256 =
          CatalogSignedDocumentSupport.optionalSha256(
              Objects.requireNonNull(reviewerSetDigestSha256, REVIEWER_SET_DIGEST_SHA256_FIELD)
                  .orElse(null),
              "transparency.reviewerSetDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      reviewerSetUri =
          CatalogSignedDocumentSupport.optionalPublicReference(
              Objects.requireNonNull(reviewerSetUri, REVIEWER_SET_URI_FIELD).orElse(null),
              "transparency.reviewerSetUri");
      publisherPolicyDigestSha256 =
          CatalogSignedDocumentSupport.optionalSha256(
              Objects.requireNonNull(
                      publisherPolicyDigestSha256, PUBLISHER_POLICY_DIGEST_SHA256_FIELD)
                  .orElse(null),
              "transparency.publisherPolicyDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      publisherPolicyUri =
          CatalogSignedDocumentSupport.optionalPublicReference(
              Objects.requireNonNull(publisherPolicyUri, PUBLISHER_POLICY_URI_FIELD).orElse(null),
              "transparency.publisherPolicyUri");
    }

    /**
     * Parses optional public transparency references.
     *
     * @param json parsed JSON-compatible transparency object
     * @return validated immutable transparency metadata
     */
    static Transparency parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json,
          Set.of(),
          OPTIONAL,
          TRANSPARENCY_FIELD,
          CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      return new Transparency(
          CatalogSignedDocumentSupport.optionalString(
              json,
              REVIEWER_SET_DIGEST_SHA256_FIELD,
              "transparency.reviewerSetDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.optionalUri(
              json, REVIEWER_SET_URI_FIELD, "transparency.reviewerSetUri"),
          CatalogSignedDocumentSupport.optionalString(
              json,
              PUBLISHER_POLICY_DIGEST_SHA256_FIELD,
              "transparency.publisherPolicyDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.optionalUri(
              json, PUBLISHER_POLICY_URI_FIELD, "transparency.publisherPolicyUri"));
    }

    /**
     * Returns the canonical transparency representation.
     *
     * @return insertion-ordered JSON-compatible transparency map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
      reviewerSetDigestSha256.ifPresent(value -> json.put(REVIEWER_SET_DIGEST_SHA256_FIELD, value));
      reviewerSetUri.ifPresent(value -> json.put(REVIEWER_SET_URI_FIELD, value.toString()));
      publisherPolicyDigestSha256.ifPresent(
          value -> json.put(PUBLISHER_POLICY_DIGEST_SHA256_FIELD, value));
      publisherPolicyUri.ifPresent(value -> json.put(PUBLISHER_POLICY_URI_FIELD, value.toString()));
      return json;
    }
  }

  /**
   * Bounded descriptor freshness interval and optional digest lineage.
   *
   * @param issuedAt timestamp at which the issuer created this descriptor
   * @param expiresAt timestamp after which import must fail closed
   * @param predecessorDigestSha256 optional digest of the predecessor descriptor
   * @param successorDigestSha256 optional digest of an announced successor descriptor
   */
  public record Validity(
      Instant issuedAt,
      Instant expiresAt,
      Optional<String> predecessorDigestSha256,
      Optional<String> successorDigestSha256) {
    private static final Set<String> REQUIRED = Set.of(ISSUED_AT_FIELD, EXPIRES_AT_FIELD);
    private static final Set<String> OPTIONAL =
        Set.of(PREDECESSOR_DIGEST_SHA256_FIELD, SUCCESSOR_DIGEST_SHA256_FIELD);

    /** Validates the interval and optional digest lineage. */
    public Validity {
      CatalogSignedDocumentSupport.requireValidity(
          issuedAt, expiresAt, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      predecessorDigestSha256 =
          CatalogSignedDocumentSupport.optionalSha256(
              Objects.requireNonNull(predecessorDigestSha256, PREDECESSOR_DIGEST_SHA256_FIELD)
                  .orElse(null),
              "validity.predecessorDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      successorDigestSha256 =
          CatalogSignedDocumentSupport.optionalSha256(
              Objects.requireNonNull(successorDigestSha256, SUCCESSOR_DIGEST_SHA256_FIELD)
                  .orElse(null),
              "validity.successorDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    }

    /**
     * Parses the descriptor validity interval and digest lineage.
     *
     * @param json parsed JSON-compatible validity object
     * @return validated immutable validity metadata
     */
    static Validity parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json,
          REQUIRED,
          OPTIONAL,
          VALIDITY_FIELD,
          CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      return new Validity(
          CatalogSignedDocumentSupport.requireInstant(
              json,
              ISSUED_AT_FIELD,
              "validity.issuedAt",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireInstant(
              json,
              EXPIRES_AT_FIELD,
              "validity.expiresAt",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.optionalString(
              json,
              PREDECESSOR_DIGEST_SHA256_FIELD,
              "validity.predecessorDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.optionalString(
              json,
              SUCCESSOR_DIGEST_SHA256_FIELD,
              "validity.successorDigestSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR));
    }

    /**
     * Returns the canonical validity representation.
     *
     * @return insertion-ordered JSON-compatible validity map
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
      json.put(ISSUED_AT_FIELD, issuedAt.toString());
      json.put(EXPIRES_AT_FIELD, expiresAt.toString());
      predecessorDigestSha256.ifPresent(value -> json.put(PREDECESSOR_DIGEST_SHA256_FIELD, value));
      successorDigestSha256.ifPresent(value -> json.put(SUCCESSOR_DIGEST_SHA256_FIELD, value));
      return json;
    }
  }

  /**
   * Public issuer identity resolved against a separate local trusted-key registry.
   *
   * @param issuerId stable public identifier for the descriptor issuer
   * @param keyId issuer key identifier resolved through local trusted material
   * @param keyFingerprintSha256 canonical fingerprint of the issuer public key
   */
  public record Issuer(String issuerId, String keyId, String keyFingerprintSha256) {
    private static final Set<String> REQUIRED =
        Set.of(ISSUER_ID_FIELD, KEY_ID_FIELD, KEY_FINGERPRINT_SHA256_FIELD);

    /** Validates issuer identifiers and the declared public-key fingerprint. */
    public Issuer {
      issuerId =
          CatalogSignedDocumentSupport.requireId(
              issuerId, "issuer.issuerId", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      keyId =
          CatalogSignedDocumentSupport.requireId(
              keyId, "issuer.keyId", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      keyFingerprintSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              keyFingerprintSha256,
              "issuer.keyFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    }

    /**
     * Parses the closed public issuer identity object.
     *
     * @param json parsed JSON-compatible issuer object
     * @return validated immutable issuer identity
     */
    static Issuer parse(Map<String, Object> json) {
      CatalogSignedDocumentSupport.requireClosedObject(
          json, REQUIRED, Set.of(), ISSUER_FIELD, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      return new Issuer(
          CatalogSignedDocumentSupport.requireString(
              json,
              ISSUER_ID_FIELD,
              "issuer.issuerId",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              json, KEY_ID_FIELD, "issuer.keyId", CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              json,
              KEY_FINGERPRINT_SHA256_FIELD,
              "issuer.keyFingerprintSha256",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR));
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
   * @param selfDigestSha256 digest of the canonical descriptor content
   * @param signatureAlgorithm closed signature algorithm identifier
   * @param signatureValueBase64 bounded Base64-encoded detached signature value
   */
  public record Authentication(
      String selfDigestSha256, String signatureAlgorithm, String signatureValueBase64) {
    private static final Set<String> REQUIRED = Set.of(ALGORITHM_FIELD, VALUE_BASE64_FIELD);

    /** Validates digest, algorithm, and detached signature encoding. */
    public Authentication {
      selfDigestSha256 =
          CatalogSignedDocumentSupport.requireSha256(
              selfDigestSha256,
              SELF_DIGEST_SHA256_FIELD,
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      signatureAlgorithm =
          CatalogSignedDocumentSupport.requireAlgorithm(
              signatureAlgorithm, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      signatureValueBase64 =
          CatalogSignedDocumentSupport.requireSignatureBase64(
              signatureValueBase64, CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
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
          CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
      return new Authentication(
          digest,
          CatalogSignedDocumentSupport.requireString(
              signature,
              ALGORITHM_FIELD,
              "signature.algorithm",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR),
          CatalogSignedDocumentSupport.requireString(
              signature,
              VALUE_BASE64_FIELD,
              "signature.valueBase64",
              CatalogSignedDocumentSupport.INVALID_DESCRIPTOR));
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
