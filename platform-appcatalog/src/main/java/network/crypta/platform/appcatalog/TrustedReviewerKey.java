package network.crypta.platform.appcatalog;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleSignature;

/**
 * Node-local public key that can authenticate independent app review receipts.
 *
 * <p>This value is the smallest unit of review trust: a stable reviewer key id, the public key that
 * verifies receipts from that reviewer, and optional operator-facing metadata. The key id is the
 * identifier receipts name in their canonical payload; it has no authority unless this object is
 * present in the node's {@link TrustedReviewerKeys} registry and the Ed25519 signature verifies
 * over the receipt payload bytes.
 *
 * <p>Reviewer keys are deliberately separate from catalog signing keys and app bundle signing keys.
 * Catalog signatures authenticate publisher metadata, bundle signatures authenticate artifacts, and
 * this key authenticates review evidence. Keeping those trust roots separate prevents a catalog
 * publisher from turning an advisory {@code review.status=reviewed} claim into a trusted review
 * without an independently configured reviewer key.
 *
 * <p>The optional policy id is a local constraint. When present, the verifier accepts receipts from
 * this key only if the receipt names the same review policy id. That allows operators to rotate or
 * narrow reviewer trust without changing app signing trust. The record stores only public
 * verification material; reviewer private keys are used by signing tools and must not be configured
 * here.
 *
 * @param keyId stable reviewer key id named by receipt payloads
 * @param algorithm signature algorithm supported by the key
 * @param publicKey public verification key used for Ed25519 receipt signatures
 * @param displayName optional operator-facing reviewer name for API and UI summaries
 * @param policyConstraint optional review policy id/version this reviewer key is trusted for
 * @param lifecycle local lifecycle governance metadata for this key
 */
public record TrustedReviewerKey(
    String keyId,
    String algorithm,
    PublicKey publicKey,
    Optional<String> displayName,
    TrustedReviewerPolicyConstraint policyConstraint,
    TrustedReviewerKeyLifecycle lifecycle) {
  /**
   * Signature algorithm accepted for review receipt signatures.
   *
   * <p>Review receipts currently use the same Ed25519 algorithm name as app bundle signatures, but
   * not the same trust registry. Sharing the algorithm constant does not imply that app signing
   * keys are valid reviewer keys.
   */
  public static final String SIGNATURE_ALGORITHM = AppBundleSignature.SIGNATURE_ALGORITHM;

  private static final Pattern PEM_HEADER_OR_FOOTER =
      Pattern.compile("-----BEGIN [^-]+-----|-----END [^-]+-----");
  private static final int MAX_KEY_ID_CHARS = 128;
  private static final int MAX_DISPLAY_NAME_CHARS = 128;

  /**
   * Creates an Ed25519 reviewer key from base64-encoded X.509 bytes or PEM text.
   *
   * <p>This factory is used by operator-facing configuration paths where key material is commonly
   * pasted as base64 text or stored as a PEM block. The decoded bytes must be an X.509
   * SubjectPublicKeyInfo public key; private key material is rejected by the Java key factory
   * rather than retained.
   *
   * @param keyId stable reviewer key id expected in receipt payloads
   * @param publicKeyMaterial X.509 public key bytes as base64 or PEM text
   * @param displayName display name exposed in review-trust summaries, or {@code null} when omitted
   * @param policyId review policy id this key is trusted for, or {@code null} when omitted
   * @return decoded trusted reviewer key
   */
  public static TrustedReviewerKey ed25519(
      String keyId, String publicKeyMaterial, String displayName, String policyId) {
    return ed25519(
        keyId,
        decodeBase64KeyMaterial(publicKeyMaterial),
        displayName,
        policyId,
        null,
        TrustedReviewerKeyLifecycle.ACTIVE);
  }

  /**
   * Creates an Ed25519 reviewer key from base64-encoded X.509 bytes or PEM text with lifecycle
   * governance metadata.
   *
   * @param keyId stable reviewer key id expected in receipt payloads
   * @param publicKeyMaterial X.509 public key bytes as base64 or PEM text
   * @param displayName display name exposed in review-trust summaries, or {@code null} when omitted
   * @param policyId review policy id this key is trusted for, or {@code null} when omitted
   * @param policyVersion review policy version this key is trusted for, or {@code null} when
   *     omitted
   * @param lifecycle reviewer-key lifecycle metadata
   * @return decoded trusted reviewer key
   */
  public static TrustedReviewerKey ed25519(
      String keyId,
      String publicKeyMaterial,
      String displayName,
      String policyId,
      String policyVersion,
      TrustedReviewerKeyLifecycle lifecycle) {
    return ed25519(
        keyId,
        decodeBase64KeyMaterial(publicKeyMaterial),
        displayName,
        policyId,
        policyVersion,
        lifecycle);
  }

  /**
   * Creates an Ed25519 reviewer key from X.509 key bytes.
   *
   * <p>This factory is useful for tests and callers that already decoded key files. The supplied
   * bytes are copied into a JCA {@link PublicKey}; callers do not need to keep the original byte
   * array after construction, and API-facing review decisions never expose it.
   *
   * @param keyId stable reviewer key id expected in receipt payloads
   * @param publicKeyBytes X.509 SubjectPublicKeyInfo key bytes
   * @param displayName display name exposed in review-trust summaries, or {@code null} when omitted
   * @param policyId review policy id this key is trusted for, or {@code null} when omitted
   * @return decoded trusted reviewer key
   */
  public static TrustedReviewerKey ed25519(
      String keyId, byte[] publicKeyBytes, String displayName, String policyId) {
    return ed25519(
        keyId, publicKeyBytes, displayName, policyId, null, TrustedReviewerKeyLifecycle.ACTIVE);
  }

  /**
   * Creates an Ed25519 reviewer key from X.509 key bytes with lifecycle governance metadata.
   *
   * @param keyId stable reviewer key id expected in receipt payloads
   * @param publicKeyBytes X.509 SubjectPublicKeyInfo key bytes
   * @param displayName display name exposed in review-trust summaries, or {@code null} when omitted
   * @param policyId review policy id this key is trusted for, or {@code null} when omitted
   * @param policyVersion review policy version this key is trusted for, or {@code null} when
   *     omitted
   * @param lifecycle reviewer-key lifecycle metadata
   * @return decoded trusted reviewer key
   */
  public static TrustedReviewerKey ed25519(
      String keyId,
      byte[] publicKeyBytes,
      String displayName,
      String policyId,
      String policyVersion,
      TrustedReviewerKeyLifecycle lifecycle) {
    try {
      PublicKey publicKey =
          KeyFactory.getInstance(SIGNATURE_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
      return new TrustedReviewerKey(
          keyId,
          SIGNATURE_ALGORITHM,
          publicKey,
          Optional.ofNullable(displayName),
          TrustedReviewerPolicyConstraint.of(policyId, policyVersion),
          Objects.requireNonNullElse(lifecycle, TrustedReviewerKeyLifecycle.ACTIVE));
    } catch (GeneralSecurityException | IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "failed to decode Ed25519 reviewer public key",
          exception);
    }
  }

  /**
   * Creates a validated reviewer key value.
   *
   * <p>All operator-controlled text is constrained to bounded single-line values so it can be
   * logged or serialized through Platform API summaries without introducing multiline diagnostics
   * or unstable output. The constructor does not verify receipts; it only validates the local trust
   * anchor metadata and stores the public verifier.
   */
  public TrustedReviewerKey {
    keyId =
        AppCatalogSidecars.requireBoundedSingleLine(
            keyId, "reviewer key id", AppCatalogSidecars.INVALID_CATALOG_ENTRY, MAX_KEY_ID_CHARS);
    algorithm =
        AppCatalogSidecars.requireNonBlankSingleLine(
            algorithm, "reviewer key algorithm", AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    Objects.requireNonNull(publicKey, "publicKey");
    Objects.requireNonNull(displayName, "displayName");
    displayName =
        displayName.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "reviewer display name",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_DISPLAY_NAME_CHARS));
    Objects.requireNonNull(policyConstraint, "policyConstraint");
    Objects.requireNonNull(lifecycle, "lifecycle");
  }

  /**
   * Returns the optional policy id constraint for source compatibility with older callers.
   *
   * @return configured policy id, when constrained
   */
  public Optional<String> policyId() {
    return policyConstraint.policyId();
  }

  /**
   * Returns the optional policy version constraint.
   *
   * @return configured policy version, when constrained
   */
  public Optional<String> policyVersion() {
    return policyConstraint.policyVersion();
  }

  /**
   * Returns the local lifecycle status.
   *
   * @return active, retired, or revoked
   */
  public TrustedReviewerKeyStatus status() {
    return lifecycle.status();
  }

  private static byte[] decodeBase64KeyMaterial(String material) {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
            Objects.requireNonNull(material, "publicKeyMaterial")
                .replace("\r", "")
                .replace("\n", ""),
            "reviewer public key material",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    String withoutPem = PEM_HEADER_OR_FOOTER.matcher(value).replaceAll("");
    String compact = withoutPem.replaceAll("\\s+", "");
    try {
      return Base64.getDecoder().decode(compact);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid reviewer public key material",
          exception);
    }
  }
}
