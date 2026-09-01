package network.crypta.platform.apphost;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleManifest;

/**
 * Host-owned, path-free provenance for one catalog-installed app revision.
 *
 * <p>The record binds installed bytes to the authenticated catalog revision, publisher, review
 * evidence, and exact local trust policies that authorized the operation. App processes and app
 * browser principals do not receive write access to this record. A source switch links to the prior
 * origin by digest, while rollback restores the previously stored record together with the prior
 * bundle bytes. Values contain public identities and digests only; source URIs, tokens, private
 * paths, and raw catalog or app content are deliberately excluded.
 *
 * @param schemaVersion closed persistent-record schema version
 * @param appId normalized application identifier owned by this origin
 * @param appVersion exact installed application version string
 * @param bundleSha256 SHA-256 digest of the installed bundle bytes
 * @param catalogId authenticated catalog identifier that supplied the revision
 * @param catalogSignerKeyId catalog signature key identifier used for authentication
 * @param catalogSignerFingerprintSha256 canonical catalog signing-key fingerprint
 * @param catalogRevisionDigestSha256 authenticated catalog revision subject digest
 * @param publisherKeyId publisher signature key identifier verified for the bundle
 * @param publisherKeyFingerprintSha256 canonical app-publisher key fingerprint
 * @param signedContentDigestSha256 SHA-256 of the exact signed digest-sidecar bytes verified from
 *     the installed bundle
 * @param reviewReceiptFingerprintSha256 verified review-receipt fingerprint or empty digest marker
 * @param reviewStatus bounded local status of the verified review evidence
 * @param catalogTrustBindingId local catalog trust binding that authorized installation
 * @param catalogTrustBindingDigestSha256 exact digest of the authorizing catalog trust binding
 * @param publisherPolicyDigestSha256 exact local publisher-policy digest used for authorization
 * @param reviewerPolicyDigestSha256 exact local reviewer-policy digest used for authorization
 * @param installedAt host timestamp for the completed install or update
 * @param previousOriginDigestSha256 prior provenance digest for an explicit source switch
 * @param selfDigestSha256 digest binding every preceding record field
 */
public record InstalledAppOrigin(
    int schemaVersion,
    String appId,
    String appVersion,
    String bundleSha256,
    String catalogId,
    String catalogSignerKeyId,
    String catalogSignerFingerprintSha256,
    String catalogRevisionDigestSha256,
    String publisherKeyId,
    String publisherKeyFingerprintSha256,
    String signedContentDigestSha256,
    String reviewReceiptFingerprintSha256,
    String reviewStatus,
    String catalogTrustBindingId,
    String catalogTrustBindingDigestSha256,
    String publisherPolicyDigestSha256,
    String reviewerPolicyDigestSha256,
    Instant installedAt,
    Optional<String> previousOriginDigestSha256,
    String selfDigestSha256) {
  public static final int CURRENT_SCHEMA_VERSION = 2;
  static final int LEGACY_SCHEMA_VERSION = 1;
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

  /** Validates and self-digests one immutable provenance record. */
  public InstalledAppOrigin {
    if (schemaVersion != LEGACY_SCHEMA_VERSION && schemaVersion != CURRENT_SCHEMA_VERSION) {
      throw new IllegalArgumentException("unsupported installed-origin schema version");
    }
    appId = AppBundleManifest.normalizeAppId(appId);
    appVersion = text(appVersion, "appVersion");
    requireDigest(bundleSha256, "bundleSha256", false);
    catalogId = text(catalogId, "catalogId");
    catalogSignerKeyId = text(catalogSignerKeyId, "catalogSignerKeyId");
    requireDigest(catalogSignerFingerprintSha256, "catalogSignerFingerprintSha256", true);
    requireDigest(catalogRevisionDigestSha256, "catalogRevisionDigestSha256", false);
    publisherKeyId = text(publisherKeyId, "publisherKeyId");
    requireDigest(publisherKeyFingerprintSha256, "publisherKeyFingerprintSha256", true);
    requireDigest(signedContentDigestSha256, "signedContentDigestSha256", true);
    if (schemaVersion == CURRENT_SCHEMA_VERSION
        && publisherKeyFingerprintSha256.isEmpty() != signedContentDigestSha256.isEmpty()) {
      throw new IllegalArgumentException(
          "publisher fingerprint and signed-content digest must both be present or absent");
    }
    requireDigest(reviewReceiptFingerprintSha256, "reviewReceiptFingerprintSha256", true);
    reviewStatus = text(reviewStatus, "reviewStatus");
    catalogTrustBindingId = text(catalogTrustBindingId, "catalogTrustBindingId");
    requireDigest(catalogTrustBindingDigestSha256, "catalogTrustBindingDigestSha256", true);
    requireDigest(publisherPolicyDigestSha256, "publisherPolicyDigestSha256", true);
    requireDigest(reviewerPolicyDigestSha256, "reviewerPolicyDigestSha256", true);
    Objects.requireNonNull(installedAt, "installedAt");
    Objects.requireNonNull(previousOriginDigestSha256, "previousOriginDigestSha256")
        .ifPresent(value -> requireDigest(value, "previousOriginDigestSha256", false));
    String computed =
        sha256(
            canonicalWithoutDigest(
                schemaVersion,
                appId,
                appVersion,
                bundleSha256,
                catalogId,
                catalogSignerKeyId,
                catalogSignerFingerprintSha256,
                catalogRevisionDigestSha256,
                publisherKeyId,
                publisherKeyFingerprintSha256,
                signedContentDigestSha256,
                reviewReceiptFingerprintSha256,
                reviewStatus,
                catalogTrustBindingId,
                catalogTrustBindingDigestSha256,
                publisherPolicyDigestSha256,
                reviewerPolicyDigestSha256,
                installedAt,
                previousOriginDigestSha256.orElse(null)));
    if (selfDigestSha256 == null) {
      selfDigestSha256 = computed;
    } else {
      requireDigest(selfDigestSha256, "selfDigestSha256", false);
      if (!computed.equals(selfDigestSha256)) {
        throw new IllegalArgumentException("installed-origin self digest does not match content");
      }
    }
  }

  /**
   * Creates a new provenance record and computes its self digest.
   *
   * <p>The caller supplies the identities and policy digests already authenticated by the catalog
   * install or update plan. The constructor normalizes bounded identifiers and rejects malformed
   * digests before returning the immutable record.
   *
   * @param appId normalized application identifier for the installed bundle
   * @param appVersion exact application version reported by the verified manifest
   * @param bundleSha256 SHA-256 digest of the installed bundle bytes
   * @param catalogId authenticated catalog identifier that supplied the bundle
   * @param catalogSignerKeyId catalog signature key identifier used for authentication
   * @param catalogSignerFingerprintSha256 canonical catalog signing-key fingerprint
   * @param catalogRevisionDigestSha256 authenticated catalog revision subject digest
   * @param publisherKeyId publisher key identifier verified against the app bundle
   * @param publisherKeyFingerprintSha256 canonical app-publisher key fingerprint
   * @param signedContentDigestSha256 SHA-256 of the exact signed digest-sidecar bytes
   * @param reviewReceiptFingerprintSha256 verified review-receipt fingerprint or empty marker
   * @param reviewStatus bounded status of the review evidence used by policy
   * @param catalogTrustBindingId local catalog trust binding that authorized the operation
   * @param catalogTrustBindingDigestSha256 exact digest of that catalog trust binding
   * @param publisherPolicyDigestSha256 exact local publisher-policy digest used for authorization
   * @param reviewerPolicyDigestSha256 exact local reviewer-policy digest used for authorization
   * @param installedAt host timestamp for the completed install or update
   * @param previousOriginDigestSha256 nullable prior origin digest for source-switch audit
   * @return immutable validated provenance with its self-digest populated
   */
  public static InstalledAppOrigin create(
      String appId,
      String appVersion,
      String bundleSha256,
      String catalogId,
      String catalogSignerKeyId,
      String catalogSignerFingerprintSha256,
      String catalogRevisionDigestSha256,
      String publisherKeyId,
      String publisherKeyFingerprintSha256,
      String signedContentDigestSha256,
      String reviewReceiptFingerprintSha256,
      String reviewStatus,
      String catalogTrustBindingId,
      String catalogTrustBindingDigestSha256,
      String publisherPolicyDigestSha256,
      String reviewerPolicyDigestSha256,
      Instant installedAt,
      String previousOriginDigestSha256) {
    return new InstalledAppOrigin(
        CURRENT_SCHEMA_VERSION,
        appId,
        appVersion,
        bundleSha256,
        catalogId,
        catalogSignerKeyId,
        catalogSignerFingerprintSha256,
        catalogRevisionDigestSha256,
        publisherKeyId,
        publisherKeyFingerprintSha256,
        signedContentDigestSha256,
        reviewReceiptFingerprintSha256,
        reviewStatus,
        catalogTrustBindingId,
        catalogTrustBindingDigestSha256,
        publisherPolicyDigestSha256,
        reviewerPolicyDigestSha256,
        installedAt,
        Optional.ofNullable(previousOriginDigestSha256),
        null);
  }

  /**
   * Serializes the complete provenance record including its self-digest.
   *
   * @return deterministic newline-terminated record text
   */
  String canonicalText() {
    return canonicalWithoutDigest(
            schemaVersion,
            appId,
            appVersion,
            bundleSha256,
            catalogId,
            catalogSignerKeyId,
            catalogSignerFingerprintSha256,
            catalogRevisionDigestSha256,
            publisherKeyId,
            publisherKeyFingerprintSha256,
            signedContentDigestSha256,
            reviewReceiptFingerprintSha256,
            reviewStatus,
            catalogTrustBindingId,
            catalogTrustBindingDigestSha256,
            publisherPolicyDigestSha256,
            reviewerPolicyDigestSha256,
            installedAt,
            previousOriginDigestSha256.orElse(null))
        + "selfDigestSha256="
        + selfDigestSha256
        + '\n';
  }

  /**
   * Builds the canonical provenance text covered by the record self-digest.
   *
   * @param schemaVersion closed provenance schema version
   * @param appId exact application identity
   * @param appVersion installed application version
   * @param bundleSha256 digest of the installed bundle bytes
   * @param catalogId authenticated source catalog identity
   * @param catalogSignerKeyId authenticated catalog signer key ID
   * @param catalogSignerFingerprintSha256 catalog signer fingerprint
   * @param catalogRevisionDigestSha256 authenticated catalog revision digest
   * @param publisherKeyId verified app publisher key ID
   * @param publisherKeyFingerprintSha256 verified publisher fingerprint
   * @param signedContentDigestSha256 exact signed bundle-content digest
   * @param reviewReceiptFingerprintSha256 accepted review receipt fingerprint
   * @param reviewStatus accepted review status
   * @param catalogTrustBindingId local catalog trust-binding ID
   * @param catalogTrustBindingDigestSha256 local trust-binding digest
   * @param publisherPolicyDigestSha256 accepted publisher-policy digest
   * @param reviewerPolicyDigestSha256 accepted reviewer-policy digest
   * @param installedAt installation or update timestamp
   * @param previousOriginDigestSha256 optional digest of the preceding origin
   * @return deterministic newline-terminated digest subject
   */
  private static String canonicalWithoutDigest(
      int schemaVersion,
      String appId,
      String appVersion,
      String bundleSha256,
      String catalogId,
      String catalogSignerKeyId,
      String catalogSignerFingerprintSha256,
      String catalogRevisionDigestSha256,
      String publisherKeyId,
      String publisherKeyFingerprintSha256,
      String signedContentDigestSha256,
      String reviewReceiptFingerprintSha256,
      String reviewStatus,
      String catalogTrustBindingId,
      String catalogTrustBindingDigestSha256,
      String publisherPolicyDigestSha256,
      String reviewerPolicyDigestSha256,
      Instant installedAt,
      String previousOriginDigestSha256) {
    return "schemaVersion="
        + schemaVersion
        + '\n'
        + "appId="
        + appId
        + '\n'
        + "appVersion="
        + appVersion
        + '\n'
        + "bundleSha256="
        + bundleSha256
        + '\n'
        + "catalogId="
        + catalogId
        + '\n'
        + "catalogSignerKeyId="
        + catalogSignerKeyId
        + '\n'
        + "catalogSignerFingerprintSha256="
        + catalogSignerFingerprintSha256
        + '\n'
        + "catalogRevisionDigestSha256="
        + catalogRevisionDigestSha256
        + '\n'
        + "publisherKeyId="
        + publisherKeyId
        + '\n'
        + "publisherKeyFingerprintSha256="
        + publisherKeyFingerprintSha256
        + '\n'
        + (schemaVersion == CURRENT_SCHEMA_VERSION
            ? "signedContentDigestSha256=" + signedContentDigestSha256 + '\n'
            : "")
        + "reviewReceiptFingerprintSha256="
        + reviewReceiptFingerprintSha256
        + '\n'
        + "reviewStatus="
        + reviewStatus
        + '\n'
        + "catalogTrustBindingId="
        + catalogTrustBindingId
        + '\n'
        + "catalogTrustBindingDigestSha256="
        + catalogTrustBindingDigestSha256
        + '\n'
        + "publisherPolicyDigestSha256="
        + publisherPolicyDigestSha256
        + '\n'
        + "reviewerPolicyDigestSha256="
        + reviewerPolicyDigestSha256
        + '\n'
        + "installedAt="
        + installedAt
        + '\n'
        + "previousOriginDigestSha256="
        + Objects.requireNonNullElse(previousOriginDigestSha256, "")
        + '\n';
  }

  /**
   * Requires normalized nonblank single-line provenance text.
   *
   * @param value provenance field value
   * @param name field name used in failures
   * @return trimmed validated text
   */
  private static String text(String value, String name) {
    String checked = Objects.requireNonNull(value, name).trim();
    if (checked.isEmpty() || checked.indexOf('\n') >= 0 || checked.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(name + " must be a non-blank single line");
    }
    return checked;
  }

  /**
   * Requires a canonical lowercase SHA-256 digest, optionally allowing empty text.
   *
   * @param value digest field value
   * @param name field name used in failures
   * @param optional whether the canonical empty value is permitted
   */
  private static void requireDigest(String value, String name, boolean optional) {
    String checked = Objects.requireNonNull(value, name);
    if (optional && checked.isEmpty()) {
      return;
    }
    if (!SHA256.matcher(checked).matches()) {
      throw new IllegalArgumentException(name + " must be lowercase SHA-256");
    }
  }

  /**
   * Computes lowercase SHA-256 over UTF-8 provenance text.
   *
   * @param value canonical digest subject
   * @return lowercase hexadecimal SHA-256 digest
   */
  private static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 unavailable", exception);
    }
  }
}
