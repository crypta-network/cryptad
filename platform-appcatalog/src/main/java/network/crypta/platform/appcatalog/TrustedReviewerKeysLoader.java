package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Loads trusted reviewer keys from node-local system properties and environment variables.
 *
 * <p>The loader is the bridge between operator configuration and the immutable {@link
 * TrustedReviewerKeys} registry used by receipt verification. It supports a properties-file trust
 * registry and an optional direct reviewer key for simple deployments or tests. System properties
 * take precedence over environment variables for each setting, matching the rest of the
 * app-platform configuration style.
 *
 * <p>The configuration names are intentionally separate from AppHost app-signing and
 * catalog-signing keys. A node that trusts a key for app bundle verification does not automatically
 * trust it for review receipts, and a reviewer key loaded here never grants bundle-signing
 * authority. Only public key material is accepted; private reviewer keys are used by offline
 * signing commands and must not be provided to daemon configuration.
 */
public final class TrustedReviewerKeysLoader {
  /**
   * System property naming a trusted reviewer keys properties file.
   *
   * <p>The file may contain multiple reviewer keys with display names and policy ids, and is the
   * preferred form for operator-managed trust roots.
   */
  public static final String TRUSTED_REVIEWER_KEYS_FILE_PROPERTY =
      "cryptad.appreview.trustedReviewerKeysFile";

  /**
   * Environment variable naming a trusted reviewer keys properties file.
   *
   * <p>This value is used only when {@link #TRUSTED_REVIEWER_KEYS_FILE_PROPERTY} is absent or
   * blank.
   */
  public static final String TRUSTED_REVIEWER_KEYS_FILE_ENV =
      "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEYS_FILE";

  /**
   * System property naming the key id for a directly configured reviewer key.
   *
   * <p>The id must match the {@code review.receipt.reviewer.key.id} field in receipts signed by the
   * corresponding public key.
   */
  public static final String TRUSTED_REVIEWER_KEY_ID_PROPERTY =
      "cryptad.appreview.trustedReviewerKeyId";

  /**
   * Environment variable naming the key id for a directly configured reviewer key.
   *
   * <p>This value is used only when {@link #TRUSTED_REVIEWER_KEY_ID_PROPERTY} is absent or blank.
   */
  public static final String TRUSTED_REVIEWER_KEY_ID_ENV =
      "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEY_ID";

  /**
   * System property containing direct reviewer public key material.
   *
   * <p>The value is parsed as base64-encoded X.509 SubjectPublicKeyInfo bytes, with PEM armor also
   * accepted when it fits in configuration text. It is mutually exclusive with {@link
   * #TRUSTED_REVIEWER_PUBLIC_KEY_FILE_PROPERTY}.
   */
  public static final String TRUSTED_REVIEWER_PUBLIC_KEY_BASE64_PROPERTY =
      "cryptad.appreview.trustedReviewerPublicKeyBase64";

  /**
   * Environment variable containing direct reviewer public key material.
   *
   * <p>This value is used only when {@link #TRUSTED_REVIEWER_PUBLIC_KEY_BASE64_PROPERTY} is absent
   * or blank and is mutually exclusive with {@link #TRUSTED_REVIEWER_PUBLIC_KEY_FILE_ENV}.
   */
  public static final String TRUSTED_REVIEWER_PUBLIC_KEY_BASE64_ENV =
      "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_PUBLIC_KEY_BASE64";

  /**
   * System property naming a file containing one direct reviewer public key.
   *
   * <p>The file may contain base64 text, PEM text, or raw X.509 public key bytes. The configured
   * path is read locally and never included in review-trust API responses.
   */
  public static final String TRUSTED_REVIEWER_PUBLIC_KEY_FILE_PROPERTY =
      "cryptad.appreview.trustedReviewerPublicKeyFile";

  /**
   * Environment variable naming a file containing one direct reviewer public key.
   *
   * <p>This value is used only when {@link #TRUSTED_REVIEWER_PUBLIC_KEY_FILE_PROPERTY} is absent or
   * blank.
   */
  public static final String TRUSTED_REVIEWER_PUBLIC_KEY_FILE_ENV =
      "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_PUBLIC_KEY_FILE";

  private TrustedReviewerKeysLoader() {}

  /**
   * Loads reviewer keys from system properties and environment variables.
   *
   * <p>If a keys-file source is configured, it is loaded first. A direct key source can then add
   * one additional key, but it must provide both a key id and exactly one public-key material
   * source: inline base64/PEM text or a public-key file. Duplicate key ids are rejected by the
   * resulting registry so a direct key cannot silently replace a file-managed reviewer.
   *
   * <p>When no reviewer trust source is configured, this method returns an empty registry. That
   * keeps older catalogs readable while causing independent receipt verification to report that
   * review trust is not configured rather than promoting publisher advisory metadata.
   *
   * @return configured reviewer-key registry, or empty when no trust source is configured
   * @throws IOException if a configured key file cannot be read
   */
  public static TrustedReviewerKeys loadFromSystem() throws IOException {
    Path keysFile =
        configuredPath(TRUSTED_REVIEWER_KEYS_FILE_PROPERTY, TRUSTED_REVIEWER_KEYS_FILE_ENV);
    TrustedReviewerKeys keys =
        keysFile == null ? TrustedReviewerKeys.empty() : TrustedReviewerKeys.load(keysFile);
    String directKeyId =
        configuredValue(TRUSTED_REVIEWER_KEY_ID_PROPERTY, TRUSTED_REVIEWER_KEY_ID_ENV);
    String directPublicKey =
        configuredValue(
            TRUSTED_REVIEWER_PUBLIC_KEY_BASE64_PROPERTY, TRUSTED_REVIEWER_PUBLIC_KEY_BASE64_ENV);
    Path directPublicKeyFile =
        configuredPath(
            TRUSTED_REVIEWER_PUBLIC_KEY_FILE_PROPERTY, TRUSTED_REVIEWER_PUBLIC_KEY_FILE_ENV);
    int directSources = (directPublicKey == null ? 0 : 1) + (directPublicKeyFile == null ? 0 : 1);
    if (directSources == 0) {
      return keys;
    }
    if (directSources > 1) {
      throw AppCatalogSidecars.invalidEntry(
          "trusted reviewer public key material must be configured by base64 or file, not both");
    }
    if (directKeyId == null || directKeyId.isBlank()) {
      throw AppCatalogSidecars.invalidEntry("missing trusted reviewer key id");
    }
    TrustedReviewerKey directKey =
        directPublicKey != null
            ? TrustedReviewerKey.ed25519(directKeyId, directPublicKey, null, null)
            : loadPublicKeyFile(directKeyId, directPublicKeyFile);
    return keys.plus(directKey);
  }

  private static TrustedReviewerKey loadPublicKeyFile(String keyId, Path file) throws IOException {
    byte[] bytes = Files.readAllBytes(file);
    String text = new String(bytes, StandardCharsets.UTF_8);
    try {
      return TrustedReviewerKey.ed25519(keyId, text, null, null);
    } catch (AppCatalogException textFailure) {
      try {
        return TrustedReviewerKey.ed25519(keyId, bytes, null, null);
      } catch (AppCatalogException rawFailure) {
        rawFailure.addSuppressed(textFailure);
        throw rawFailure;
      }
    }
  }

  private static Path configuredPath(String propertyName, String environmentName) {
    String value = configuredValue(propertyName, environmentName);
    return value == null ? null : Path.of(value).toAbsolutePath().normalize();
  }

  private static String configuredValue(String propertyName, String environmentName) {
    String propertyValue = System.getProperty(propertyName);
    if (propertyValue != null && !propertyValue.isBlank()) {
      return propertyValue.trim();
    }
    String environmentValue = System.getenv(environmentName);
    return environmentValue == null || environmentValue.isBlank() ? null : environmentValue.trim();
  }
}
