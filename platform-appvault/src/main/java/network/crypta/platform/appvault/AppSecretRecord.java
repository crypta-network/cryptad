package network.crypta.platform.appvault;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Redacted metadata for one app-owned secret.
 *
 * <p>The record intentionally carries no secret value, ciphertext, local path, or key material. It
 * is safe for list/status responses and Web Shell summaries. Caller-supplied metadata is already
 * normalized and sensitive-looking values are replaced with {@link AppVaultMetadata#REDACTED_VALUE}
 * before the record is stored.
 *
 * <p>The secret name and app id are part of the authenticated envelope AAD used for the encrypted
 * value. That means copied or misplaced metadata will not decrypt as another app's secret, and
 * listing code can validate that directory names still match the embedded metadata.
 *
 * @param appId app id that owns the secret
 * @param secretName normalized app-local secret name
 * @param secretKind caller-supplied kind label for operator and app metadata views
 * @param createdAt original creation timestamp bound into the value envelope AAD
 * @param updatedAt most recent metadata or value update timestamp
 * @param lastUsedAt optional timestamp of the most recent successful value read
 * @param sizeClass coarse value-size bucket that avoids exposing exact secret length
 * @param metadata redacted caller-supplied metadata safe for public summaries
 */
public record AppSecretRecord(
    String appId,
    String secretName,
    String secretKind,
    Instant createdAt,
    Instant updatedAt,
    Instant lastUsedAt,
    String sizeClass,
    Map<String, String> metadata) {
  /**
   * Creates a validated redacted secret metadata record.
   *
   * <p>The constructor normalizes app and secret names, requires non-blank kind and size-class
   * values, and defensively copies metadata. It does not accept or expose the plaintext secret
   * value; value bytes live only in encrypted envelopes managed by the store.
   */
  public AppSecretRecord {
    appId = AppVaultPaths.normalizeAppId(appId);
    secretName = AppVaultPaths.normalizeSecretName(secretName);
    secretKind = requireText(secretKind, "secretKind");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    sizeClass = requireText(sizeClass, "sizeClass");
    metadata = Map.copyOf(Objects.requireNonNull(metadata, "metadata"));
  }

  @Override
  public @NotNull String toString() {
    return "AppSecretRecord[appId="
        + appId
        + ", secretName="
        + secretName
        + ", secretKind="
        + secretKind
        + ", sizeClass="
        + sizeClass
        + ", value=<redacted>]";
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
