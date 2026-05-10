package network.crypta.platform.appvault;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.jetbrains.annotations.NotNull;

/**
 * Public metadata for one vault-managed identity.
 *
 * <p>The record is safe to return through Platform API identity list and detail routes. It contains
 * identity ids, kind, label, owner app id, public summary fields, fingerprint, and supported usage
 * scopes. It never carries private key bytes, encrypted private envelopes, local filesystem paths,
 * or wrapping-key identifiers.
 *
 * <p>{@code ownerAppId} distinguishes app-owned identities from operator-managed shared identities.
 * Ownership does not by itself authorize use; app-facing code still relies on active grants so
 * revocation and uninstall cleanup can stop access consistently.
 *
 * @param identityId durable identity id used by grants and route paths
 * @param kind identity implementation kind that controls supported operations
 * @param label operator-facing display label
 * @param ownerAppId optional app id that owns the identity metadata
 * @param createdAt creation timestamp used in AAD and management displays
 * @param updatedAt most recent metadata update timestamp
 * @param publicSummary public kind-specific metadata, such as encoded public keys
 * @param fingerprint stable public fingerprint for comparison and display
 * @param usageScopes operations this identity kind and record can support
 */
public record AppIdentityRecord(
    String identityId,
    AppIdentityKind kind,
    String label,
    String ownerAppId,
    Instant createdAt,
    Instant updatedAt,
    Map<String, String> publicSummary,
    String fingerprint,
    Set<AppIdentityGrantScope> usageScopes) {
  /**
   * Creates a validated identity metadata record.
   *
   * <p>Identifiers are normalized to vault-safe forms, optional ownership is normalized to an app
   * id, and maps and scope sets are defensively copied. The constructor rejects blank labels and
   * fingerprints because those values appear in operator-visible summaries.
   */
  public AppIdentityRecord {
    identityId = AppVaultPaths.normalizeIdentityId(identityId);
    Objects.requireNonNull(kind, "kind");
    label = requireText(label, "label");
    ownerAppId =
        ownerAppId == null || ownerAppId.isBlank()
            ? null
            : AppVaultPaths.normalizeAppId(ownerAppId);
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    publicSummary = Map.copyOf(Objects.requireNonNull(publicSummary, "publicSummary"));
    fingerprint = requireText(fingerprint, "fingerprint");
    usageScopes = Set.copyOf(new TreeSet<>(Objects.requireNonNull(usageScopes, "usageScopes")));
  }

  @Override
  public @NotNull String toString() {
    return "AppIdentityRecord[identityId="
        + identityId
        + ", kind="
        + kind.jsonValue()
        + ", ownerAppId="
        + ownerAppId
        + ", fingerprint="
        + fingerprint
        + ", privateKey=<redacted>]";
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
