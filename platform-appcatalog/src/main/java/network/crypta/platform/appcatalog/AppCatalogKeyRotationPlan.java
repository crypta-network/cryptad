package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Operator-safe catalog signing-key rotation plan metadata.
 *
 * <p>This record intentionally carries key ids and timestamps only. It never stores public key
 * bytes, private key material, key files, command lines, or secret-bearing source data.
 */
public record AppCatalogKeyRotationPlan(
    Optional<String> nextKeyId,
    Optional<Instant> startsAt,
    Optional<Instant> endsAt,
    Optional<String> message) {
  /** Creates validated plan metadata. */
  public AppCatalogKeyRotationPlan {
    Objects.requireNonNull(nextKeyId, "nextKeyId");
    Objects.requireNonNull(startsAt, "startsAt");
    Objects.requireNonNull(endsAt, "endsAt");
    Objects.requireNonNull(message, "message");
  }

  /** Returns an empty local plan. */
  public static AppCatalogKeyRotationPlan empty() {
    return new AppCatalogKeyRotationPlan(
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
  }
}
