package network.crypta.platform.appcatalog;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Operator-safe signing-key rotation status for one catalog.
 *
 * <p>The status is derived from verified catalog signatures, retained revision history, and the
 * current trusted-key registry. It exposes only key ids, booleans, and bounded blocker reasons.
 */
public record AppCatalogKeyRotationStatus(
    String status,
    Optional<String> currentKeyId,
    Optional<String> previousKeyId,
    boolean currentKeyTrusted,
    AppCatalogKeyRotationPlan plan,
    List<String> blockerReasons) {
  /** Creates validated status metadata. */
  public AppCatalogKeyRotationStatus {
    status =
        AppCatalogSidecars.requireNonBlankSingleLine(
            status, "rotation.status", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    Objects.requireNonNull(currentKeyId, "currentKeyId");
    Objects.requireNonNull(previousKeyId, "previousKeyId");
    Objects.requireNonNull(plan, "plan");
    blockerReasons = List.copyOf(Objects.requireNonNull(blockerReasons, "blockerReasons"));
  }
}
