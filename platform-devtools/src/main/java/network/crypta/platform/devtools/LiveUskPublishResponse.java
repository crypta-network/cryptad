package network.crypta.platform.devtools;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Sanitized response from a live USK insertion adapter.
 *
 * <p>The response contains only status labels, public or already-sanitized fetch metadata, and
 * bounded warnings. It must never include private insert URIs, form passwords, local staging paths,
 * raw request bodies, raw node response bodies, or key material.
 *
 * @param catalogInsertStatus status for the catalog properties sidecar
 * @param signatureInsertStatus status for the signature sidecar
 * @param resolvedCatalogSource resolved public catalog source, when verified or reported
 * @param postPublishVerificationStatus status of optional live fetch verification
 * @param schedulerRefreshVerificationStatus status of scheduler/catalog-refresh compatibility
 * @param warnings sanitized warnings to include in the final summary
 */
record LiveUskPublishResponse(
    String catalogInsertStatus,
    String signatureInsertStatus,
    Optional<String> resolvedCatalogSource,
    String postPublishVerificationStatus,
    String schedulerRefreshVerificationStatus,
    List<String> warnings) {
  /**
   * Validates optional metadata and normalizes nullable warning lists at the publisher boundary.
   *
   * <p>Publisher implementations are intentionally small adapters around external node behavior, so
   * this constructor keeps the stricter rule that optional metadata is represented by a non-null
   * {@link Optional}. The copied warning list prevents later mutation from changing the publication
   * evidence after the service has built its final summary.
   */
  LiveUskPublishResponse {
    Objects.requireNonNull(resolvedCatalogSource, "resolvedCatalogSource");
    warnings = warnings == null ? List.of() : List.copyOf(warnings);
  }
}
