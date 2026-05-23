package network.crypta.platform.devtools;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Report-safe result for one live USK catalog publication attempt.
 *
 * <p>The live publication command needs a durable summary that release jobs, operators, and release
 * certification can archive without carrying the secret-bearing request object. This record is that
 * boundary. It keeps the public catalog source, sibling signature source, digests, signing-key id,
 * catalog size, insertion outcomes, and verification outcomes, but it deliberately stores only file
 * names for local artifacts. It does not retain private insert material, form passwords, node
 * request bodies, node response bodies, or staging directories.
 *
 * <p>Instances are immutable snapshots. Optional components must be explicit non-null {@link
 * Optional} instances, and the warning list is copied on construction so later caller mutation
 * cannot change already-rendered release evidence. The values are still assumed to be sanitized
 * before construction; writers should not recover additional data from a {@code
 * LiveUskPublishRequest}.
 *
 * @param catalogId signed catalog id
 * @param catalogFileName local catalog file basename
 * @param catalogSignatureFileName local signature sidecar basename
 * @param publicCatalogSource public {@code crypta:USK@.../cryptad-app-catalog.properties} source
 * @param publicSignatureSource public sibling signature sidecar source
 * @param resolvedCatalogSource resolved public catalog source, when available
 * @param edition numeric USK edition when it can be derived from public or resolved source
 * @param catalogSha256 SHA-256 digest of the catalog sidecar
 * @param signatureSha256 SHA-256 digest of the signature sidecar
 * @param catalogSigningKeyId key id from the catalog signature sidecar
 * @param entryCount number of signed catalog entries
 * @param catalogInsertStatus status for the catalog properties sidecar
 * @param signatureInsertStatus status for the signature sidecar
 * @param postPublishVerificationStatus status of optional live fetch verification
 * @param schedulerRefreshVerificationStatus status of scheduler/catalog-refresh compatibility
 * @param warnings sanitized warnings
 * @param output normalized output path used by the CLI
 */
record LiveUskPublicationResult(
    String catalogId,
    String catalogFileName,
    String catalogSignatureFileName,
    String publicCatalogSource,
    String publicSignatureSource,
    Optional<String> resolvedCatalogSource,
    Optional<String> edition,
    String catalogSha256,
    String signatureSha256,
    String catalogSigningKeyId,
    int entryCount,
    String catalogInsertStatus,
    String signatureInsertStatus,
    String postPublishVerificationStatus,
    String schedulerRefreshVerificationStatus,
    List<String> warnings,
    Path output) {
  /**
   * Normalizes report collections and verifies optional metadata containers.
   *
   * <p>Callers represent absent optional metadata with {@link Optional#empty()}, never with a null
   * {@code Optional}. That keeps the record contract precise while still allowing warning lists to
   * default to an empty immutable list when older test builders omit them.
   */
  LiveUskPublicationResult {
    Objects.requireNonNull(resolvedCatalogSource, "resolvedCatalogSource");
    Objects.requireNonNull(edition, "edition");
    warnings = warnings == null ? List.of() : List.copyOf(warnings);
  }
}
