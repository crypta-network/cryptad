package network.crypta.platform.appcatalog;

import java.util.List;
import network.crypta.platform.appdist.AppBundleManifest;

/**
 * Verified view of a third-party app submission ZIP.
 *
 * <p>This record is returned after structural inspection has parsed the top-level metadata, the
 * embedded staged-bundle manifest, and the canonical packaged bundle artifact. It intentionally
 * stores only bounded metadata, digests, sizes, and entry names. Raw package bytes, rationale
 * bodies, signatures, and bundle contents stay out of this model so CLI JSON output and
 * release-certification evidence remain redacted.
 *
 * <p>The snapshot is immutable and represents the exact submission bytes that were inspected. A
 * caller that needs to extract the staged bundle should use {@link AppSubmissionPackageVerifier}
 * instead of trusting entry names or reopening an unverified path.
 *
 * @param metadata parsed and validated top-level submission metadata
 * @param manifest parsed staged bundle manifest from {@code bundle/cryptad-app.properties}
 * @param submissionDigest lowercase SHA-256 digest of the entire submission ZIP
 * @param manifestDigest lowercase SHA-256 digest of {@code bundle/cryptad-app.properties}
 * @param bundleArtifactSizeBytes byte size of {@code artifacts/app-bundle.zip}
 * @param entryNames normalized ZIP entry names observed during package inspection
 */
public record AppSubmissionPackage(
    AppSubmissionMetadata metadata,
    AppBundleManifest manifest,
    String submissionDigest,
    String manifestDigest,
    long bundleArtifactSizeBytes,
    List<String> entryNames) {
  /**
   * Creates a verified package snapshot.
   *
   * <p>The constructor validates immutable value boundaries but assumes the caller already
   * performed package inspection. It checks digest syntax, non-negative artifact size, and
   * defensive copies of entry names so downstream report generation cannot mutate the snapshot.
   */
  public AppSubmissionPackage {
    java.util.Objects.requireNonNull(metadata, "metadata");
    java.util.Objects.requireNonNull(manifest, "manifest");
    submissionDigest =
        AppCatalogSidecars.requireLowercaseSha256(submissionDigest, "submissionDigest");
    manifestDigest = AppCatalogSidecars.requireLowercaseSha256(manifestDigest, "manifestDigest");
    if (bundleArtifactSizeBytes < 0L) {
      throw AppCatalogSidecars.invalidEntry("bundle artifact size must be non-negative");
    }
    entryNames = List.copyOf(java.util.Objects.requireNonNull(entryNames, "entryNames"));
  }
}
