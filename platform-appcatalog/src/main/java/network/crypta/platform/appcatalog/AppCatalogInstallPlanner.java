package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Prepares and re-verifies staged app bundles selected from a verified catalog.
 *
 * <p>The public catalog manager selects the signed catalog entry and owns synchronization. This
 * collaborator owns the filesystem-heavy part of the installation/update preparation path: creating
 * a scratch directory, downloading the declared artifact, extracting the signed bundle, cleaning up
 * on failure, and re-verifying retained installation plans before callers hand them to AppHost.
 */
final class AppCatalogInstallPlanner {
  private final AppCatalogSourceStore sourceStore;
  private final AppCatalogBundleVerificationPolicy bundleVerificationPolicy;
  private final AppCatalogArtifactDownloader artifactDownloader;
  private final AppCatalogBundleExtractor bundleExtractor;

  AppCatalogInstallPlanner(
      AppCatalogSourceStore sourceStore,
      AppCatalogBundleVerificationPolicy bundleVerificationPolicy,
      AppCatalogArtifactDownloader artifactDownloader,
      AppCatalogBundleExtractor bundleExtractor) {
    this.sourceStore = Objects.requireNonNull(sourceStore, "sourceStore");
    this.bundleVerificationPolicy =
        Objects.requireNonNull(bundleVerificationPolicy, "bundleVerificationPolicy");
    this.artifactDownloader = Objects.requireNonNull(artifactDownloader, "artifactDownloader");
    this.bundleExtractor = Objects.requireNonNull(bundleExtractor, "bundleExtractor");
  }

  AppCatalogInstallPlan prepareInstallPlan(
      String normalizedCatalogId, AppCatalogEntry entry, AppCatalogOriginContext originContext)
      throws IOException {
    Path stagingDirectory = sourceStore.stagingDirectory();
    Files.createDirectories(stagingDirectory);
    Path scratchRoot = Files.createTempDirectory(stagingDirectory, normalizedCatalogId + "-");
    try {
      Path artifactZip = artifactDownloader.download(entry, scratchRoot);
      AppCatalogBundleVerificationContext context =
          new AppCatalogBundleVerificationContext(normalizedCatalogId, entry);
      AppCatalogBundleExtractor.VerifiedBundle verifiedBundle =
          extractBundle(context, artifactZip, scratchRoot);
      return new AppCatalogInstallPlan(
          normalizedCatalogId,
          entry,
          verifiedBundle.stagedBundleDirectory(),
          scratchRoot,
          verifiedBundle.verificationResult(),
          java.util.Optional.of(Objects.requireNonNull(originContext, "originContext")));
    } catch (IOException | RuntimeException exception) {
      AppCatalogBundleExtractor.deleteRecursively(scratchRoot);
      throw exception;
    }
  }

  void verifyInstallPlan(AppCatalogInstallPlan plan) throws IOException {
    AppCatalogInstallPlan checkedPlan = Objects.requireNonNull(plan, "plan");
    AppCatalogBundleVerificationContext context =
        new AppCatalogBundleVerificationContext(checkedPlan.catalogId(), checkedPlan.entry());
    AppCatalogBundleVerificationResult currentResult =
        bundleExtractor.verifyStagedBundle(
            context, checkedPlan.stagedBundleDirectory(), bundleVerificationPolicy);
    if (!checkedPlan.bundleVerification().equals(currentResult)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_APP_BUNDLE,
          "catalog bundle publisher authorization changed after plan creation");
    }
  }

  private AppCatalogBundleExtractor.VerifiedBundle extractBundle(
      AppCatalogBundleVerificationContext context, Path artifactZip, Path scratchRoot)
      throws IOException {
    return bundleExtractor.extract(context, artifactZip, scratchRoot, bundleVerificationPolicy);
  }
}
