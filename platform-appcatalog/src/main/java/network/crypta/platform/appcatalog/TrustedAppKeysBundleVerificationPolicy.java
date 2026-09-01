package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies catalog bundles against the current ordinary app-publisher trust registry.
 *
 * <p>This adapter keeps generic trusted-key verification separate from catalog-manager
 * orchestration. It reloads the provider on every invocation so rotations and revocations take
 * effect at both initial extraction and retained-plan re-verification. Verification delegates to
 * {@link AppBundleVerifier}, which authenticates the bundle's signed digest sidecar and publisher
 * key rather than relying on catalog metadata alone.
 *
 * <p>The adapter is immutable and does not cache a trust snapshot. Its effective concurrency and
 * key-lifecycle behavior therefore follow the supplied {@link
 * AppCatalogManager.TrustedKeyProvider}. A successful check authorizes only the staged bundle bytes
 * presented for that invocation; catalog orchestration remains responsible for staging,
 * installation, and cleanup.
 */
final class TrustedAppKeysBundleVerificationPolicy implements AppCatalogBundleVerificationPolicy {
  /** Supplies the app-publisher registry used for each independent bundle verification. */
  private final AppCatalogManager.TrustedKeyProvider trustedKeyProvider;

  /**
   * Creates an adapter backed by a dynamically loaded trusted-key provider.
   *
   * <p>Construction stores the provider reference without loading keys or performing I/O. This
   * preserves the catalog manager's ability to observe key rotation and revocation when it later
   * verifies extracted or retained bundles.
   *
   * @param trustedKeyProvider non-null provider for the ordinary app-publisher trust registry
   * @throws NullPointerException if {@code trustedKeyProvider} is {@code null}
   */
  TrustedAppKeysBundleVerificationPolicy(AppCatalogManager.TrustedKeyProvider trustedKeyProvider) {
    this.trustedKeyProvider = Objects.requireNonNull(trustedKeyProvider, "trustedKeyProvider");
  }

  @Override
  public void verify(Path stagedBundleDirectory) throws IOException {
    AppBundleVerifier.verify(stagedBundleDirectory, trustedKeyProvider.trustedKeys());
  }

  @Override
  public AppCatalogBundleVerificationResult verify(
      AppCatalogBundleVerificationContext context, Path stagedBundleDirectory) throws IOException {
    Objects.requireNonNull(context, "context");
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    AppBundleVerification verification =
        AppBundleVerifier.requireSigned(trustedKeys).verify(stagedBundleDirectory);
    return AppCatalogBundleVerificationResult.trustedAppKeys(verification);
  }
}
