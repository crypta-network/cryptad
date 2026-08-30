package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerifier;

/**
 * Defines the app-publisher authorization boundary for bundles obtained from an app catalog.
 *
 * <p>A valid catalog signature authenticates the catalog authority, but it does not establish that
 * the publisher may sign the referenced app. Catalog orchestration therefore invokes this policy
 * immediately after safe extraction and again before applying a retained installation plan. The
 * second check covers key rotation, revocation, and time-bounded approvals before installation or a
 * staged migration command can execute.
 *
 * <p>Ordinary nodes normally use {@link #fromTrustedKeys(AppCatalogManager.TrustedKeyProvider)}.
 * Isolated pilot nodes can supply a stricter implementation that also binds the app ID, version,
 * and signature sidecar. Implementations inspect the supplied private staging directory but do not
 * own its lifecycle. This functional interface can be composed without changing catalog signature
 * verification or catalog-source trust.
 */
@FunctionalInterface
public interface AppCatalogBundleVerificationPolicy {
  /**
   * Creates the ordinary trusted-app-key verification policy.
   *
   * <p>The returned policy reloads the provider for every verification so key lifecycle changes do
   * not require reconstructing the catalog manager. Each verification uses one current provider
   * result and delegates the bundle checks to the standard app-bundle verifier. Callers should use
   * a separate policy when authorization depends on an app-specific or time-bounded approval.
   *
   * @param trustedKeyProvider provider that supplies the current app-publisher trust registry
   * @return verification policy backed by the provider's current trusted app keys
   * @throws NullPointerException if {@code trustedKeyProvider} is {@code null}
   */
  static AppCatalogBundleVerificationPolicy fromTrustedKeys(
      AppCatalogManager.TrustedKeyProvider trustedKeyProvider) {
    return new TrustedAppKeysBundleVerificationPolicy(trustedKeyProvider);
  }

  /**
   * Verifies one safely extracted staged bundle root.
   *
   * <p>The method must reject a bundle unless its publisher and complete signed subject satisfy the
   * active policy. Catalog orchestration may call it more than once for the same staged bytes, so
   * implementations should not consume, move, or mutate the directory. Successful return only
   * authorizes this verification step; ownership and cleanup remain with the catalog pipeline.
   *
   * @param stagedBundleDirectory private catalog staging directory containing the extracted bundle
   * @throws IOException if the bundle is unauthorized, malformed, or cannot be inspected safely
   */
  void verify(Path stagedBundleDirectory) throws IOException;

  /**
   * Verifies one staged bundle in its authenticated catalog/app context.
   *
   * <p>The default preserves source compatibility for existing lambdas and bounded pilot policies:
   * it invokes {@link #verify(Path)} and records the verified signature key id as an explicitly
   * unscoped compatibility result. A development policy that explicitly accepts a completely
   * sidecar-free bundle receives an unsigned, unscoped compatibility result; partial or malformed
   * sidecars still fail closed. Federation-aware policies override this method to authorize the
   * exact catalog/app pair and return their canonical key fingerprint and local policy digest.
   *
   * @param context authenticated catalog and entry identity
   * @param stagedBundleDirectory private catalog staging directory
   * @return exact authorization identity for retained-plan comparison
   * @throws IOException if the bundle is unauthorized, malformed, or cannot be inspected safely
   */
  default AppCatalogBundleVerificationResult verify(
      AppCatalogBundleVerificationContext context, Path stagedBundleDirectory) throws IOException {
    Objects.requireNonNull(context, "context");
    Path stagedRoot = Objects.requireNonNull(stagedBundleDirectory, "stagedBundleDirectory");
    verify(stagedRoot);
    if (AppBundleVerifier.isDistributionSidecarFree(stagedRoot)) {
      return AppCatalogBundleVerificationResult.unsignedDevelopmentCompatibility();
    }
    AppBundleSignature signature =
        AppBundleVerifier.read(stagedRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
    return AppCatalogBundleVerificationResult.legacyCompatibility(signature);
  }
}
