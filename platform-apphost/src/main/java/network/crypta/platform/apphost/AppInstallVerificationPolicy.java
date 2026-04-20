package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Selects how {@link network.crypta.platform.apphost.runtime.LocalProcessAppHost} validates copied
 * staged bundles before installation or update continues.
 *
 * <p>AppHost copies caller-owned staged directories into a managed temporary tree before it trusts
 * their contents. This policy runs against that copied tree and therefore decides whether a bundle
 * must pass signed-distribution verification or whether unsigned bundles are temporarily allowed
 * for development and tests.
 *
 * <p>The production-facing default is fail-closed: unsigned bundles are rejected unless the runtime
 * wires a verifier backed by trusted public keys. Tests and local development can opt into
 * unsigned-bundle support explicitly, but that mode still verifies any sidecars that are present so
 * stale or partially signed bundles do not pass in development while failing in production.
 */
public final class AppInstallVerificationPolicy {
  private static final String DEFAULT_SIGNED_BUNDLE_REQUIRED_MESSAGE =
      "signed app bundle verification is required";
  private static final AppBundleVerifier DEFAULT_DEVELOPMENT_BUNDLE_VERIFIER =
      AppBundleVerifier.allowUnsignedForDevelopmentOnly(TrustedAppKeys.empty());

  private static final AppInstallVerificationPolicy ALLOW_UNSIGNED_FOR_DEVELOPMENT =
      allowUnsignedForDevelopmentOnly(DEFAULT_DEVELOPMENT_BUNDLE_VERIFIER::verify);

  private final boolean allowUnsignedForDevelopment;
  private final CopiedBundleVerifier verifier;

  private AppInstallVerificationPolicy(
      boolean allowUnsignedForDevelopment, CopiedBundleVerifier verifier) {
    this.allowUnsignedForDevelopment = allowUnsignedForDevelopment;
    this.verifier = Objects.requireNonNull(verifier, "verifier");
  }

  /**
   * Creates a policy that requires a caller-supplied verifier to accept the copied bundle.
   *
   * <p>The callback receives the AppHost-owned temporary bundle tree, not the original staging path
   * supplied by the API caller. Implementations should therefore verify only the copied tree that
   * will be moved into managed storage.
   *
   * @param verifier verification callback that runs against the copied managed bundle tree
   * @return policy that requires signed-distribution verification
   */
  public static AppInstallVerificationPolicy requireSigned(CopiedBundleVerifier verifier) {
    return new AppInstallVerificationPolicy(false, verifier);
  }

  /**
   * Creates a policy that rejects installs and updates until a signed-bundle verifier is supplied.
   *
   * <p>This is the safe production-facing default while the host has no trusted key material or
   * concrete bundle verifier configured. It prevents constructors from silently accepting unsigned
   * bundles just because the caller forgot to supply a distribution policy.
   *
   * @return policy that rejects copied bundles with a clear signed-verification error
   */
  public static AppInstallVerificationPolicy rejectUnsignedByDefault() {
    return requireSigned(
        _ -> {
          throw new AppBundleVerificationException(DEFAULT_SIGNED_BUNDLE_REQUIRED_MESSAGE);
        });
  }

  /**
   * Creates a policy that allows completely unsigned staged bundles for tests and development only.
   *
   * <p>If digest or signature sidecars are present, this default development policy still verifies
   * them against an empty trusted-key set instead of silently bypassing signed-bundle checks. That
   * means fully unsigned fixtures can install, but a bundle that looks signed must still be
   * internally consistent and trusted by the configured verifier.
   *
   * @return permissive development-only policy
   */
  public static AppInstallVerificationPolicy allowUnsignedForDevelopmentOnly() {
    return ALLOW_UNSIGNED_FOR_DEVELOPMENT;
  }

  /**
   * Creates a development-only policy that still runs a caller-supplied verifier.
   *
   * <p>Use this when local or test flows may accept fully unsigned bundles but any present sidecars
   * must still pass a concrete signed-distribution verifier. Runtime integration uses this shape so
   * optional unsigned development mode can share the same trusted-key loading path as production
   * signed installations.
   *
   * @param verifier verification callback that runs against the copied managed bundle tree
   * @return development-only policy that may allow fully unsigned bundles
   */
  public static AppInstallVerificationPolicy allowUnsignedForDevelopmentOnly(
      CopiedBundleVerifier verifier) {
    return new AppInstallVerificationPolicy(true, verifier);
  }

  /**
   * Returns whether this policy explicitly allows unsigned bundles for development.
   *
   * <p>This flag is informational for host/test code. The actual verification decision is still
   * made by {@link #verifyCopiedBundle(Path)}.
   *
   * @return {@code true} when copied bundles may remain fully unsigned for development use
   */
  @SuppressWarnings("unused")
  public boolean allowsUnsignedForDevelopmentOnly() {
    return allowUnsignedForDevelopment;
  }

  /**
   * Verifies one copied staged bundle.
   *
   * <p>{@link AppDistributionException} and other AppHost verification rejections are converted to
   * {@link AppBundleVerificationException} so API layers can classify them as invalid app bundles.
   * {@link AppHostConfigurationException} and raw {@link IOException} failures are preserved so
   * node-configuration and managed-filesystem problems are not misreported as bad client input.
   *
   * @param copiedBundleDirectory copied managed bundle directory that is about to be installed
   * @throws IOException if verification fails, configuration is invalid, or the copied tree cannot
   *     be inspected
   */
  public void verifyCopiedBundle(Path copiedBundleDirectory) throws IOException {
    Path normalized =
        Objects.requireNonNull(copiedBundleDirectory, "copiedBundleDirectory")
            .toAbsolutePath()
            .normalize();
    try {
      verifier.verifyCopiedBundle(normalized);
    } catch (AppBundleVerificationException | AppHostConfigurationException e) {
      throw e;
    } catch (AppDistributionException | AppHostException e) {
      throw new AppBundleVerificationException(messageOrDefault(e), e);
    }
  }

  private static String messageOrDefault(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? "signed app bundle verification failed" : message;
  }

  /**
   * Verifies a copied managed bundle directory.
   *
   * <p>Implementations are expected to read only the copied tree that AppHost controls rather than
   * the original caller-owned staging directory. This avoids time-of-check/time-of-use races where
   * a caller could mutate the staging tree between verification and installation.
   */
  @FunctionalInterface
  public interface CopiedBundleVerifier {
    /**
     * Verifies one copied bundle directory.
     *
     * @param copiedBundleDirectory copied managed bundle directory that AppHost is about to trust
     * @throws IOException if verification fails or the copied bundle cannot be inspected
     */
    void verifyCopiedBundle(Path copiedBundleDirectory) throws IOException;
  }
}
