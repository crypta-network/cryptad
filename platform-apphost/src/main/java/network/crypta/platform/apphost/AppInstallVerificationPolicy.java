package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Selects how {@link network.crypta.platform.apphost.runtime.LocalProcessAppHost} validates copied
 * staged or retained bundles before installation, update, rollback, or launch continues.
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
      allowUnsignedForDevelopmentOnly(
          DEFAULT_DEVELOPMENT_BUNDLE_VERIFIER::verify, DEFAULT_DEVELOPMENT_BUNDLE_VERIFIER::verify);

  private final boolean allowUnsignedForDevelopment;
  private final CopiedBundleIdentityVerifier verifier;
  private final CopiedBundleIdentityVerifier historicalVerifier;

  private AppInstallVerificationPolicy(
      boolean allowUnsignedForDevelopment,
      CopiedBundleIdentityVerifier verifier,
      CopiedBundleIdentityVerifier historicalVerifier) {
    this.allowUnsignedForDevelopment = allowUnsignedForDevelopment;
    this.verifier = Objects.requireNonNull(verifier, "verifier");
    this.historicalVerifier = Objects.requireNonNull(historicalVerifier, "historicalVerifier");
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
    return requireSigned(verifier, verifier);
  }

  /**
   * Creates a policy with distinct new-bundle and retained historical verifiers.
   *
   * <p>Install and update admission use {@code verifier}. AppHost rollback uses {@code
   * historicalVerifier}, allowing a lifecycle-aware runtime to launch or restore bundles signed by
   * supported predecessor keys without permitting them to authorize another install or update.
   *
   * @param verifier verification callback for newly copied install and update bundles
   * @param historicalVerifier verification callback for exact retained installed or rollback
   *     bundles
   * @return policy that requires signed-distribution verification for both purposes
   */
  public static AppInstallVerificationPolicy requireSigned(
      CopiedBundleVerifier verifier, CopiedBundleVerifier historicalVerifier) {
    return new AppInstallVerificationPolicy(
        false, legacyIdentity(verifier), legacyIdentity(historicalVerifier));
  }

  /**
   * Creates a signed policy whose callbacks expose the exact verified copied-bundle identity.
   *
   * <p>Federation-aware AppHost operations use this form so installed provenance can be compared
   * with the actual publisher key and signed content in the AppHost-owned copied tree. The older
   * void callback factories remain source-compatible, but cannot satisfy exact catalog provenance.
   *
   * @param verifier identity-returning verifier for new bundles
   * @param historicalVerifier identity-returning verifier for retained historical bundles
   * @return signed policy with exact identity reporting
   */
  public static AppInstallVerificationPolicy requireSignedWithIdentity(
      CopiedBundleIdentityVerifier verifier, CopiedBundleIdentityVerifier historicalVerifier) {
    return new AppInstallVerificationPolicy(false, verifier, historicalVerifier);
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
   * Creates a development-only policy with distinct new and historical verification callbacks.
   *
   * <p>The callbacks still decide whether a copied bundle is acceptable. Runtime integration uses
   * this overload to preserve an explicit unsigned-development bypass while applying
   * lifecycle-aware verification to every signed install, update, rollback, or launch bundle.
   *
   * @param verifier verification callback for newly copied install and update bundles
   * @param historicalVerifier verification callback for exact retained installed or rollback
   *     bundles
   * @return development-only policy with purpose-separated verification
   */
  public static AppInstallVerificationPolicy allowUnsignedForDevelopmentOnly(
      CopiedBundleVerifier verifier, CopiedBundleVerifier historicalVerifier) {
    return new AppInstallVerificationPolicy(
        true, legacyIdentity(verifier), legacyIdentity(historicalVerifier));
  }

  /** Creates a development policy whose callbacks expose exact signed-bundle identities. */
  public static AppInstallVerificationPolicy allowUnsignedForDevelopmentOnlyWithIdentity(
      CopiedBundleIdentityVerifier verifier, CopiedBundleIdentityVerifier historicalVerifier) {
    return new AppInstallVerificationPolicy(true, verifier, historicalVerifier);
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
   * @return verified signer and signed-content identity for the copied tree
   * @throws IOException if verification fails, configuration is invalid, or the copied tree cannot
   *     be inspected
   */
  public AppBundleVerification verifyCopiedBundle(Path copiedBundleDirectory) throws IOException {
    return verifyCopiedBundle(copiedBundleDirectory, verifier);
  }

  /**
   * Verifies one exact retained bundle before AppHost launches or restores it.
   *
   * <p>This method applies the separately configured historical callback. It preserves the same
   * path normalization and exception classification as new-bundle verification, but it does not
   * permit callers to use historical lifecycle authority for install or update admission.
   *
   * @param copiedBundleDirectory retained managed installed or rollback bundle directory
   * @return verified historical signer and signed-content identity for the retained tree
   * @throws IOException if verification fails, configuration is invalid, or the retained tree
   *     cannot be inspected
   */
  public AppBundleVerification verifyHistoricalCopiedBundle(Path copiedBundleDirectory)
      throws IOException {
    return verifyCopiedBundle(copiedBundleDirectory, historicalVerifier);
  }

  private static AppBundleVerification verifyCopiedBundle(
      Path copiedBundleDirectory, CopiedBundleIdentityVerifier copiedBundleVerifier)
      throws IOException {
    Path normalized =
        Objects.requireNonNull(copiedBundleDirectory, "copiedBundleDirectory")
            .toAbsolutePath()
            .normalize();
    try {
      return Objects.requireNonNull(
          copiedBundleVerifier.verifyCopiedBundle(normalized), "copied bundle verification");
    } catch (AppBundleVerificationException | AppHostConfigurationException e) {
      throw e;
    } catch (AppDistributionException | AppHostException e) {
      throw new AppBundleVerificationException(messageOrDefault(e), e);
    }
  }

  private static CopiedBundleIdentityVerifier legacyIdentity(CopiedBundleVerifier verifier) {
    CopiedBundleVerifier checked = Objects.requireNonNull(verifier, "verifier");
    return copiedBundleDirectory -> {
      checked.verifyCopiedBundle(copiedBundleDirectory);
      if (AppBundleVerifier.isDistributionSidecarFree(copiedBundleDirectory)) {
        return AppBundleVerification.unsigned();
      }
      AppBundleSignature signature =
          AppBundleVerifier.read(
              copiedBundleDirectory.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
      return AppBundleVerification.signed(signature.keyId(), signature.algorithm());
    };
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

  /** Verifies a copied bundle and returns its exact cryptographic identity. */
  @FunctionalInterface
  public interface CopiedBundleIdentityVerifier {
    /**
     * Verifies one copied bundle directory.
     *
     * @param copiedBundleDirectory copied AppHost-owned bundle tree
     * @return exact verified signer and signed-content identity
     * @throws IOException if verification fails
     */
    AppBundleVerification verifyCopiedBundle(Path copiedBundleDirectory) throws IOException;
  }
}
