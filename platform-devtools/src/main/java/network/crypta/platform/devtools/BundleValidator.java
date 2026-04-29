package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.api.PlatformApiCapabilityRegistry;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleDigestVerifier;
import network.crypta.platform.appdist.AppBundleDigestWriter;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleStructureValidator;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Runs production bundle validation plus developer-facing permission linting.
 *
 * <p>The validator deliberately reuses appdist parsing, structure checks, digest generation, and
 * signed-sidecar readers. It does not make trust decisions for signed bundles; cryptographic trust
 * remains the job of the verify command because that command has trusted-key inputs.
 *
 * <p>This class is used by {@code crypta-app validate} and by packaging before ZIP output. Its
 * checks are intentionally close to install-time behavior: catalog sidecars are never valid inside
 * a staged bundle, distribution sidecars must be complete and canonical when present, and
 * permissions are compared with the public Platform API capability registry. Strict mode upgrades
 * unknown permissions from warnings to failures without changing the production manifest parser.
 */
final class BundleValidator {
  /** Reserved root sidecar names that developer tooling must validate before packaging. */
  private static final Set<String> RESERVED_SIDECARS =
      Set.of(
          AppBundleDigest.DIGEST_FILE_NAME,
          AppBundleSignature.SIGNATURE_FILE_NAME,
          "cryptad-app.catalog",
          "cryptad-app.catalog.signature");

  /** Utility class; validation is exposed through {@link #validate(Path, boolean)}. */
  private BundleValidator() {}

  /**
   * Validates one staged bundle directory for developer tooling.
   *
   * <p>The method first delegates to production bundle structure validation, then computes the
   * canonical digest to ensure bundle contents are digestible, validates any existing signed-bundle
   * sidecars, and finally lints manifest permissions. It does not require the bundle to be signed
   * and does not verify signature trust against trusted keys.
   *
   * @param bundleDir staged bundle root directory supplied to the CLI
   * @param strict whether unknown manifest permissions should fail validation
   * @return parsed manifest and permission lint findings for CLI reporting
   * @throws IOException if the bundle cannot be read or digest sidecars cannot be verified
   */
  static BundleValidation validate(Path bundleDir, boolean strict) throws IOException {
    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleDir);
    AppBundleDigestWriter.create(bundleDir);
    validateReservedSidecars(bundleDir);
    AppBundleManifest manifest = validated.manifest();
    PermissionLintResult lint =
        PermissionLintResult.lint(
            manifest.permissions(), PlatformApiCapabilityRegistry.knownCapabilities());
    if (strict && lint.hasUnknownPermissions()) {
      throw new AppDistributionException(
          "unknown app permission(s): " + String.join(", ", lint.unknownPermissions()));
    }
    return new BundleValidation(manifest, lint);
  }

  /**
   * Validates reserved app distribution sidecars in the bundle root.
   *
   * <p>Catalog sidecars belong next to catalog files, not inside bundles. Digest and signature
   * sidecars are allowed only as a complete pair using canonical lowercase names, and an existing
   * pair must parse and match the current bundle contents.
   *
   * @param bundleDir normalized staged bundle root directory
   * @throws IOException if sidecar files cannot be scanned or verified
   */
  private static void validateReservedSidecars(Path bundleDir) throws IOException {
    Path normalizedBundleDir = bundleDir.toAbsolutePath().normalize();
    SidecarState sidecars = scanReservedSidecars(normalizedBundleDir);
    if (!sidecars.present()) {
      return;
    }
    if (sidecars.hasCatalogSidecar()) {
      throw new AppDistributionException("bundle must not contain catalog sidecars");
    }
    if (!sidecars.hasDigest() || !sidecars.hasSignature()) {
      throw new AppDistributionException("bundle has incomplete distribution sidecars");
    }
    AppBundleDigestVerifier.verify(normalizedBundleDir);
    AppBundleVerifier.read(normalizedBundleDir.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
  }

  /**
   * Scans the bundle root for reserved sidecar file names.
   *
   * @param bundleDir normalized staged bundle root directory
   * @return presence flags for known distribution and catalog sidecars
   * @throws IOException if the root directory cannot be scanned
   */
  private static SidecarState scanReservedSidecars(Path bundleDir) throws IOException {
    SidecarPresence sidecars = new SidecarPresence();
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(bundleDir)) {
      for (Path entry : stream) {
        scanReservedSidecar(entry, sidecars);
      }
    }
    return sidecars.toState();
  }

  private static void scanReservedSidecar(Path entry, SidecarPresence sidecars) throws IOException {
    if (!Files.exists(entry, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    Path entryFileName = Objects.requireNonNull(entry.getFileName(), "bundle entry file name");
    String fileName = entryFileName.toString();
    String normalized = fileName.toLowerCase(Locale.ROOT);
    if (!RESERVED_SIDECARS.contains(normalized)) {
      return;
    }
    if (!fileName.equals(normalized)) {
      throw new AppDistributionException(
          "reserved sidecar must use canonical lowercase name: " + fileName);
    }
    sidecars.mark(normalized);
  }

  /**
   * Presence flags for reserved sidecars found in the bundle root.
   *
   * @param hasDigest whether {@code cryptad-app.digest} was present
   * @param hasSignature whether {@code cryptad-app.signature} was present
   * @param hasCatalogSidecar whether any catalog sidecar was present
   */
  private record SidecarState(boolean hasDigest, boolean hasSignature, boolean hasCatalogSidecar) {
    /**
     * Reports whether any reserved sidecar was found.
     *
     * @return {@code true} if at least one reserved sidecar is present
     */
    boolean present() {
      return hasDigest || hasSignature || hasCatalogSidecar;
    }
  }

  private static final class SidecarPresence {
    private boolean digest;
    private boolean signature;
    private boolean catalog;

    private void mark(String sidecarName) {
      switch (sidecarName) {
        case AppBundleDigest.DIGEST_FILE_NAME -> digest = true;
        case AppBundleSignature.SIGNATURE_FILE_NAME -> signature = true;
        default -> catalog = true;
      }
    }

    private SidecarState toState() {
      return new SidecarState(digest, signature, catalog);
    }
  }
}
