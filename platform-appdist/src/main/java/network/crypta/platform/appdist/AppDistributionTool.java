package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.List;

/**
 * Small JDK-only CLI for signing, verifying, and packaging local staged app bundles.
 *
 * <p>This keeps first-party Gradle tasks and ad-hoc local workflows wired to the same
 * implementation used by the runtime verifier, without duplicating digest or crypto logic in the
 * build scripts. The tool is intentionally limited to local directories. It does not fetch
 * catalogs, download bundles, or manage a remote app store.
 *
 * <p>The {@code sign} command regenerates {@code cryptad-app.digests} and writes {@code
 * cryptad-app.signature}. The {@code verify} command checks signed bundles against trusted public
 * keys and, when {@code --allow-unsigned} is present, accepts only completely unsigned development
 * bundles after validating their structure. Private signing material can be supplied through a file
 * or environment variable so Gradle tasks do not need to place secrets in child-process arguments.
 * The {@code package} command emits the canonical deterministic ZIP implemented by {@link
 * AppBundlePackager} and does not alter the staged bundle.
 */
public final class AppDistributionTool {
  private static final String COMMAND_PACKAGE = "package";
  private static final String COMMAND_SIGN = "sign";
  private static final String COMMAND_VERIFY = "verify";
  private static final String OPTION_ALLOW_UNSIGNED = "--allow-unsigned";
  private static final String OPTION_BUNDLE_DIR = "--bundle-dir";
  private static final String OPTION_KEY_ID = "--key-id";
  private static final String OPTION_OUTPUT_ZIP = "--output-zip";
  private static final String OPTION_PRIVATE_KEY_BASE64 = "--private-key-base64";
  private static final String OPTION_PRIVATE_KEY_ENV = "--private-key-env";
  private static final String OPTION_PRIVATE_KEY_FILE = "--private-key-file";
  private static final String OPTION_TRUSTED_KEY_ID = "--trusted-key-id";
  private static final String OPTION_TRUSTED_KEYS_FILE = "--trusted-keys-file";
  private static final String OPTION_TRUSTED_PUBLIC_KEY_BASE64 = "--trusted-public-key-base64";
  private static final String OPTION_TRUSTED_PUBLIC_KEY_FILE = "--trusted-public-key-file";
  private static final String USAGE =
      """
      Usage:
        package --bundle-dir <dir> --output-zip <path>
        sign --bundle-dir <dir> --key-id <id> (--private-key-base64 <base64> | --private-key-file <path> | --private-key-env <name>)
        verify --bundle-dir <dir> [--allow-unsigned] [--trusted-keys-file <path>]
        verify --bundle-dir <dir> [--allow-unsigned] --trusted-key-id <id> (--trusted-public-key-base64 <base64> | --trusted-public-key-file <path>)
      """;

  private AppDistributionTool() {}

  /**
   * Runs one of the supported signing or verification commands.
   *
   * <p>The method throws checked exceptions directly so Gradle {@code JavaExec} tasks and shell
   * callers receive a non-zero process exit with the underlying validation message. Unsupported
   * invocations receive the usage text emitted by this tool.
   *
   * @param arguments command-line arguments starting with {@code package}, {@code sign}, or {@code
   *     verify}
   * @throws IOException when command parsing, key loading, signing, or verification fails
   */
  public static void main(String[] arguments) throws IOException {
    if (arguments.length == 0) {
      throw new AppDistributionException(USAGE);
    }
    String command = arguments[0];
    List<String> args = List.of(arguments).subList(1, arguments.length);
    switch (command) {
      case COMMAND_PACKAGE -> packageBundle(args);
      case COMMAND_SIGN -> sign(args);
      case COMMAND_VERIFY -> verify(args);
      default -> throw new AppDistributionException(USAGE);
    }
  }

  private static void packageBundle(List<String> arguments) throws IOException {
    Arguments args = Arguments.parse(arguments);
    AppBundlePackager.packageBundle(
        args.requirePath(OPTION_BUNDLE_DIR), args.requirePath(OPTION_OUTPUT_ZIP));
  }

  private static void sign(List<String> arguments) throws IOException {
    Arguments args = Arguments.parse(arguments);
    Path bundleDir = args.requirePath(OPTION_BUNDLE_DIR);
    String keyId = args.require(OPTION_KEY_ID);
    PrivateKey privateKey = loadPrivateKey(args);
    AppBundleSigner.sign(bundleDir, keyId, privateKey);
  }

  private static void verify(List<String> arguments) throws IOException {
    Arguments args = Arguments.parse(arguments);
    Path bundleDir = AppDistributionSidecars.requireBundleRoot(args.requirePath(OPTION_BUNDLE_DIR));
    boolean allowUnsigned = args.has(OPTION_ALLOW_UNSIGNED);
    if (allowUnsigned && AppBundleVerifier.isDistributionSidecarFree(bundleDir)) {
      validateBundleStructure(bundleDir);
      return;
    }
    TrustedAppKeys trustedKeys = trustedKeys(args);
    AppBundleVerifier verifier =
        allowUnsigned
            ? AppBundleVerifier.allowUnsignedForDevelopmentOnly(trustedKeys)
            : AppBundleVerifier.requireSigned(trustedKeys);
    verifier.verify(bundleDir);
    validateBundleStructure(bundleDir);
  }

  private static TrustedAppKeys trustedKeys(Arguments arguments) throws IOException {
    if (arguments.has(OPTION_TRUSTED_KEYS_FILE)) {
      return TrustedAppKeys.load(arguments.requirePath(OPTION_TRUSTED_KEYS_FILE));
    }
    if (arguments.has(OPTION_TRUSTED_PUBLIC_KEY_BASE64)
        && arguments.has(OPTION_TRUSTED_PUBLIC_KEY_FILE)) {
      throw new AppDistributionException(
          "Trusted app public key material must be configured by base64 or file, not both.");
    }
    if (arguments.has(OPTION_TRUSTED_KEY_ID)
        && (arguments.has(OPTION_TRUSTED_PUBLIC_KEY_BASE64)
            || arguments.has(OPTION_TRUSTED_PUBLIC_KEY_FILE))) {
      return TrustedAppKeys.of(
          arguments.has(OPTION_TRUSTED_PUBLIC_KEY_FILE)
              ? TrustedAppKey.ed25519(
                  arguments.require(OPTION_TRUSTED_KEY_ID),
                  AppDistributionSidecars.readKeyMaterial(
                      arguments.requirePath(OPTION_TRUSTED_PUBLIC_KEY_FILE)))
              : TrustedAppKey.ed25519(
                  arguments.require(OPTION_TRUSTED_KEY_ID),
                  arguments.require(OPTION_TRUSTED_PUBLIC_KEY_BASE64)));
    }
    return TrustedAppKeys.empty();
  }

  private static PrivateKey loadPrivateKey(Arguments arguments) throws IOException {
    int configuredPrivateKeySources =
        (arguments.has(OPTION_PRIVATE_KEY_FILE) ? 1 : 0)
            + (arguments.has(OPTION_PRIVATE_KEY_ENV) ? 1 : 0)
            + (arguments.has(OPTION_PRIVATE_KEY_BASE64) ? 1 : 0);
    if (configuredPrivateKeySources > 1) {
      throw new AppDistributionException(
          "Trusted app private key material must be configured by base64, file, or env, not"
              + " multiple sources.");
    }
    if (arguments.has(OPTION_PRIVATE_KEY_FILE)) {
      return AppBundleSigner.loadPrivateKey(
          AppDistributionSidecars.readKeyMaterial(arguments.requirePath(OPTION_PRIVATE_KEY_FILE)));
    }
    if (arguments.has(OPTION_PRIVATE_KEY_ENV)) {
      return AppBundleSigner.loadPrivateKey(
          arguments.requireEnvironmentValue(arguments.require(OPTION_PRIVATE_KEY_ENV)));
    }
    return AppBundleSigner.loadPrivateKey(arguments.require(OPTION_PRIVATE_KEY_BASE64));
  }

  private static void validateBundleStructure(Path bundleDir) throws IOException {
    AppBundleDigestWriter.create(bundleDir);
  }

  private record Arguments(List<String> tokens) {
    private Arguments {
      tokens = List.copyOf(tokens);
    }

    static Arguments parse(List<String> tokens) {
      return new Arguments(tokens);
    }

    boolean has(String name) {
      return tokens.contains(name);
    }

    String require(String name) throws AppDistributionException {
      int index = tokens.indexOf(name);
      if (index < 0 || index + 1 >= tokens.size()) {
        throw new AppDistributionException("missing required argument: " + name);
      }
      return tokens.get(index + 1);
    }

    String requireEnvironmentValue(String environmentName) throws AppDistributionException {
      String value = System.getenv(environmentName);
      if (value == null || value.isBlank()) {
        throw new AppDistributionException(
            "missing required environment variable: " + environmentName);
      }
      return value.trim();
    }

    Path requirePath(String name) throws AppDistributionException {
      return Path.of(require(name)).toAbsolutePath().normalize();
    }
  }
}
