package network.crypta.platform.appvault;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;

/**
 * Path-safe naming rules and derived storage paths for the local app vault.
 *
 * <p>The vault stores app-owned secrets, identity metadata, private-material envelopes, grants, and
 * uninstall access blocks under one host-owned root. This helper centralizes every path derivation
 * so callers do not concatenate request strings into filesystem paths directly.
 *
 * <p>Names are intentionally conservative. They are lower-cased, trimmed, constrained to a small
 * local-segment character set, and checked for traversal and Windows aliasing hazards. Rejected
 * names fail with a stable vault error before any path is resolved.
 *
 * @param root absolute normalized vault root path
 */
public record AppVaultPaths(Path root) {
  private static final String LOCAL_SEGMENT_PATTERN = "[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?";
  private static final String SECRET_NAME_PATTERN = "[a-z0-9][a-z0-9._-]{0,127}";
  private static final String ID_PATTERN = "[a-z0-9][a-z0-9._-]{0,191}";

  /**
   * Creates a vault path helper rooted in one host-owned directory.
   *
   * <p>The root is made absolute and normalized once. Child path methods still normalize ids and
   * names before resolving beneath that root.
   *
   * @param root vault storage root owned by the local node
   */
  public AppVaultPaths {
    root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
  }

  /**
   * Returns the local wrapping-key file path.
   *
   * @return path of the v1 local vault wrapping-key file
   */
  public Path keyFile() {
    return root.resolve("keys").resolve("local-vault-key-v1.key");
  }

  /**
   * Returns the app secret metadata file path.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @return path of the redacted secret metadata properties file
   */
  public Path secretMetadataPath(String appId, String secretName) {
    return secretRoot(appId, secretName).resolve("metadata.properties");
  }

  /**
   * Returns the app secret envelope file path.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @return path of the encrypted secret value envelope
   */
  public Path secretEnvelopePath(String appId, String secretName) {
    return secretRoot(appId, secretName).resolve("value.envelope.json");
  }

  /**
   * Returns the identity metadata file path.
   *
   * @param identityId identity id stored by the vault
   * @return path of the public identity metadata properties file
   */
  public Path identityMetadataPath(String identityId) {
    return identityRoot(identityId).resolve("metadata.properties");
  }

  /**
   * Returns the identity private-material envelope file path.
   *
   * @param identityId identity id stored by the vault
   * @return path of the encrypted private-material envelope
   */
  public Path identityPrivateEnvelopePath(String identityId) {
    return identityRoot(identityId).resolve("private.envelope.json");
  }

  /**
   * Returns the grant metadata file path.
   *
   * @param grantId durable grant id assigned by the vault
   * @return path of the grant metadata properties file
   */
  public Path grantPath(String grantId) {
    return root.resolve("grants").resolve(normalizeGrantId(grantId) + ".properties");
  }

  Path secretsRoot() {
    return root.resolve("secrets");
  }

  Path identitiesRoot() {
    return root.resolve("identities");
  }

  Path grantsRoot() {
    return root.resolve("grants");
  }

  Path appAccessBlocksRoot() {
    return root.resolve("app-access-blocks");
  }

  Path appAccessBlockPath(String appId) {
    return appAccessBlocksRoot().resolve(normalizeAppId(appId) + ".properties");
  }

  Path secretRoot(String appId, String secretName) {
    return secretsRoot().resolve(normalizeAppId(appId)).resolve(normalizeSecretName(secretName));
  }

  Path identityRoot(String identityId) {
    return identitiesRoot().resolve(normalizeIdentityId(identityId));
  }

  /**
   * Normalizes and validates one app id as a local path segment.
   *
   * <p>App ids use the strict local segment pattern because they are used as directory names for
   * app-owned secrets and app access blocks.
   *
   * @param appId supplied app id from a manifest or principal
   * @return normalized lower-case app id safe for local paths
   */
  public static String normalizeAppId(String appId) {
    return normalizeLocalSegment(appId, "app id", LOCAL_SEGMENT_PATTERN);
  }

  /**
   * Normalizes and validates one app-owned secret name.
   *
   * <p>Secret names allow short dotted or dashed labels such as {@code api-token} but reject
   * traversal fragments, trailing dots, and Windows reserved device names. Those restrictions avoid
   * aliases where two logical secrets could target the same directory on a supported platform.
   *
   * @param secretName supplied app-local secret name
   * @return normalized lower-case secret name safe for local paths
   */
  public static String normalizeSecretName(String secretName) {
    String normalized = normalizeLocalSegment(secretName, "secret name", SECRET_NAME_PATTERN);
    if (normalized.contains("..")
        || normalized.endsWith(".")
        || isReservedWindowsName(normalized)) {
      throw invalidName("secret name");
    }
    return normalized;
  }

  /**
   * Normalizes and validates one identity id.
   *
   * <p>Identity ids are generated by the vault in normal operation, but validation also protects
   * operator routes and restored metadata files from unsafe path segments.
   *
   * @param identityId supplied identity id
   * @return normalized lower-case identity id safe for local paths
   */
  public static String normalizeIdentityId(String identityId) {
    return normalizeLocalSegment(identityId, "identity id", ID_PATTERN);
  }

  /**
   * Normalizes and validates one grant id.
   *
   * <p>Grant ids are generated by the vault and used as properties filenames. Validation prevents a
   * copied or request-supplied id from escaping the grants' directory.
   *
   * @param grantId supplied grant id
   * @return normalized lower-case grant id safe for local paths
   */
  public static String normalizeGrantId(String grantId) {
    return normalizeLocalSegment(grantId, "grant id", ID_PATTERN);
  }

  private static String normalizeLocalSegment(String value, String label, String pattern) {
    String normalized = Objects.requireNonNull(value, label).trim().toLowerCase(Locale.ROOT);
    if (!normalized.matches(pattern)
        || normalized.contains("/")
        || normalized.contains("\\")
        || normalized.contains("%")) {
      throw invalidName(label);
    }
    return normalized;
  }

  private static AppVaultException invalidName(String label) {
    return new AppVaultException(400, "invalid_vault_name", "Invalid vault " + label + ".");
  }

  private static boolean isReservedWindowsName(String name) {
    String baseName = name.contains(".") ? name.substring(0, name.indexOf('.')) : name;
    return switch (baseName) {
      case "con",
          "prn",
          "aux",
          "nul",
          "com1",
          "com2",
          "com3",
          "com4",
          "com5",
          "com6",
          "com7",
          "com8",
          "com9",
          "lpt1",
          "lpt2",
          "lpt3",
          "lpt4",
          "lpt5",
          "lpt6",
          "lpt7",
          "lpt8",
          "lpt9" ->
          true;
      default -> false;
    };
  }
}
