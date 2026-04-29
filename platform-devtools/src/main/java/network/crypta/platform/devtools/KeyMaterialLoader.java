package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Loads Ed25519 signing and trusted-key material for developer CLI commands.
 *
 * <p>The low-level bundle and catalog signers require decoded JDK key instances. This utility keeps
 * the CLI's accepted input forms aligned with {@code AppDistributionTool}: base64 or PEM text, raw
 * DER files, and private-key environment variables. It also centralizes the "exactly one source"
 * checks so bundle signing, catalog signing, and verification commands fail with consistent
 * messages before any cryptographic operation starts.
 *
 * <p>Private keys may be supplied as direct text, a file, or the name of an environment variable
 * that contains the text. Trusted public keys may come from a trusted-keys properties file or from
 * a direct key id plus one public key source. This loader does not cache key material and does not
 * log or echo secrets.
 */
final class KeyMaterialLoader {
  /** Utility class; all key-loading operations are static. */
  private KeyMaterialLoader() {}

  /**
   * Loads one Ed25519 private key from the configured CLI source.
   *
   * @param base64 direct base64 or PEM private-key text, when provided
   * @param file private-key file containing text or raw DER bytes, when provided
   * @param environmentName environment variable name containing private-key text, when provided
   * @return decoded private key ready for bundle or catalog signing
   * @throws IOException if a configured key file cannot be read
   */
  static PrivateKey loadPrivateKey(String base64, Path file, String environmentName)
      throws IOException {
    int sourceCount = countConfigured(base64, file, environmentName);
    if (sourceCount != 1) {
      throw new AppDistributionException(
          "private key material must be configured by exactly one of base64, file, or env");
    }
    if (base64 != null) {
      return AppBundleSigner.loadPrivateKey(base64);
    }
    if (environmentName != null) {
      String value = System.getenv(environmentName);
      if (value == null || value.isBlank()) {
        throw new AppDistributionException(
            "missing required environment variable: " + environmentName);
      }
      return AppBundleSigner.loadPrivateKey(value.trim());
    }
    return loadPrivateKeyFile(file);
  }

  /**
   * Loads trusted public keys from a properties file or direct key material.
   *
   * <p>A trusted-keys file wins over direct inputs because it may contain multiple keys and already
   * carries key identifiers. Without a file, direct public key material requires a non-blank key
   * id. When no trust source is configured, an empty key set is returned so callers can decide
   * whether unsigned or untrusted input is allowed for their command.
   *
   * @param trustedKeysFile optional properties file containing trusted app signing keys
   * @param keyId key id used for direct public key input
   * @param publicKeyBase64 direct base64 or PEM public-key text, when provided
   * @param publicKeyFile public-key file containing text or raw DER bytes, when provided
   * @return trusted key collection assembled from the requested source
   * @throws IOException if a configured trusted-keys or public-key file cannot be read
   */
  static TrustedAppKeys loadTrustedKeys(
      Path trustedKeysFile, String keyId, String publicKeyBase64, Path publicKeyFile)
      throws IOException {
    if (trustedKeysFile != null) {
      return TrustedAppKeys.load(trustedKeysFile);
    }
    int directSourceCount = countConfigured(publicKeyBase64, publicKeyFile, null);
    if (directSourceCount == 0) {
      return TrustedAppKeys.empty();
    }
    if (directSourceCount > 1) {
      throw new AppDistributionException(
          "trusted public key material must be configured by base64 or file, not both");
    }
    if (keyId == null || keyId.isBlank()) {
      throw new AppDistributionException("missing required argument: --trusted-key-id");
    }
    return TrustedAppKeys.of(
        publicKeyBase64 != null
            ? TrustedAppKey.ed25519(keyId, publicKeyBase64)
            : loadTrustedPublicKeyFile(keyId, publicKeyFile));
  }

  /**
   * Counts how many mutually exclusive key sources were configured.
   *
   * @param text direct key text source
   * @param file key file source
   * @param environmentName environment-variable key source
   * @return number of non-null sources supplied by the command
   */
  private static int countConfigured(String text, Path file, String environmentName) {
    return (text == null ? 0 : 1) + (file == null ? 0 : 1) + (environmentName == null ? 0 : 1);
  }

  /**
   * Loads a private key from a file as text first and raw bytes second.
   *
   * @param file private-key file path supplied by the CLI
   * @return decoded private key from the file contents
   * @throws IOException if the file cannot be read
   */
  private static PrivateKey loadPrivateKeyFile(Path file) throws IOException {
    byte[] rawBytes = Files.readAllBytes(file);
    String text = new String(rawBytes, StandardCharsets.UTF_8);
    try {
      return AppBundleSigner.loadPrivateKey(text);
    } catch (AppDistributionException | IllegalArgumentException textFailure) {
      try {
        return AppBundleSigner.loadPrivateKey(rawBytes);
      } catch (AppDistributionException rawFailure) {
        rawFailure.addSuppressed(textFailure);
        throw rawFailure;
      }
    }
  }

  /**
   * Loads one trusted public key from a file as text first and raw bytes second.
   *
   * @param keyId key identifier associated with the public key
   * @param file public-key file path supplied by the CLI
   * @return trusted public key using the supplied key identifier
   * @throws IOException if the file cannot be read
   */
  private static TrustedAppKey loadTrustedPublicKeyFile(String keyId, Path file)
      throws IOException {
    byte[] rawBytes = Files.readAllBytes(file);
    String text = new String(rawBytes, StandardCharsets.UTF_8);
    try {
      return TrustedAppKey.ed25519(keyId, text);
    } catch (AppDistributionException | IllegalArgumentException textFailure) {
      try {
        return TrustedAppKey.ed25519(keyId, rawBytes);
      } catch (AppDistributionException rawFailure) {
        rawFailure.addSuppressed(textFailure);
        throw rawFailure;
      }
    }
  }
}
