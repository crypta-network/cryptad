package network.crypta.platform.appdist;

import java.util.Base64;
import java.util.Objects;

/**
 * Immutable parsed or generated content of {@code cryptad-app.signature}.
 *
 * <p>The signature sidecar authenticates the exact bytes of {@code cryptad-app.digests}, not a
 * reparsed or normalized representation. That detail matters because the verifier first checks the
 * Ed25519 signature over the sidecar payload and then compares the parsed digest with the current
 * bundle tree. Any change to either the digest sidecar bytes or the files named by the digest
 * causes verification to fail.
 *
 * <p>{@code keyId} is a stable lookup key into {@link TrustedAppKeys}. It is not a proof by itself;
 * the public key registry still decides whether the signer is trusted for this node or tool
 * invocation. The record validates only the sidecar schema and base64 encoding.
 *
 * @param version signature schema version, currently required to be {@code 1}
 * @param algorithm signature algorithm name, currently required to be {@code Ed25519}
 * @param keyId stable trusted-key identifier used to select the verification key
 * @param payload signed payload filename, currently {@code cryptad-app.digests}
 * @param valueBase64 base64-encoded signature over the exact digest sidecar bytes
 */
public record AppBundleSignature(
    int version, String algorithm, String keyId, String payload, String valueBase64) {
  /**
   * Canonical signature sidecar filename at the staged bundle root.
   *
   * <p>The verifier reads this file next to {@code cryptad-app.digests}; it is excluded from digest
   * generation so signatures can be regenerated without changing the payload digest.
   */
  public static final String SIGNATURE_FILE_NAME = "cryptad-app.signature";

  /**
   * Current signature sidecar schema version.
   *
   * <p>Unsupported versions are rejected instead of interpreted leniently so later signature
   * formats cannot be confused with the v1 Ed25519 payload contract.
   */
  public static final int SIGNATURE_VERSION = 1;

  /**
   * Supported signature algorithm for local app bundle signatures.
   *
   * <p>The first distribution layer intentionally uses only JDK Ed25519 support and does not depend
   * on external crypto providers.
   */
  public static final String SIGNATURE_ALGORITHM = "Ed25519";

  /**
   * Creates a validated signature snapshot.
   *
   * <p>Construction validates the declared schema, algorithm, single-line key id, single-line
   * payload name, and base64 signature encoding. It does not check whether the key id is trusted or
   * whether the signature is cryptographically valid; use {@link AppBundleVerifier} for that.
   *
   * @param version signature schema version, currently required to be {@code 1}
   * @param algorithm signature algorithm name, currently required to be {@code Ed25519}
   * @param keyId stable trusted-key identifier used to select the verification key
   * @param payload signed payload filename, currently {@code cryptad-app.digests}
   * @param valueBase64 base64-encoded signature over the exact digest sidecar bytes
   * @throws IllegalArgumentException if the supplied fields cannot represent a v1 signature sidecar
   */
  public AppBundleSignature {
    if (version != SIGNATURE_VERSION) {
      throw new IllegalArgumentException("unsupported signature.version: " + version);
    }
    if (!SIGNATURE_ALGORITHM.equals(Objects.requireNonNull(algorithm, "algorithm"))) {
      throw new IllegalArgumentException("unsupported signature.algorithm: " + algorithm);
    }
    keyId = AppDistributionSidecars.requireNonBlankSingleLine(keyId, "signature.key.id");
    payload = AppDistributionSidecars.requireNonBlankSingleLine(payload, "signature.payload");
    valueBase64 = AppDistributionSidecars.requireNonBlankSingleLine(valueBase64, "signature");
    AppDistributionSidecars.decodeBase64(valueBase64, "signature.value.base64");
  }

  /**
   * Decodes the signature bytes.
   *
   * <p>The returned array is a fresh decode of the immutable base64 text and may be safely modified
   * by the caller.
   *
   * @return signature bytes decoded from {@link #valueBase64()}
   */
  public byte[] signatureBytes() {
    return Base64.getDecoder().decode(valueBase64);
  }
}
