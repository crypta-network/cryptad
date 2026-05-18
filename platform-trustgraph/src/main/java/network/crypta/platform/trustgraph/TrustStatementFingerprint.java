package network.crypta.platform.trustgraph;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 helpers for canonical trust statement payloads and redacted document summaries.
 *
 * <p>The preview service uses hashes as stable local identifiers in API responses and release
 * evidence. Hashes let the app display and compare imported statements without echoing raw
 * documents, raw signatures, or request bodies. The helpers are deterministic and use lowercase
 * hexadecimal output.
 */
public final class TrustStatementFingerprint {
  private static final char[] HEX = "0123456789abcdef".toCharArray();

  private TrustStatementFingerprint() {}

  /**
   * Returns the SHA-256 hash of the domain-separated canonical payload bytes.
   *
   * @param document trust statement whose payload should be canonicalized
   * @return lowercase hexadecimal SHA-256 payload hash
   */
  public static String payloadHash(TrustStatementDocument document) {
    return sha256Hex(TrustStatementCanonicalizer.canonicalPayloadBytes(document.payload()));
  }

  /**
   * Returns a document fingerprint over public statement metadata without logging the signature.
   *
   * <p>The signature value is included in the in-memory hash input through the full JSON document,
   * but callers only receive the hash. Normal summaries never include the raw signature.
   *
   * @param document trust statement document to fingerprint
   * @return lowercase hexadecimal SHA-256 document fingerprint
   */
  public static String documentFingerprint(TrustStatementDocument document) {
    return sha256Hex(
        TrustJson.write(document.toJson()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  /**
   * Returns the SHA-256 hash of arbitrary bytes as lowercase hex.
   *
   * @param bytes input bytes to hash
   * @return lowercase hexadecimal SHA-256 digest
   */
  public static String sha256Hex(byte[] bytes) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
      char[] out = new char[digest.length * 2];
      for (int i = 0; i < digest.length; i++) {
        int value = digest[i] & 0xff;
        out[i * 2] = HEX[value >>> 4];
        out[i * 2 + 1] = HEX[value & 0x0f];
      }
      return new String(out);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
