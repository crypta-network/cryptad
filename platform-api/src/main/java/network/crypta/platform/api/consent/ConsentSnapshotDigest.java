package network.crypta.platform.api.consent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Computes deterministic SHA-256 fingerprints for consent snapshots.
 *
 * <p>The digest binds an operator decision to the exact material contents of a consent preview.
 * Request ids and creation timestamps stay outside the digest, while action, app id, versions,
 * digests, catalog metadata, risk, findings, and recommended action remain inside it. Mutating
 * routes compare this value before consuming an approval so a refreshed catalog, changed review
 * receipt, altered permission set, or different migration plan cannot reuse an old decision.
 *
 * <p>Digest input is first canonicalized with {@link ConsentJson#canonicalize(Object)} and then
 * written through the Platform API JSON writer. The resulting bytes are hashed with SHA-256 and
 * returned with the {@code sha256:} prefix used by the rest of the app-platform API.
 */
public final class ConsentSnapshotDigest {
  private ConsentSnapshotDigest() {}

  /**
   * Returns {@code sha256:<hex>} for the canonical digest form of the snapshot.
   *
   * <p>The method is deterministic for equal snapshot material even when map insertion order
   * differs inside sections or findings. It throws an unchecked exception only if the Java runtime
   * does not provide SHA-256, which would make stale-consent protection unavailable.
   *
   * @param snapshot consent snapshot whose digestable contents should be fingerprinted
   * @return stable SHA-256 digest token for approval matching
   */
  public static String digest(ConsentSnapshot snapshot) {
    String json = PlatformApiJsonWriter.write(ConsentJson.canonicalize(snapshot.toDigestJson()));
    byte[] digest;
    try {
      digest = MessageDigest.getInstance("SHA-256").digest(json.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
    StringBuilder hex = new StringBuilder("sha256:");
    for (byte value : digest) {
      hex.append(Character.forDigit((value >>> 4) & 0x0f, 16));
      hex.append(Character.forDigit(value & 0x0f, 16));
    }
    return hex.toString();
  }
}
