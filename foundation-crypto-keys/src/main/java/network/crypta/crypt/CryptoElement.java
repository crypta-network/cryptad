package network.crypta.crypt;

/**
 * Common supertype for cryptography‑related elements.
 *
 * <p>Implementations represent values that belong to the cryptographic domain and may appear in
 * debug output, logs, or error messages. The primary contract is to provide a long, human‑readable
 * description via {@link #toLongString()} that helps diagnose issues without exposing sensitive
 * material. Implementations should avoid including raw secrets (e.g., private key bytes, seeds,
 * plaintext) in any returned text.
 *
 * @author oskar
 */
public interface CryptoElement {

  /**
   * Returns a detailed, human‑readable description of this element for diagnostics and logging.
   *
   * <p>The description should surface identifying attributes useful during debugging (for example,
   * algorithm names, sizes, or stable IDs) while refraining from printing any secret material. The
   * format is intended for humans and is not guaranteed to be stable or parseable.
   *
   * @return a descriptive string suitable for logs and error messages
   */
  @SuppressWarnings("unused")
  String toLongString();
}
