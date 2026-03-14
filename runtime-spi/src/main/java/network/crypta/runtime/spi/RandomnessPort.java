package network.crypta.runtime.spi;

import java.util.Random;

/**
 * Exposes secure and weak random services without leaking daemon-specific random-source types.
 *
 * <p>This port separates two distinct runtime capabilities that already exist inside the daemon: a
 * stronger source for security-sensitive byte generation and a faster weak generator for low-risk,
 * infrastructure-oriented randomness. By publishing both through JDK types, higher layers can
 * request randomness without depending on bootstrap internals or on custom random abstractions that
 * belong to the root module.
 *
 * <p>Callers are responsible for choosing the right method for their use case. Secure byte filling
 * is appropriate when unpredictability matters. The weak generator exists for cases where
 * reproducibility is not required and the values are not used as a security boundary.
 *
 * @see RuntimePorts
 */
public interface RandomnessPort {
  /**
   * Fills the supplied byte array with bytes from the runtime's secure random source.
   *
   * <p>The contents of {@code target} are replaced in place. The method preserves the daemon's
   * existing secure-random behavior, including any seeding and implementation details hidden behind
   * the runtime. Callers may pass an empty array when they need no bytes, but they should provide a
   * correctly sized buffer up front because this method does not allocate or return a new array.
   *
   * @param target destination buffer that receives secure random bytes across its full length
   */
  void fillSecureRandom(byte[] target);

  /**
   * Returns the runtime's fast weak random generator.
   *
   * <p>The returned {@link Random} preserves the daemon's current non-cryptographic randomness
   * source. It is suitable for low-risk identifiers, backoff variation, or other operational uses
   * where speed matters more than strong unpredictability. Callers should not treat values from
   * this generator as secrets, authentication material, or a replacement for the secure byte source
   * exposed by {@link #fillSecureRandom(byte[])}.
   *
   * @return a live weak random generator supplied by the runtime for non-cryptographic use
   */
  Random fastWeakRandom();
}
