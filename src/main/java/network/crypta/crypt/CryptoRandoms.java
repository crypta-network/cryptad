package network.crypta.crypt;

import java.security.SecureRandom;

/**
 * Exposes the shared process-wide source of cryptographic randomness.
 *
 * <p>The shared {@link SecureRandom} is initialized lazily and force-seeded on first use. Node
 * bootstrap warms the same singleton via {@code NodeStarter.getGlobalSecureRandom()} so that
 * callers still pay any entropy blocking cost during startup instead of during later cryptographic
 * operations.
 *
 * <p>This class exists so crypt-layer code can depend on a stable helper inside {@code
 * network.crypta.crypt} instead of reaching up into startup code. The lifecycle is still
 * coordinated with bootstrap: the first call creates the singleton, eagerly seeds it by producing a
 * small block of random bytes, and then publishes the fully initialized instance for the rest of
 * the process lifetime.
 */
public final class CryptoRandoms {
  /** Prevents instantiation of this singleton access utility. */
  private CryptoRandoms() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Returns the shared process-wide {@link SecureRandom} instance.
   *
   * <p>The instance is created lazily on first use and seeded eagerly before being published.
   * Repeated calls return the same object, so callers share one process-wide randomness source
   * rather than creating their own per-operation generators.
   *
   * @return shared secure random source for cryptographic operations in this JVM
   */
  public static SecureRandom shared() {
    return Holder.SHARED;
  }

  /** Holds the lazily initialized singleton and the private seeding routine used to create it. */
  private static final class Holder {
    /** Shared {@link SecureRandom} instance after eager self-seeding completes. */
    private static final SecureRandom SHARED = forceSeeding(new SecureRandom());

    /** Prevents instantiation of the lazy-holder helper. */
    private Holder() {
      throw new IllegalStateException("Utility class");
    }

    /**
     * Forces the candidate random source to perform its initial self-seeding work immediately.
     *
     * <p>The method reads a small block of random bytes before the instance is published. That
     * keeps any startup-time entropy blocking at initialization time instead of deferring it to the
     * first later encryption, key-generation, or certificate-generation call.
     *
     * @param secureRandom random source being prepared for shared process-wide use
     * @return the same random source after eager seeding has completed
     */
    private static SecureRandom forceSeeding(SecureRandom secureRandom) {
      secureRandom.nextBytes(new byte[16]);
      return secureRandom;
    }
  }
}
