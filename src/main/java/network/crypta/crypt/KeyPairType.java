package network.crypta.crypt;

import java.security.spec.ECGenParameterSpec;

/**
 * Enumerates EC-based keypair algorithms available to Crypta.
 *
 * <p>Legacy DSA handling remains in dedicated DSA classes for verification of historical content,
 * but is no longer exposed via this enum.
 */
public enum KeyPairType {
  ECP256("EC", "secp256r1", 91),
  ECP384("EC", "secp384r1", 120),
  ECP521("EC", "secp521r1", 158);

  public final String alg;
  public final String specName;

  /** Expected size of a DER encoded pubkey in bytes. */
  public final int modulusSize;

  public final ECGenParameterSpec spec;

  /**
   * Creates EC enum values and creates ECGenParameterSpec for them.
   *
   * @param alg What algorithm KeyPairGenerators should use
   * @param specName The elliptic curve to use.
   * @param modulusSize Expected size of a DER encoded pubkey in bytes
   */
  KeyPairType(String alg, String specName, int modulusSize) {
    this.alg = alg;
    this.specName = specName;
    this.modulusSize = modulusSize;
    this.spec = new ECGenParameterSpec(specName);
  }
}
