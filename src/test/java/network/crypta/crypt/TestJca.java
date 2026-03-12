package network.crypta.crypt;

import network.crypta.crypt.ciphers.Rijndael;

/** Test-only utility to expose whether AES/CTR is available via JCA. */
public final class TestJca {
  private TestJca() {}

  /** Whether AES/CTR with unrestricted key sizes is available via JCA. */
  public static final boolean AES_CTR_AVAILABLE = Rijndael.getAesCtrProvider() != null;
}
