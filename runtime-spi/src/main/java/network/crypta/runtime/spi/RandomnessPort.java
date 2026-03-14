package network.crypta.runtime.spi;

import java.util.Random;

/** Exposes secure and weak random services without leaking daemon random-source types. */
public interface RandomnessPort {
  void fillSecureRandom(byte[] target);

  Random fastWeakRandom();
}
