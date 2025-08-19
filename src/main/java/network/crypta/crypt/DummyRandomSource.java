package network.crypta.crypt;

import java.io.Serial;

/**
 * @author amphibian
 *     <p>Not a real RNG at all, just a simple PRNG. Use it for e.g. simulations.
 */
public class DummyRandomSource extends RandomSource {
  @Serial private static final long serialVersionUID = -1;

  public DummyRandomSource() {}

  public DummyRandomSource(long seed) {
    setSeed(seed);
  }

  @Override
  public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
    return 0;
  }

  @Override
  public int acceptTimerEntropy(EntropySource timer) {
    return 0;
  }

  @Override
  public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
    return 0;
  }

  @Override
  public int acceptEntropyBytes(
      EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
    return 0;
  }

  @Override
  public void close() {}
}
