package network.crypta.crypt;

import java.util.Random;

/**
 * Abstraction for randomness providers used within Crypta.
 *
 * <p>This class extends {@link java.util.Random} to integrate with existing Java APIs while
 * allowing implementations to inject external entropy and report (or ignore) entropy estimates.
 * Unless otherwise documented by the implementation, the threading semantics are those of {@link
 * java.util.Random} (method-level synchronization). Implementers should preserve these semantics or
 * document deviations.
 *
 * @author Scott G. Miller <scgmille@indiana.edu>
 */
public abstract class RandomSource extends Random {

  /**
   * Returns a 32-bit random IEEE 754 float by interpreting uniformly random bits.
   *
   * <p>All 2^32 bit patterns are equally likely; this is not a uniform distribution over real
   * numbers representable as {@code float}. The result may be {@code NaN}, {@code +Infinity},
   * {@code -Infinity}, subnormal, or have either sign of zero.
   *
   * @see RandomSource#nextFloat()
   */
  public float nextFullFloat() {
    return Float.intBitsToFloat(nextInt());
  }

  /**
   * Returns a 64-bit random IEEE 754 double by interpreting uniformly random bits.
   *
   * <p>All 2^64 bit patterns are equally likely; this is not a uniform distribution over real
   * numbers representable as {@code double}. The result may be {@code NaN}, {@code +Infinity},
   * {@code -Infinity}, subnormal, or have either sign of zero.
   *
   * @see RandomSource#nextDouble()
   */
  public double nextFullDouble() {
    return Double.longBitsToDouble(nextLong());
  }

  /**
   * Accepts a 64-bit sample of entropy from the given source.
   *
   * <p>Implementations may mix {@code data} into an internal pool and may use {@code entropyGuess}
   * (in bits) as a caller-supplied estimate of the sample's unpredictability. How the estimate is
   * interpreted, bounded, or ignored is implementation-specific.
   *
   * @param source the origin of the sample; must not be {@code null}.
   * @param data the raw 64-bit sample to incorporate.
   * @param entropyGuess caller's estimate of entropy contained in {@code data}, in bits.
   * @return an implementation-defined value (commonly the number of bits credited).
   */
  public abstract int acceptEntropy(EntropySource source, long data, int entropyGuess);

  /**
   * Accepts timing-derived entropy from the given source.
   *
   * <p>Typical sources include high-resolution timers or inter-arrival measurements. The method may
   * bound or discard low-variance contributions.
   *
   * @param timer the timing-based entropy source; must not be {@code null}.
   * @return an implementation-defined value (commonly the number of bits credited).
   */
  public abstract int acceptTimerEntropy(EntropySource timer);

  /**
   * Accepts timing-derived entropy from a source with an attenuation factor.
   *
   * <p>The {@code bias} scales the contribution of the measured entropy (for example, to account
   * for correlation). Implementations may clamp values outside the supported range.
   *
   * @param fnpTimingSource the timing-based source; must not be {@code null}.
   * @param bias multiplicative factor applied to any credited entropy (commonly in {@code [0,1]}).
   * @return an implementation-defined value (commonly the number of bits credited).
   */
  public abstract int acceptTimerEntropy(EntropySource fnpTimingSource, double bias);

  /**
   * Accepts a buffer of samples from a source, with an attenuation factor.
   *
   * <p>Bytes from {@code buf} in the range {@code [offset, offset + length)} may be mixed into an
   * internal pool. Implementations should not retain a reference to {@code buf}.
   *
   * @param myPacketDataSource the origin of the data; must not be {@code null}.
   * @param buf the byte buffer containing samples; must not be {@code null}.
   * @param offset start index within {@code buf} (inclusive).
   * @param length number of bytes to read from {@code buf} starting at {@code offset}.
   * @param bias multiplicative factor applied to any credited entropy (commonly in {@code [0,1]}).
   * @return an implementation-defined value (commonly the number of bits credited).
   */
  public abstract int acceptEntropyBytes(
      EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias);

  /**
   * Blocks until the requested entropy is available, if supported.
   *
   * <p>If the implementation supports entropy accounting, the call blocks until at least {@code
   * bits} are available. Otherwise, the call returns immediately without blocking.
   *
   * @param bits number of entropy bits to wait for.
   */
  @SuppressWarnings("unused")
  public void waitForEntropy(int bits) {}

  /**
   * Releases any resources held by this source.
   *
   * <p>Implementations may use this hook to stop background collectors, close devices, or flush
   * state. The method may be a no-op. Callers should not use the instance after {@code close()}.
   */
  public abstract void close();

  @Override
  // Delegate to Random to preserve algorithm and synchronized semantics.
  protected synchronized int next(int bits) {
    return super.next(bits);
  }
}
