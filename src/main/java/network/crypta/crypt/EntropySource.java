package network.crypta.crypt;

/**
 * Mutable token that carries per‑source state for entropy estimation.
 *
 * <p>Instances are passed to {@link RandomSource} methods such as {@link
 * RandomSource#acceptTimerEntropy(EntropySource)} and {@link
 * RandomSource#acceptTimerEntropy(EntropySource, double)}. Keep one instance per independent
 * entropy producer (for example, a packet‑arrival timer or a byte stream) so the PRNG can compute
 * deltas relative to the previous observation from the same source.
 *
 * <p>Thread‑safety: this type is mutable and not thread‑safe. If shared between threads, callers
 * must coordinate access externally. Typical usage creates and uses one instance per source on the
 * calling thread.
 */
public class EntropySource {
  // Internal state tracked for a single entropy producer.
  // lastVal: last observed raw value (e.g., time or counter) used to compute deltas.
  // lastDelta/lastDelta2: first and second differences used by entropy estimators.
  long lastVal;
  int lastDelta;
  int lastDelta2;
}
