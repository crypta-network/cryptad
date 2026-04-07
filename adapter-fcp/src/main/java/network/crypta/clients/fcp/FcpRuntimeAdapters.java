package network.crypta.clients.fcp;

import java.io.Serial;
import java.nio.ByteBuffer;
import java.util.Objects;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.PriorityAwareExecutor;
import org.jetbrains.annotations.NotNull;

/**
 * Package-local adapters that let FCP consume runtime SPI capabilities through legacy interfaces.
 *
 * <p>This helper keeps the migration boundary inside {@code clients.fcp}. Callers that already
 * depend on FCP-local behavior can obtain a {@link PriorityAwareExecutor}, a {@link RandomSource},
 * or a one-off secure {@code long} without reaching back into daemon-only runtime objects. The
 * class deliberately translates only the narrow behavior needed by the remaining call sites in this
 * package.
 *
 * <p>The adapters are intentionally conservative. Execution introspection methods report empty
 * snapshots rather than guessing at daemon thread state, and the randomness bridge does not claim
 * ownership of the underlying {@link RandomnessPort}. Treat the returned adapters as short-lived
 * views over the live runtime rather than as stable serialization or lifecycle boundaries.
 */
final class FcpRuntimeAdapters {
  /** Prevents instantiation of this utility holder. */
  private FcpRuntimeAdapters() {}

  /**
   * Returns a {@link PriorityAwareExecutor} backed by the runtime execution port.
   *
   * <p>The adapter preserves the legacy FCP call shape for code that still expects an executor-like
   * type. Task submission flows through {@link ExecutionPort#execute(Runnable, String)}, while the
   * optional thread-count methods continue to report conservative empty snapshots because the SPI
   * does not expose daemon worker internals.
   *
   * @param runtime aggregate runtime SPI view that supplies the execution capability
   * @return executor adapter that forwards named work to the live runtime
   */
  static PriorityAwareExecutor priorityAwareExecutor(RuntimePorts runtime) {
    return new ExecutionPortPriorityAwareExecutor(runtime.execution());
  }

  /**
   * Returns a {@link RandomSource} backed by the runtime secure-random capability.
   *
   * <p>This bridge exists for legacy APIs that still accept the daemon's {@link RandomSource}
   * abstraction. Calls that need random bytes delegate to {@link RandomnessPort#fillSecureRandom
   * (byte[])}, while entropy-acceptance hooks remain inert because the SPI does not publish mutable
   * entropy-pool controls.
   *
   * @param randomness runtime randomness capability that supplies secure bytes
   * @return random-source adapter that reads secure randomness from the runtime
   */
  static RandomSource secureRandomSource(RandomnessPort randomness) {
    return new RandomnessPortRandomSource(randomness);
  }

  /**
   * Returns a secure pseudo-random {@code long} generated from the runtime randomness port.
   *
   * <p>The helper allocates an eight-byte buffer, fills it with secure random data, and interprets
   * the resulting bytes as a {@code long}. It is intended for FCP call sites that need a single
   * secure identifier value without depending on the daemon's bootstrap randomness classes.
   *
   * @param randomness runtime randomness capability used to fill the temporary byte buffer
   * @return a {@code long} assembled from eight secure random bytes
   */
  static long nextSecureLong(RandomnessPort randomness) {
    byte[] bytes = new byte[Long.BYTES];
    randomness.fillSecureRandom(bytes);
    return ByteBuffer.wrap(bytes).getLong();
  }

  /**
   * Minimal {@link PriorityAwareExecutor} implementation that delegates scheduling to {@link
   * ExecutionPort}.
   *
   * <p>The adapter preserves the legacy submission overloads used by FCP without widening the SPI.
   * It normalizes missing job names to the runnable class name and ignores the {@code fromTicker}
   * hint because the runtime execution port does not expose ticker-aware scheduling controls.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class ExecutionPortPriorityAwareExecutor implements PriorityAwareExecutor {
    /** Underlying runtime execution capability that receives all submitted jobs. */
    private final ExecutionPort execution;

    /**
     * Creates an executor adapter for the supplied runtime execution capability.
     *
     * @param execution runtime execution port that accepts named background work
     */
    private ExecutionPortPriorityAwareExecutor(ExecutionPort execution) {
      this.execution = Objects.requireNonNull(execution);
    }

    @Override
    public void execute(@NotNull Runnable job) {
      execution.execute(Objects.requireNonNull(job), defaultJobName(job));
    }

    @Override
    public void execute(Runnable job, String jobName) {
      execution.execute(Objects.requireNonNull(job), normalizeJobName(job, jobName));
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      execution.execute(Objects.requireNonNull(job), normalizeJobName(job, jobName));
    }

    @Override
    public int[] waitingThreads() {
      return new int[0];
    }

    @Override
    public int[] runningThreads() {
      return new int[0];
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }

    /**
     * Derives a fallback job label from the runnable implementation type.
     *
     * @param job submitted runnable whose implementation class names the work item
     * @return non-empty default job name used for diagnostics
     */
    private static String defaultJobName(Runnable job) {
      return job.getClass().getName();
    }

    /**
     * Normalizes an optional job name before it is passed to the runtime.
     *
     * @param job submitted runnable used as the fallback naming source
     * @param jobName caller-provided label that may be {@code null} or blank
     * @return caller label when present, otherwise the runnable class name
     */
    private static String normalizeJobName(Runnable job, String jobName) {
      return (jobName == null || jobName.isBlank()) ? defaultJobName(job) : jobName;
    }
  }

  /**
   * {@link RandomSource} adapter that sources secure bytes from {@link RandomnessPort}.
   *
   * <p>The bridge supports legacy APIs that still require {@link RandomSource} while keeping the
   * daemon-specific random implementation out of the runtime SPI. It only models the read side of
   * the old abstraction. Entropy-ingest methods return zero, and callers should treat instances as
   * non-owning views over a live runtime port.
   */
  private static final class RandomnessPortRandomSource extends RandomSource {
    @Serial private static final long serialVersionUID = 1L;

    /**
     * Live runtime randomness capability backing this adapter.
     *
     * <p>The field is transient so misuse after Java serialization fails explicitly instead of
     * silently reviving a disconnected runtime handle.
     */
    private final transient RandomnessPort randomness;

    /**
     * Creates a random-source adapter for the supplied runtime randomness capability.
     *
     * @param randomness runtime randomness port that supplies secure bytes on demand
     */
    private RandomnessPortRandomSource(RandomnessPort randomness) {
      this.randomness = Objects.requireNonNull(randomness);
    }

    @Override
    public void nextBytes(byte[] bytes) {
      requireRandomness().fillSecureRandom(bytes);
    }

    @Override
    protected synchronized int next(int bits) {
      if (bits <= 0) {
        return 0;
      }
      byte[] bytes = new byte[Integer.BYTES];
      requireRandomness().fillSecureRandom(bytes);
      return ByteBuffer.wrap(bytes).getInt() >>> (Integer.SIZE - bits);
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
    public void close() {
      // This adapter does not own the runtime randomness port, so there is nothing to release.
    }

    /**
     * Returns the live runtime randomness capability or fails clearly after serialization.
     *
     * @return runtime randomness port currently backing this adapter
     * @throws NullPointerException if the adapter has been deserialized without a live runtime port
     */
    private RandomnessPort requireRandomness() {
      return Objects.requireNonNull(
          randomness, "RandomnessPortRandomSource must not be used after serialization");
    }
  }
}
