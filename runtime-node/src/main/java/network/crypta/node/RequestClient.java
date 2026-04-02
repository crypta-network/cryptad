package network.crypta.node;

/**
 * Describes client-level attributes used by the scheduler to classify and prioritize a request.
 *
 * <p>Implementations are returned by {@code SendableRequest.getClient()} and provide stable
 * metadata that guides scheduling decisions. The results of {@link #persistent()} and {@link
 * #realTimeFlag()} must remain constant for the lifetime of the enclosing request. Methods are side
 * effect free and expected to execute quickly.
 *
 * <p>Use a {@link RequestClientBuilder} to conveniently build {@code RequestClient} instances.
 *
 * @author toad
 */
public interface RequestClient {

  /**
   * Returns whether the request is persistent. The value is consulted by the scheduler to treat the
   * request as durable versus ephemeral and must not change once constructed.
   *
   * @return {@code true} if the request is persistent; {@code false} otherwise
   */
  boolean persistent();

  /**
   * Returns whether the request uses the real-time flag. Real-time requests receive latency-
   * oriented handling and a higher priority in data transfers, but fewer are admitted and overall
   * throughput may be lower. The value must not change over the lifetime of the request.
   *
   * @return {@code true} for real-time scheduling; {@code false} for normal scheduling
   */
  boolean realTimeFlag();
}
