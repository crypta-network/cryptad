package network.crypta.store;

import java.io.Serial;
import network.crypta.support.LightweightException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signals that a store operation would insert a block under a routing key that already exists.
 *
 * <p>Store implementations throw this exception when an insert collides with an existing entry and
 * overwriting is not allowed. It extends {@link LightweightException} because collisions are an
 * expected control-flow outcome on hot paths; by default, no stack trace is captured to avoid the
 * associated overhead.
 *
 * <p>Diagnostics: when debug logging is enabled for this class, stack traces are captured to aid
 * troubleshooting. See {@link #shouldFillInStackTrace()}.
 *
 * @see FreenetStore#put(StorableBlock, byte[], byte[], boolean, boolean)
 * @see LightweightException
 */
public class KeyCollisionException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;

  private static final Logger LOG = LoggerFactory.getLogger(KeyCollisionException.class);

  /**
   * Enables stack-trace capture only when debug logging is active.
   *
   * <p>Collisions are common in normal operation; omitting stack traces keeps them inexpensive to
   * throw and catch. Turning on debug logging for this class opts into full traces for deeper
   * diagnostics.
   *
   * @return {@code true} if {@link Logger#isDebugEnabled()} is {@code true}; {@code false}
   *     otherwise.
   */
  @Override
  protected boolean shouldFillInStackTrace() {
    return LOG.isDebugEnabled();
  }
}
