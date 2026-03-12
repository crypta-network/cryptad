package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * Signals that a previously connected peer or channel became disconnected while a blocking
 * operation was in progress.
 *
 * <p>This checked exception typically originates from messaging and transfer code when a caller is
 * waiting for an event (for example, {@code waitFor(...)} in the messaging layer) and the
 * underlying connection drops locally or remotely. It is distinct from {@link
 * NotConnectedException}, which indicates that no connection existed at the time the operation was
 * attempted.
 *
 * <p>The class extends {@link LightweightException}; by default, stack traces may be omitted to
 * keep the exception inexpensive for frequent control-flow paths. Callers should catch this
 * exception to abort the current operation or re-resolve the peer according to the calling
 * context's retry policy.
 *
 * @see NotConnectedException
 * @see PeerRestartedException
 */
public class DisconnectedException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;
}
