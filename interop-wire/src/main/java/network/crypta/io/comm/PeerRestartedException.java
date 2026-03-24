package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * Indicates that the remote peer restarted during an in‑flight operation.
 *
 * <p>This specialized form of {@link DisconnectedException} is used when an established connection
 * drops because the peer process has restarted. Typical triggers include attempting to send a
 * throttled packet, waiting for an incoming reply, or otherwise interacting with a session whose
 * {@link PeerContext#getBootID() boot ID} has changed.
 *
 * <p>As a descendant of {@link LightweightException} (via {@link DisconnectedException}), stack
 * traces may be omitted by default to keep the exception inexpensive in frequent control‑flow
 * paths.
 *
 * @see DisconnectedException
 * @see NotConnectedException
 * @see PeerContext#getBootID()
 */
public class PeerRestartedException extends DisconnectedException {

  @Serial private static final long serialVersionUID = 616182042289792833L;
}
