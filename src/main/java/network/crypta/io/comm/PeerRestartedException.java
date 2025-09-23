package network.crypta.io.comm;

import java.io.Serial;

/**
 * Thrown if a peer is restarted during an attempt to send a throttled packet, wait for an incoming
 * packet from a peer, etc.
 */
public class PeerRestartedException extends DisconnectedException {

  @Serial private static final long serialVersionUID = 616182042289792833L;
}
