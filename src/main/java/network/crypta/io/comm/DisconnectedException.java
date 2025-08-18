package network.crypta.io.comm;

import network.crypta.support.LightweightException;

import java.io.Serial;

/**
 * Thrown when the node is disconnected in the middle of (or
 * at the beginning of) a waitFor(). Not the same as 
 * NotConnectedException.
 */
public class DisconnectedException extends LightweightException {
	@Serial private static final long serialVersionUID = -1;
}
