package network.crypta.io.comm;

import network.crypta.support.LightweightException;

import java.io.Serial;

public class IncomingPacketFilterException extends LightweightException {
	@Serial private static final long serialVersionUID = -1;

	public IncomingPacketFilterException(String string) {
		super(string);
	}

	public IncomingPacketFilterException() {
		super();
	}

}
