package network.crypta.clients.http;

import network.crypta.support.LightweightException;

/**
 * If thrown, something wrong with http range
 */
public class HTTPRangeException extends LightweightException {
	private static final long serialVersionUID = -1;

	public HTTPRangeException(Throwable cause) {
		super(cause);
	}

	public HTTPRangeException(String msg) {
		super(msg);
	}
}
