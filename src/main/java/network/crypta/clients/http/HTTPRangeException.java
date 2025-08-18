package network.crypta.clients.http;

import network.crypta.support.LightweightException;

import java.io.Serial;

/**
 * If thrown, something wrong with http range
 */
public class HTTPRangeException extends LightweightException {
	@Serial private static final long serialVersionUID = -1;

	public HTTPRangeException(Throwable cause) {
		super(cause);
	}

	public HTTPRangeException(String msg) {
		super(msg);
	}
}
