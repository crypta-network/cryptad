package network.crypta.client.async;

import network.crypta.keys.KeyVerifyException;

import java.io.Serial;

public class BinaryBlobFormatException extends Exception {

	/**
	 * 
	 */
	@Serial private static final long serialVersionUID = 1L;

	public BinaryBlobFormatException(String message) {
		super(message);
	}

	public BinaryBlobFormatException(String message, KeyVerifyException e) {
		super(message, e);
	}

}
