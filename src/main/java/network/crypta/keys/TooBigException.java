package network.crypta.keys;

import java.io.IOException;
import java.io.Serial;

public class TooBigException extends IOException {

	/**
	 * 
	 */
	@Serial private static final long serialVersionUID = 1L;

	public TooBigException(String msg) {
		super(msg);
	}

}
