package network.crypta.io.xfer;

import java.io.Serial;

/**
 * Thrown when a transfer is aborted, and caller tries to do something on PRB,
 * in order to avoid some races.
 */
public class AbortedException extends Exception {
	@Serial private static final long serialVersionUID = -1;
	
	public AbortedException(String msg) {
		super(msg);
	}

}
