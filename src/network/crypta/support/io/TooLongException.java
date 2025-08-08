package network.crypta.support.io;

import java.io.IOException;

/** Exception thrown by a LineReadingInputStream when a line is too long. */
public class TooLongException extends IOException {
	private static final long serialVersionUID = -1;

	TooLongException(String s) {
		super(s);
	}
}