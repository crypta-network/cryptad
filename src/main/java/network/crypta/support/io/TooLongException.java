package network.crypta.support.io;

import java.io.IOException;
import java.io.Serial;

/** Exception thrown by a LineReadingInputStream when a line is too long. */
public class TooLongException extends IOException {
	@Serial private static final long serialVersionUID = -1;

	TooLongException(String s) {
		super(s);
	}
}