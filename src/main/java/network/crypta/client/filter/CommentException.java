package network.crypta.client.filter;

import java.io.Serial;

/**
 * Thrown when a filter operation cannot complete and the filter has produced some error output to help guide the user in
 * resolving the situation.
 * 
 * Note that the message is not yet encoded, and may contain data-dependant information; that is the responsibility of the 
 * catcher.
 */
public class CommentException extends Exception {

	@Serial private static final long serialVersionUID = 1L;

	public CommentException(String msg) {
		super(msg);
	}

}
