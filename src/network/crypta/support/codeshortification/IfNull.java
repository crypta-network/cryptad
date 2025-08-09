package network.crypta.support.codeshortification;

import java.util.Objects;


/**
 * Class for reducing the amount of code to type with regards to null pointers: <br>
 * <code>if(value == null) throw new NullPointerException(message);</code><br>
 * becomes:<br>
 * <code>IfNull.thenThrow(value, message);</code>
 * 
 * @author xor (xor@freenetproject.org)
 * @deprecated
 *     Use {@link Objects#requireNonNull(Object)} or {@link Objects#requireNonNull(Object, String)}
 */
@Deprecated
public final class IfNull {
	
	/** @deprecated Use {@link Objects#requireNonNull(Object)} */
	@Deprecated
	public static void thenThrow(Object value) {
		if(value == null)
			throw new NullPointerException();
	}
	
	/** @deprecated Use {@link Objects#requireNonNull(Object, String)} */
	@Deprecated
	public static void thenThrow(Object value, String message) {
		if(value == null)
			throw new NullPointerException(message);
	}
	
}
