package network.crypta.support.compress;

/**
 * The given codec identifier was invalid (number out of range, or misstyped
 * name)
 */
public class InvalidCompressionCodecException extends Exception {

	private static final long serialVersionUID = -1;

	public InvalidCompressionCodecException(String message) {
		super(message);
	}

}
