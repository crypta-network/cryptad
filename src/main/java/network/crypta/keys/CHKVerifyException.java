package network.crypta.keys;

/**
 * @author amphibian
 * 
 * Exception thrown when a CHK doesn't verify.
 */
public class CHKVerifyException extends KeyVerifyException {
	private static final long serialVersionUID = -1;

    public CHKVerifyException() {
        super();
    }

    public CHKVerifyException(String message) {
        super(message);
    }

    public CHKVerifyException(String message, Throwable cause) {
        super(message, cause);
    }

    public CHKVerifyException(Throwable cause) {
        super(cause);
    }

}
