package network.crypta.keys;

/**
 * @author amphibian
 * 
 * Exception thrown when decode fails.
 */
public class CHKDecodeException extends KeyDecodeException {
    private static final long serialVersionUID = -1;
    
    public CHKDecodeException() {
        super();
    }

    public CHKDecodeException(String message) {
        super(message);
    }

    public CHKDecodeException(String message, Throwable cause) {
        super(message, cause);
    }

    public CHKDecodeException(Throwable cause) {
        super(cause);
    }

}
