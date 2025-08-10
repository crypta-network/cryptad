package network.crypta.keys;

public class KeyEncodeException extends Exception {
	private static final long serialVersionUID = -1;

	public KeyEncodeException(String string) {
		super(string);
	}

	public KeyEncodeException() {
		super();
	}

	public KeyEncodeException(String message, Throwable cause) {
		super(message, cause);
	}

	public KeyEncodeException(Throwable cause) {
		super(cause);
	}

}
