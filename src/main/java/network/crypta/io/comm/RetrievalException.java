package network.crypta.io.comm;


import network.crypta.support.LightweightException;

/**
 * @author ian
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class RetrievalException extends LightweightException {
	private static final long serialVersionUID = 3257565105301500723L;

	public static final int UNKNOWN = 0;
	public static final int PREMATURE_EOF = 2;
	public static final int IO_ERROR = 3;
	public static final int SENDER_DIED = 5;
	public static final int TIMED_OUT = 4;
    public static final int ALREADY_CACHED = 6;
    public static final int SENDER_DISCONNECTED = 7;
    public static final int NO_DATAINSERT = 8;
    public static final int CANCELLED_BY_RECEIVER = 9;
	public static final int RECEIVER_DIED = 11;
	public static final int UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT = 12;
	public static final int GONE_TO_TURTLE_MODE = 13;
	public static final int TURTLE_KILLED = 14;
	
	int _reason;
	String _cause;

	public RetrievalException(int reason) {
		_reason = reason;
		_cause = getErrString(reason);
	}
	
	public RetrievalException(int reason, String cause) {
		_reason = reason;
		_cause = cause;
		if (cause==null || cause.isEmpty() || cause.equals("null"))
			_cause=getErrString(reason);
	}
	
	public int getReason() {
		return _reason;
	}
	
	@Override
	public String toString() {
		return getErrString(_reason)+":"+_cause;
	}

	/** Guaranteed not to have any spaces in it. */
	public String getErrString() {
		return getErrString(_reason);
	}
	
	public static String getErrString(int reason) {
		switch (reason) {
			case PREMATURE_EOF:
				return "PREMATURE_EOF";
			case IO_ERROR:
				return "IO_ERROR";
			case SENDER_DIED:
				return "SENDER_DIED";
			case TIMED_OUT:
				return "TIMED_OUT";
			case ALREADY_CACHED:
				return "ALREADY_CACHED";
			case SENDER_DISCONNECTED:
				return "SENDER_DISCONNECTED";
			case NO_DATAINSERT:
				return "NO_DATAINSERT";
			case CANCELLED_BY_RECEIVER:
				return "CANCELLED_BY_RECEIVER";
			case UNKNOWN:
				return "UNKNOWN";
			case UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT:
				return "UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT";
			case GONE_TO_TURTLE_MODE:
				return "GONE_TO_TURTLE_MODE";
			case TURTLE_KILLED:
				return "TURTLE_KILLED";
			default:
				return "UNKNOWN ("+reason+")";
		}
	}
	
	@Override
	public String getMessage() {
		return toString();
	}
}
