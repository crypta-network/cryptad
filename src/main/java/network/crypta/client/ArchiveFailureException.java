package network.crypta.client;

/**
 * @author amphibian (Matthew Toseland)
 * Thrown when an archive operation fails.
 */
public class ArchiveFailureException extends Exception {

	private static final long serialVersionUID = -5915105120222575469L;
	
	public static final String TOO_MANY_LEVELS = "Too many archive levels";
	public static final String ARCHIVE_LOOP_DETECTED = "Archive loop detected";

	public ArchiveFailureException(String message) {
		super(message);
	}

	public ArchiveFailureException(String message, Exception e) {
		super(message);
		initCause(e);
	}

}
