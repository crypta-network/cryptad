package network.crypta.node;

/**
 * checked exception thrown by Version.getArbitraryBuildNumber()
 * @author toad
 */
public class VersionParseException extends Exception {
	private static final long serialVersionUID = -19006235321212642L;

	public VersionParseException(String msg) {
		super(msg);
	}

}
