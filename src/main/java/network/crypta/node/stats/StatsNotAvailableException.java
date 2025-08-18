package network.crypta.node.stats;

import java.io.Serial;

/**
 * @author nikotyan
 */
public class StatsNotAvailableException extends Exception {

	@Serial final private static long serialVersionUID = -7349859507599514672L;

	public StatsNotAvailableException() {
	}

	public StatsNotAvailableException(String s) {
		super(s);
	}

	public StatsNotAvailableException(String s, Throwable throwable) {
		super(s, throwable);
	}

	public StatsNotAvailableException(Throwable throwable) {
		super(throwable);
	}
}
