package network.crypta.config;

import java.io.Serial;

/**
 * Thrown when a format error occurs, and we cannot parse the string set into the appropriate
 * type.
 */
public class OptionFormatException extends InvalidConfigValueException {
	@Serial private static final long serialVersionUID = -1;
	public OptionFormatException(String msg) {
		super(msg);
	}

}
