package network.crypta.client;

import java.io.Serial;

/** Thrown when Metadata parse fails. */
public class MetadataParseException extends Exception {

	@Serial private static final long serialVersionUID = 4910650977022715220L;

	public MetadataParseException(String string) {
		super(string);
	}

}
