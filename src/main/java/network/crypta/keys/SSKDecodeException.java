package network.crypta.keys;

import java.io.Serial;

public class SSKDecodeException extends KeyDecodeException {
	@Serial private static final long serialVersionUID = -1;

	public SSKDecodeException(String string) {
		super(string);
	}

}
