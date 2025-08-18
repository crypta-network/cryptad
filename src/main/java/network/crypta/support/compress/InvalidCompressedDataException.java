package network.crypta.support.compress;

import java.io.IOException;
import java.io.Serial;

public class InvalidCompressedDataException extends IOException {

	@Serial private static final long serialVersionUID = -1L;

	public InvalidCompressedDataException() {
		super();
	}
	
	public InvalidCompressedDataException(String msg) {
		super(msg);
	}

}
