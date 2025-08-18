package network.crypta.keys;

import network.crypta.crypt.CryptFormatException;

import java.io.Serial;

public class PubkeyVerifyException extends KeyVerifyException {

	@Serial private static final long serialVersionUID = 1L;

	public PubkeyVerifyException(CryptFormatException e) {
		super(e);
	}

	public PubkeyVerifyException(String msg) {
		super(msg);
	}

}
