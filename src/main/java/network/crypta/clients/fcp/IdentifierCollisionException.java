package network.crypta.clients.fcp;

import java.io.Serial;

/**
 * Thrown to indicate reuse of an Identifier.
 */
public class IdentifierCollisionException extends Exception {
	@Serial private static final long serialVersionUID = -1;
}
