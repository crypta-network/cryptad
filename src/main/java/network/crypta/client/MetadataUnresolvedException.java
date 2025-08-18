package network.crypta.client;

import java.io.Serial;

public class MetadataUnresolvedException extends Exception {
	@Serial private static final long serialVersionUID = -1;

	public final Metadata[] mustResolve;
	
	public MetadataUnresolvedException(Metadata[] mustResolve, String message) {
		super(message);
		this.mustResolve = mustResolve;
	}

}
