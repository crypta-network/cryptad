package network.crypta.client;

public class MetadataUnresolvedException extends Exception {
	private static final long serialVersionUID = -1;

	public final Metadata[] mustResolve;
	
	public MetadataUnresolvedException(Metadata[] mustResolve, String message) {
		super(message);
		this.mustResolve = mustResolve;
	}

}
