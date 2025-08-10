package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

public class PutSuccessfulMessage extends FCPMessage {

	public final String identifier;
	public final boolean global;
	public final FreenetURI uri;
	public final long startupTime, completionTime;
	
	public PutSuccessfulMessage(String identifier, boolean global, FreenetURI uri, long startupTime, long completionTime) {
		this.identifier = identifier;
		this.global = global;
		this.uri = uri;
		this.startupTime = startupTime;
		this.completionTime = completionTime;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		fs.put("Global", global);
		// This is useful for simple clients.
		if(uri != null)
			fs.putSingle("URI", uri.toString(false, false));
		fs.put("StartupTime", startupTime);
		fs.put("CompletionTime", completionTime);
		return fs;
	}

	@Override
	public String getName() {
		return "PutSuccessful";
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "InsertSuccessful goes from server to client not the other way around", identifier, global);
	}

}
