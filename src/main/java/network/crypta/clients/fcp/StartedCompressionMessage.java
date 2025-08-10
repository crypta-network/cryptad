package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

public class StartedCompressionMessage extends FCPMessage {

	final String identifier;
	final boolean global;
	
	final COMPRESSOR_TYPE codec;
	
	public StartedCompressionMessage(String identifier, boolean global, COMPRESSOR_TYPE codec) {
		this.identifier = identifier;
		this.codec = codec;
		this.global = global;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		fs.putSingle("Codec", codec.name);
		fs.put("Global", global);
		return fs;
	}

	@Override
	public String getName() {
		return "StartedCompression";
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "StartedCompression goes from server to client not the other way around", identifier, global);
	}

}
