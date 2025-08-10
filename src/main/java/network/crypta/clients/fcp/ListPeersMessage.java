package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;

public class ListPeersMessage extends FCPMessage {

	final boolean withMetadata;
	final boolean withVolatile;
	final String identifier;
	static final String NAME = "ListPeers";
	
	public ListPeersMessage(SimpleFieldSet fs) {
		withMetadata = fs.getBoolean("WithMetadata", false);
		withVolatile = fs.getBoolean("WithVolatile", false);
		this.identifier = fs.get("Identifier");
		fs.removeValue("Identifier");
	}
	
	@Override
	public SimpleFieldSet getFieldSet() {
		return new SimpleFieldSet(true);
	}
	
	@Override
	public String getName() {
		return NAME;
	}
	
	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		if(!handler.hasFullAccess()) {
			throw new MessageInvalidException(ProtocolErrorMessage.ACCESS_DENIED, "ListPeers requires full access", identifier, false);
		}
		PeerNode[] nodes = node.getPeerNodes();
		for(PeerNode pn: nodes) {
			handler.send(new PeerMessage(pn, withMetadata, withVolatile, identifier));
		}
		
		handler.send(new EndListPeersMessage(identifier));
	}

}
