package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

public class EndListPersistentRequestsMessage extends FCPMessage {

	static final String name = "EndListPersistentRequests";
	private final String listRequestIdentifier;

	public EndListPersistentRequestsMessage(String listRequestIdentifier) {
		this.listRequestIdentifier = listRequestIdentifier;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("Identifier", listRequestIdentifier);
		return simpleFieldSet;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "EndListPersistentRequests goes from server to client not the other way around", null, false);
	}

}
