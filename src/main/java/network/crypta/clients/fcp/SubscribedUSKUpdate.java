package network.crypta.clients.fcp;

import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

public class SubscribedUSKUpdate extends FCPMessage {

	final String identifier;
	final long edition;
	final USK key;
	final boolean newKnownGood;
	final boolean newSlotToo;
	
	static final String name = "SubscribedUSKUpdate";
	
	public SubscribedUSKUpdate(String identifier, long l, USK key, boolean newKnownGood, boolean newSlotToo) {
		this.identifier = identifier;
		this.edition = l;
		this.key = key;
		this.newKnownGood = newKnownGood;
		this.newSlotToo = newSlotToo;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		fs.put("Edition", edition);
		fs.putSingle("URI", key.getURI().toString());
		fs.put("NewKnownGood", newKnownGood);
		fs.put("NewSlotToo", newSlotToo);
		return fs;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "SubscribedUSKUpdate goes from server to client not the other way around", identifier, false);
	}

}
