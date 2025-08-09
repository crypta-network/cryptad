package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

public class WatchGlobal extends FCPMessage {

	final boolean enabled;
	final int verbosityMask;
	static final String NAME = "WatchGlobal";

	public WatchGlobal(SimpleFieldSet fs) throws MessageInvalidException {
		enabled = fs.getBoolean("Enabled", true);
		String s = fs.get("VerbosityMask");
		if(s != null)
			try {
				verbosityMask = Integer.parseInt(s);
			} catch (NumberFormatException e) {
				throw new MessageInvalidException(ProtocolErrorMessage.ERROR_PARSING_NUMBER, e.toString(), null, false);
			}
		else
			verbosityMask = Integer.MAX_VALUE;
	}
	
	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("Enabled", enabled);
		fs.put("VerbosityMask", verbosityMask);
		return fs;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void run(final FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		if(!handler.getRebootClient().setWatchGlobal(enabled, verbosityMask, node.getClientCore().getFCPServer())) {
			FCPMessage err = new ProtocolErrorMessage(ProtocolErrorMessage.PERSISTENCE_DISABLED, false, "Persistence disabled", null, true);
			handler.send(err);
		}
		PersistentRequestClient client = handler.getForeverClient();
		if(client != null)
		    client.setWatchGlobal(enabled, verbosityMask, handler.getServer());
	}

}
