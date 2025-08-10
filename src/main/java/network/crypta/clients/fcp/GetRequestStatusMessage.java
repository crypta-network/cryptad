package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;

public class GetRequestStatusMessage extends FCPMessage {

	final String identifier;
	final boolean global;
	final boolean onlyData;
	final static String NAME = "GetRequestStatus";
	
	public GetRequestStatusMessage(SimpleFieldSet fs) {
		this.identifier = fs.get("Identifier");
		this.global = fs.getBoolean("Global", false);
		this.onlyData = fs.getBoolean("OnlyData", false);
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		return fs;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void run(final FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		ClientRequest req = handler.getRebootRequest(global, handler, identifier);
		if(req == null) {
			if(node.getClientCore().killedDatabase()) {
				// Ignore.
				return;
			}
			try {
                node.getClientCore().getClientContext().jobRunner.queue(new PersistentJob() {
                    
                    @Override
                    public boolean run(ClientContext context) {
                        ClientRequest req = handler.getForeverRequest(global, handler, identifier);
                        if(req == null) {
                            ProtocolErrorMessage msg = new ProtocolErrorMessage(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, false, null, identifier, global);
                            handler.send(msg);
                        } else {
                            req.sendPendingMessages(handler.getOutputHandler(), identifier, true, onlyData);
                        }
                        return false;
                    }
                    
                }, NativeThread.NORM_PRIORITY);
            } catch (PersistenceDisabledException e) {
                ProtocolErrorMessage msg = new ProtocolErrorMessage(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, false, null, identifier, global);
                handler.send(msg);
            }
		} else {
			req.sendPendingMessages(handler.getOutputHandler(), identifier, true, onlyData);
		}
	}

}
