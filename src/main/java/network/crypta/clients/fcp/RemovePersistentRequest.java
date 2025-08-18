package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.node.Node;
import network.crypta.support.Logger;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;

/**
 * Client telling node to remove a (completed or not) persistent request.
 */
public class RemovePersistentRequest extends FCPMessage {

	final static String NAME = "RemoveRequest";
	final static String ALT_NAME = "RemovePersistentRequest";
	
	final String identifier;
	final boolean global;
	
	public RemovePersistentRequest(SimpleFieldSet fs) throws MessageInvalidException {
		this.global = fs.getBoolean("Global", false);
		this.identifier = fs.get("Identifier");
		if(identifier == null)
			throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must have Identifier", null, global);
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
		ClientRequest req = handler.removePersistentRebootRequest(global, identifier);
		if(req == null && !global) {
			req = handler.removeRequestByIdentifier(identifier, true);
		}
		if(req == null) {
		    try {
                handler.getServer().getCore().getClientContext().jobRunner.queue(new PersistentJob() {
                    
                    @Override
                    public boolean run(ClientContext context) {
                        try {
                            ClientRequest req = handler.removePersistentForeverRequest(global, identifier);
                            if(req == null) {
                                Logger.error(this, "Huh ? the request is null!");
                                return false;
                            }
                            return true;
                        } catch (MessageInvalidException e) {
                            FCPMessage err = new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global);
                            handler.send(err);
                            return false;
                        }
                    }
                    
                }, NativeThread.PriorityLevel.HIGH_PRIORITY.value);
            } catch (PersistenceDisabledException e) {
                FCPMessage err = new ProtocolErrorMessage(ProtocolErrorMessage.PERSISTENCE_DISABLED, false, "Persistence disabled and non-persistent request not found", identifier, global);
                handler.send(err);
            }
		}
	}

}
