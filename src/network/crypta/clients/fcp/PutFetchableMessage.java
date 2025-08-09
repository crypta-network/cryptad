/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

public class PutFetchableMessage extends FCPMessage {

	PutFetchableMessage(String ident, boolean global, FreenetURI uri) {
		this.identifier = ident;
		this.global = global;
		this.uri = uri;
	}
	
	final String identifier;
	final boolean global;
	final FreenetURI uri;
	
	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		fs.put("Global", global);
		if(uri != null)
			fs.putSingle("URI", uri.toString(false, false));
		return fs;
	}

	@Override
	public String getName() {
		return "PutFetchable";
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "PutFetchable goes from server to client not the other way around", identifier, global);
	}

}
