package network.crypta.io;

import java.net.UnknownHostException;

import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;

public class PeerAddressTrackerItem extends AddressTrackerItem {
	
	public final Peer peer;

	public PeerAddressTrackerItem(long timeDefinitelyNoPacketsReceived, 
			long timeDefinitelyNoPacketsSent, Peer peer) {
		super(timeDefinitelyNoPacketsReceived, timeDefinitelyNoPacketsSent);
		this.peer = peer;
	}
	
	public PeerAddressTrackerItem(SimpleFieldSet fs) throws FSParseException {
		super(fs);
		try {
			peer = new Peer(fs.getString("Address"), false);
		} catch (UnknownHostException e) {
			throw (FSParseException)new FSParseException("Unknown domain name in Address: "+e).initCause(e);
		} catch (PeerParseException e) {
			throw new FSParseException(e);
		}
	}

	@Override
	public SimpleFieldSet toFieldSet() {
		SimpleFieldSet fs = super.toFieldSet();
		fs.putOverwrite("Address", peer.toStringPrefNumeric());
		return fs;
	}

}
