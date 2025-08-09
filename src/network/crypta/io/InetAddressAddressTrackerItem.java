package network.crypta.io;

import java.net.InetAddress;
import java.net.UnknownHostException;

import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;

public class InetAddressAddressTrackerItem extends AddressTrackerItem {

	public InetAddressAddressTrackerItem(long timeDefinitelyNoPacketsReceived, 
			long timeDefinitelyNoPacketsSent, InetAddress addr) {
		super(timeDefinitelyNoPacketsReceived, timeDefinitelyNoPacketsSent);
		this.addr = addr;
	}

	public final InetAddress addr;
	
	@Override
	public SimpleFieldSet toFieldSet() {
		SimpleFieldSet fs = super.toFieldSet();
		fs.putOverwrite("Address", addr.getHostAddress());
		return fs;
	}
	
	public InetAddressAddressTrackerItem(SimpleFieldSet fs) throws FSParseException {
		super(fs);
		try {
			addr = InetAddress.getByName(fs.getString("Address"));
		} catch (UnknownHostException e) {
			throw (FSParseException)new FSParseException("Unknown domain name in Address: "+e).initCause(e);
		}
	}

}
