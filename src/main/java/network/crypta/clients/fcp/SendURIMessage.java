package network.crypta.clients.fcp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;

import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.BucketTools;

public class SendURIMessage extends SendPeerMessage {

	public final static String NAME = "SendURI";
	private final FreenetURI uri;

	public SendURIMessage(SimpleFieldSet fs) throws MessageInvalidException {
		super(fs);
		try {
			uri = new FreenetURI(fs.get("URI"));
		} catch (MalformedURLException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(),
					identifier, false);
		}
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = super.getFieldSet();
		fs.putSingle("URI", uri.toString());
		return fs;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	protected int handleFeed(DarknetPeerNode pn) throws MessageInvalidException {
		try {
			if(dataLength() > 0) {
				byte[] description = BucketTools.toByteArray(bucket);
				return pn.sendDownloadFeed(uri, new String(description, StandardCharsets.UTF_8));
			}
			else
				return pn.sendDownloadFeed(uri, null);
		} catch (IOException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "", null, false);
		}
	}
}