package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;

import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;

public class TextFeedMessage extends N2NFeedMessage {

	public static final String NAME = "TextFeed";

	public TextFeedMessage(String header, String shortText, String text, short priorityClass, long updatedTime,
			String sourceNodeName, long composed, long sent, long received,
			String messageText) {
		super(header, shortText, text, priorityClass, updatedTime, sourceNodeName, composed, sent, received);
		final Bucket messageTextBucket;
		if (messageText != null) {
			messageTextBucket = new ArrayBucket(messageText.getBytes(StandardCharsets.UTF_8));
		} else {
			messageTextBucket = new NullBucket();
		}
		buckets.put("MessageText", messageTextBucket);
	}

	@Override
	public String getName() {
		return NAME;
	}

}
