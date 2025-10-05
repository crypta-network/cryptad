package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TextFeedMessage extends N2NFeedMessage {
  private static final Logger LOG = LoggerFactory.getLogger(TextFeedMessage.class);

  public static final String NAME = "TextFeed";

  public TextFeedMessage(
      String header,
      String shortText,
      String text,
      short priorityClass,
      long updatedTime,
      String sourceNodeName,
      long composed,
      long sent,
      long received,
      String messageText) {
    super(
        header,
        shortText,
        text,
        priorityClass,
        updatedTime,
        sourceNodeName,
        composed,
        sent,
        received);
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
