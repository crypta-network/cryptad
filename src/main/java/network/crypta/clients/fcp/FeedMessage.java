package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;

public class FeedMessage extends MultipleDataCarryingMessage {

  public static final String NAME = "Feed";
  // We assume that the header and shortText doesn't contain any newlines
  private final String header;
  private final String shortText;

  private final short priorityClass;
  private final long updatedTime;

  public FeedMessage(
      String header, String shortText, String text, short priorityClass, long updatedTime) {
    this.header = header;
    this.shortText = shortText;
    this.priorityClass = priorityClass;
    this.updatedTime = updatedTime;

    // The text may contain newlines
    Bucket textBucket = new ArrayBucket(text.getBytes(StandardCharsets.UTF_8));
    buckets.put("Text", textBucket);
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("Header", header);
    fs.putSingle("ShortText", shortText);
    fs.put("PriorityClass", priorityClass);
    fs.put("UpdatedTime", updatedTime);
    return fs;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        getName() + " goes from server to client not the other way around",
        null,
        false);
  }

  @Override
  public String getName() {
    return NAME;
  }
}
