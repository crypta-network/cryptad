package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.api.BucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseDataCarryingMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(BaseDataCarryingMessage.class);

  abstract long dataLength();

  public abstract void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException;

  @Override
  public void send(OutputStream os) throws IOException {
    super.send(os);
    writeData(os);
  }

  protected abstract void writeData(OutputStream os) throws IOException;
}
