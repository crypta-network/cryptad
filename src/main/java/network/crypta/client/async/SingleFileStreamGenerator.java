package network.crypta.client.async;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Writes a <code>Bucket</code> to an output stream. */
public class SingleFileStreamGenerator implements StreamGenerator {
  private static final Logger LOG = LoggerFactory.getLogger(SingleFileStreamGenerator.class);

  private final Bucket bucket;

  static {
  }

  SingleFileStreamGenerator(Bucket bucket, boolean persistent) {
    this.bucket = bucket;
  }

  @Override
  public void writeTo(OutputStream os, ClientContext context) throws IOException {
    try (OutputStream managedOs = os;
        AutoCloseable managedBucket = bucket) {
      if (LOG.isDebugEnabled()) LOG.debug("Generating Stream");
      try (InputStream data = bucket.getInputStream()) {
        FileUtil.copy(data, managedOs, -1);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Stream completely generated");
    } catch (Exception e) {
      if (e instanceof IOException exception) {
        throw exception;
      } else {
        throw new IOException("Error during stream generation", e);
      }
    }
  }

  @Override
  public long size() {
    return bucket.size();
  }
}
