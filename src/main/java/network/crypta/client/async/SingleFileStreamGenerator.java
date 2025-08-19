package network.crypta.client.async;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileUtil;

/** Writes a <code>Bucket</code> to an output stream. */
public class SingleFileStreamGenerator implements StreamGenerator {

  private final Bucket bucket;

  private static volatile boolean logMINOR;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
          }
        });
  }

  SingleFileStreamGenerator(Bucket bucket, boolean persistent) {
    this.bucket = bucket;
  }

  @Override
  public void writeTo(OutputStream os, ClientContext context) throws IOException {
    try (OutputStream managedOs = os;
        AutoCloseable managedBucket = bucket) {
      if (logMINOR) Logger.minor(this, "Generating Stream", new Exception("debug"));
      try (InputStream data = bucket.getInputStream()) {
        FileUtil.copy(data, managedOs, -1);
      }
      if (logMINOR) Logger.minor(this, "Stream completely generated", new Exception("debug"));
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
