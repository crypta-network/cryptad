package network.crypta.support.io;

import java.io.*;
import java.lang.ref.Cleaner;
import java.util.ArrayList;
import network.crypta.client.async.ClientContext;
import network.crypta.support.ListUtils;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.api.Bucket;

/**
 * A wrapper for a read-only bucket providing for multiple readers. The data is only freed when all
 * of the readers have freed it.
 *
 * @author toad
 */
public class MultiReaderBucket implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  // Cleaner for safety net resource cleanup
  private static final Cleaner cleaner = Cleaner.create();

  // Static nested class for cleaner action to avoid holding reference to the ReaderBucket instance
  private static class ReaderBucketCleanup implements Runnable {
    private final MultiReaderBucket parent;

    ReaderBucketCleanup(MultiReaderBucket parent) {
      this.parent = parent;
    }

    @Override
    public void run() {
      // Safety net cleanup - this should rarely be called if free() is used properly
      synchronized (parent) {
        if (parent.readers != null && !parent.readers.isEmpty()) {
          parent.readers.clear();
          parent.readers = null;
        }
        if (!parent.closed) {
          parent.closed = true;
        }
      }
      if (parent.bucket != null) {
        parent.bucket.free();
      }
    }
  }

  private final Bucket bucket;

  // Assume there will be relatively few readers
  private ArrayList<Bucket> readers;

  private boolean closed;
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

  public MultiReaderBucket(Bucket underlying) {
    bucket = underlying;
  }

  protected MultiReaderBucket() {
    // For serialization.
    bucket = null;
  }

  /** Get a reader bucket */
  public Bucket getReaderBucket() {
    synchronized (this) {
      if (closed) return null;
      Bucket d = new ReaderBucket();
      if (readers == null) readers = new ArrayList<>(1);
      readers.add(d);
      if (logMINOR)
        Logger.minor(this, "getReaderBucket() returning " + d + " for " + this + " for " + bucket);
      return d;
    }
  }

  class ReaderBucket implements Bucket, Serializable {

    @Serial private static final long serialVersionUID = 1L;
    private boolean freed;

    // Cleaner for safety net resource cleanup
    private final Cleaner.Cleanable cleanable;

    ReaderBucket() {
      // Register cleaner for safety net (will be cleaned up when free() is called properly)
      this.cleanable = cleaner.register(this, new ReaderBucketCleanup(MultiReaderBucket.this));
    }

    @Override
    public void free() {
      if (logMINOR)
        Logger.minor(
            this,
            "ReaderBucket " + this + " for " + MultiReaderBucket.this + " free()ing for " + bucket);
      synchronized (MultiReaderBucket.this) {
        if (freed) return;
        freed = true;
        // Check if readers is null before trying to remove from it
        if (readers != null) {
          ListUtils.removeBySwapLast(readers, this);
          if (!readers.isEmpty()) {
            // Clean up the cleaner since we've properly freed this reader
            if (cleanable != null) {
              cleanable.clean();
            }
            return;
          }
          readers = null;
        }
        if (closed) {
          // Clean up the cleaner since we've properly freed this reader
          if (cleanable != null) {
            cleanable.clean();
          }
          return;
        }
        closed = true;
      }
      bucket.free();

      // Clean up the cleaner since we've properly freed this reader
      if (cleanable != null) {
        cleanable.clean();
      }
    }

    @Override
    public InputStream getInputStream() throws IOException {
      synchronized (MultiReaderBucket.this) {
        if (freed || closed) {
          throw new IOException("Already freed");
        }
        return new ReaderBucketInputStream(true);
      }
    }

    @Override
    public InputStream getInputStreamUnbuffered() throws IOException {
      synchronized (MultiReaderBucket.this) {
        if (freed || closed) {
          throw new IOException("Already freed");
        }
        return new ReaderBucketInputStream(false);
      }
    }

    private class ReaderBucketInputStream extends InputStream {

      InputStream is;

      ReaderBucketInputStream(boolean buffer) throws IOException {
        is = buffer ? bucket.getInputStream() : bucket.getInputStreamUnbuffered();
      }

      @Override
      public final int read() throws IOException {
        synchronized (MultiReaderBucket.this) {
          if (freed || closed) throw new IOException("Already closed");
        }
        return is.read();
      }

      @Override
      public final int read(byte[] data, int offset, int length) throws IOException {
        synchronized (MultiReaderBucket.this) {
          if (freed || closed) throw new IOException("Already closed");
        }
        return is.read(data, offset, length);
      }

      @Override
      public final int read(byte[] data) throws IOException {
        synchronized (MultiReaderBucket.this) {
          if (freed || closed) throw new IOException("Already closed");
        }
        return is.read(data);
      }

      @Override
      public final void close() throws IOException {
        is.close();
      }

      @Override
      public final int available() throws IOException {
        return is.available();
      }
    }

    @Override
    public String getName() {
      return bucket.getName();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      throw new IOException("Read only");
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
      throw new IOException("Read only");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }

    @Override
    public void setReadOnly() {
      // Already read only
    }

    @Override
    public long size() {
      return bucket.size();
    }

    @Override
    public Bucket createShadow() {
      return null;
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      throw new UnsupportedOperationException(); // Not persistent.
    }

    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
      throw new UnsupportedOperationException();
    }
  }
}
