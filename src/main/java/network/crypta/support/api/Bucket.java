package network.crypta.support.api;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.io.ResumeFailedException;

/**
 * A bucket is any arbitrary object can temporarily store data. In other words, it is the equivalent
 * of a temporary file, but it could be in RAM, on disk, encrypted, part of a file on disk, composed
 * from a chain of other buckets etc.
 *
 * <p>Not all buckets are Serializable.
 *
 * @author oskar
 */
public interface Bucket extends AutoCloseable {

  /**
   * Returns an OutputStream that is used to put data in this Bucket, from the beginning. It is not
   * possible to append data to a Bucket! This simplifies the code significantly for some classes.
   * If you need to append, just pass the OutputStream around. Will be buffered if appropriate (e.g.
   * byte array backed buckets don't need to be buffered).
   */
  OutputStream getOutputStream() throws IOException;

  /**
   * Get an OutputStream which is not buffered. Should be called when we will buffer the stream at a
   * higher level or when we will only be doing large writes (e.g. copying data from one Bucket to
   * another). Does not make any more persistence guarantees than getOutputStream() does, this is
   * just to save memory.
   */
  OutputStream getOutputStreamUnbuffered() throws IOException;

  /**
   * Returns an InputStream that reads data from this Bucket. If there is no data in this bucket,
   * null is returned.
   *
   * <p>You have to call IOUtils.closeQuietly(inputStream) on the obtained stream to prevent
   * resource leakage.
   */
  InputStream getInputStream() throws IOException;

  InputStream getInputStreamUnbuffered() throws IOException;

  /**
   * Returns a name for the bucket, may be used to identify them in certain in certain situations.
   */
  String getName();

  /** Returns the amount of data currently in this bucket in bytes. */
  long size();

  /** Is the bucket read-only? */
  boolean isReadOnly();

  /** Make the bucket read-only. Irreversible. */
  void setReadOnly();

  /**
   * Free the bucket, if supported. Note that you must call free() even if you haven't used the
   * Bucket (haven't called getOutputStream()) for some kinds of Bucket's, as they may have
   * allocated space (e.g. created a temporary file).
   */
  void free();

  /**
   * AutoCloseable implementation that delegates to free(). This allows Bucket to be used with
   * try-with-resources.
   */
  @Override
  default void close() {
    free();
  }

  /**
   * Create a shallow read-only copy of this bucket, using different objects but using the same
   * external storage. If this is not possible, return null. Note that if the underlying bucket is
   * deleted, the copy will become invalid and probably throw an IOException on read, or possibly
   * return too-short data etc. In some use cases e.g. on fproxy, this is acceptable.
   */
  Bucket createShadow();

  /**
   * Called after restarting. The Bucket should do any necessary housekeeping after resuming, e.g.
   * registering itself with the appropriate persistent bucket tracker to avoid being
   * garbage-collected. May be called twice, so the Bucket may need to track this internally.
   *
   * @param context All the necessary runtime support will be on this object.
   * @throws ResumeFailedException
   */
  void onResume(ClientContext context) throws ResumeFailedException;

  /**
   * Write enough data to reconstruct the Bucket, or throw UnsupportedOperationException. Used for
   * recovering in emergencies, should be versioned if necessary.
   *
   * @throws IOException
   */
  void storeTo(DataOutputStream dos) throws IOException;
}
