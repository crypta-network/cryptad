package network.crypta.support.io;

import java.io.*;
import java.util.Arrays;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;

/**
 * A bucket that stores data in the memory.
 *
 * <p>FIXME: No synchronization, should there be?
 *
 * @author oskar
 */
public class ArrayBucket implements Bucket, Serializable, RandomAccessBucket {
  @Serial private static final long serialVersionUID = 1L;
  private volatile byte[] data;
  private final String name;
  private boolean readOnly;
  private boolean freed;

  public ArrayBucket() {
    this("ArrayBucket");
  }

  public ArrayBucket(byte[] initdata) {
    this("ArrayBucket");
    data = initdata;
  }

  public ArrayBucket(String name) {
    data = new byte[0];
    this.name = name;
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    if (readOnly) throw new IOException("Read only");
    if (freed) throw new IOException("Already freed");
    return new ArrayBucketOutputStream();
  }

  @Override
  public InputStream getInputStream() throws IOException {
    if (freed) throw new IOException("Already freed");
    return new ByteArrayInputStream(data);
  }

  @Override
  public String toString() {
    return new String(data);
  }

  @Override
  public long size() {
    return data.length;
  }

  @Override
  public String getName() {
    return name;
  }

  private class ArrayBucketOutputStream extends ByteArrayOutputStream {
    private boolean hasBeenClosed = false;

    public ArrayBucketOutputStream() {
      super();
    }

    @Override
    public synchronized void close() throws IOException {
      if (hasBeenClosed) return;
      data = super.toByteArray();
      if (readOnly) throw new IOException("Read only");
      // FIXME maybe we should throw on write instead? :)
      hasBeenClosed = true;
    }
  }

  @Override
  public boolean isReadOnly() {
    return readOnly;
  }

  @Override
  public void setReadOnly() {
    readOnly = true;
  }

  @Override
  public void free() {
    freed = true;
    data = null;
    // Not much else we can do.
  }

  public byte[] toByteArray() throws IOException {
    if (freed) throw new IOException("Already freed");
    long sz = size();
    int size = (int) sz;
    return Arrays.copyOf(data, size);
  }

  @Override
  public RandomAccessBucket createShadow() {
    return null;
  }

  @Override
  public void onResume(ClientContext context) {
    // Do nothing.
  }

  @Override
  public void storeTo(DataOutputStream dos) {
    // Should not be used for persistent requests.
    throw new UnsupportedOperationException();
  }

  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() {
    readOnly = true;
    return new ByteArrayRandomAccessBuffer(data, 0, data.length, true);
  }

  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return getInputStream();
  }

  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    return getOutputStream();
  }
}
