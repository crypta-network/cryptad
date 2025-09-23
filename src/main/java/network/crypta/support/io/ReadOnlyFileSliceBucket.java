package network.crypta.support.io;

import java.io.*;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;

/** FIXME: implement a hash verifying version of this. */
public class ReadOnlyFileSliceBucket implements Bucket, Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private final File file;
  private final long startAt;
  private final long length;

  public ReadOnlyFileSliceBucket(File f, long startAt, long length) {
    this.file = new File(f.getPath()); // copy so we can delete it
    this.startAt = startAt;
    this.length = length;
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Bucket is read-only");
  }

  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    throw new IOException("Bucket is read-only");
  }

  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return new MyInputStream();
  }

  @Override
  public String getName() {
    return "ROFS:" + file.getAbsolutePath() + ':' + startAt + ':' + length;
  }

  @Override
  public long size() {
    return length;
  }

  @Override
  public boolean isReadOnly() {
    return true;
  }

  @Override
  public void setReadOnly() {
    // Do nothing
  }

  private class MyInputStream extends InputStream {

    private final RandomAccessFile f;
    private long ptr; // relative to startAt

    MyInputStream() throws IOException {
      try {
        this.f = new RandomAccessFile(file, "r");
        f.seek(startAt);
        if (f.length() < (startAt + length))
          throw new ReadOnlyFileSliceBucketException(
              "File truncated? Length "
                  + f.length()
                  + " but start at "
                  + startAt
                  + " for "
                  + length
                  + " bytes");
        ptr = 0;
      } catch (FileNotFoundException e) {
        throw new ReadOnlyFileSliceBucketException(e);
      }
    }

    @Override
    public int read() throws IOException {
      if (ptr >= length) return -1;
      int x = f.read();
      if (x != -1) ptr++;
      return x;
    }

    @Override
    public int read(byte[] buf, int offset, int len) throws IOException {
      if (ptr >= length) return -1;
      len = (int) Math.min(len, length - ptr);
      int x = f.read(buf, offset, len);
      ptr += x;
      return x;
    }

    @Override
    public int read(byte[] buf) throws IOException {
      return read(buf, 0, buf.length);
    }

    @Override
    public void close() throws IOException {
      f.close();
    }
  }

  public static class ReadOnlyFileSliceBucketException extends IOException {

    @Serial private static final long serialVersionUID = -1;

    public ReadOnlyFileSliceBucketException(FileNotFoundException e) {
      super("File not found: " + e.getMessage());
      initCause(e);
    }

    public ReadOnlyFileSliceBucketException(String string) {
      super(string);
    }
  }

  @Override
  public void free() {}

  @Override
  public Bucket createShadow() {
    String fnam = file.getPath();
    File newFile = new File(fnam);
    return new ReadOnlyFileSliceBucket(newFile, startAt, length);
  }

  @Override
  public void onResume(ClientContext context) {
    // Do nothing.
  }

  static final int MAGIC = 0x99e54c4;
  static final int VERSION = 1;

  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeUTF(file.toString());
    dos.writeLong(startAt);
    dos.writeLong(length);
  }

  protected ReadOnlyFileSliceBucket(DataInputStream dis)
      throws StorageFormatException, IOException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    file = new File(dis.readUTF());
    startAt = dis.readLong();
    if (startAt < 0) throw new StorageFormatException("Bad start at");
    length = dis.readLong();
    if (length < 0) throw new StorageFormatException("Bad length");
    if (!file.exists()) throw new StorageFormatException("File does not exist any more");
    if (file.length() < startAt + length)
      throw new StorageFormatException("Slice does not fit in file");
  }
}
