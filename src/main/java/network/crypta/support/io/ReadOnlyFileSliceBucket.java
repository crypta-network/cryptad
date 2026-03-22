package network.crypta.support.io;

import java.io.*;

import network.crypta.support.api.Bucket;
import network.crypta.support.api.ResumeContext;
import org.jetbrains.annotations.NotNull;

/**
 * Read-only {@link Bucket} view over a contiguous slice of a file.
 *
 * <p>This bucket exposes an input-only stream interface over a fixed region of an underlying {@link
 * File}. It does not own the file, holds no open descriptors until a stream is created, and never
 * allows writing. Instances are lightweight; resource lifetime is bound to the returned {@link
 * InputStream}s, which must be closed by callers.
 *
 * <p>Format persistence is supported via {@link #storeTo(DataOutputStream)} and a protected
 * constructor that reads from a {@link DataInputStream}. The persistence scheme uses a class {@code
 * MAGIC} and {@code VERSION}. The writer emits both, while the protected constructor expects the
 * caller to have consumed any outer framing and begins at {@code VERSION}.
 *
 * <p>This class does not verify content hashes; callers should wrap it if integrity checks are
 * required.
 */
public final class ReadOnlyFileSliceBucket implements Bucket, Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private final File file;
  private final long startAt;
  private final long length;

  /**
   * Construct a read-only view over a slice of {@code f}.
   *
   * @param f backing file; must exist and be at least {@code startAt + length} bytes long when an
   *     input stream is created.
   * @param startAt byte offset in {@code f} where the slice begins; must be {@code >= 0}.
   * @param length number of bytes in the slice; must be {@code >= 0}. A length of zero yields an
   *     empty bucket.
   */
  public ReadOnlyFileSliceBucket(File f, long startAt, long length) {
    // Re-wrap the incoming File by path to decouple from the caller's File instance.
    this.file = new File(f.getPath());
    this.startAt = startAt;
    this.length = length;
  }

  /**
   * Always fails because this bucket is read-only.
   *
   * @return never returns normally.
   * @throws IOException always thrown with message {@code "Bucket is read-only"}.
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Bucket is read-only");
  }

  /**
   * Always fails because this bucket is read-only.
   *
   * @return never returns normally.
   * @throws IOException always thrown with message {@code "Bucket is read-only"}.
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    throw new IOException("Bucket is read-only");
  }

  /**
   * Return a buffered input stream over the slice.
   *
   * <p>The returned stream reads exactly {@code length} bytes starting at {@code startAt}. If the
   * underlying file is shorter than required at stream creation time, a {@link
   * ReadOnlyFileSliceBucketException} is thrown.
   *
   * @return buffered {@link InputStream} positioned at the start of the slice.
   * @throws IOException if the stream cannot be created.
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  /**
   * Return an unbuffered input stream over the slice.
   *
   * <p>The returned stream reads at most {@code length} bytes starting at {@code startAt}. It
   * validates the file length before returning.
   *
   * @return unbuffered {@link InputStream} positioned at the start of the slice.
   * @throws ReadOnlyFileSliceBucketException if the file does not exist or the slice exceeds the
   *     file length.
   * @throws IOException on other I/O errors.
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return new MyInputStream();
  }

  /**
   * Return a stable, human-readable identifier for the bucket.
   *
   * <p>Format: {@code ROFS:<absolutePath>:<startAt>:<length>}.
   *
   * @return identifier string describing the backing file and slice.
   */
  @Override
  public String getName() {
    return "ROFS:" + file.getAbsolutePath() + ':' + startAt + ':' + length;
  }

  /**
   * Return the number of readable bytes in this bucket.
   *
   * @return slice length in bytes.
   */
  @Override
  public long size() {
    return length;
  }

  /**
   * Indicate that this bucket is read-only.
   *
   * @return always {@code true}.
   */
  @Override
  public boolean isReadOnly() {
    return true;
  }

  /** No-op. This bucket is already read-only by design. */
  @Override
  public void setReadOnly() {
    // Intentional no-op.
  }

  private static IOException closeOnInputStreamInitFailure(
      RandomAccessFile randomAccessFile, IOException failure) {
    try {
      randomAccessFile.close();
    } catch (IOException closeFailure) {
      failure.addSuppressed(closeFailure);
    }
    return failure;
  }

  private final class MyInputStream extends InputStream {

    private final RandomAccessFile f;
    // Current read position relative to {@code startAt} within the slice.
    private long ptr;

    /**
     * Open the underlying file for reading and position at {@code startAt}.
     *
     * <p>Performs a length check to ensure the full slice fits within the file.
     *
     * @throws ReadOnlyFileSliceBucketException if the file is missing or too short.
     * @throws IOException on other I/O errors.
     */
    MyInputStream() throws IOException {
      RandomAccessFile randomAccessFile;
      try {
        randomAccessFile = new RandomAccessFile(file, "r");
      } catch (FileNotFoundException e) {
        throw new ReadOnlyFileSliceBucketException(e);
      }
      try {
        randomAccessFile.seek(startAt);
        long fileLength = randomAccessFile.length();
        if (fileLength < (startAt + length))
          throw new ReadOnlyFileSliceBucketException(
              "File truncated? Length "
                  + fileLength
                  + " but start at "
                  + startAt
                  + " for "
                  + length
                  + " bytes");
      } catch (IOException e) {
        throw closeOnInputStreamInitFailure(randomAccessFile, e);
      }
      this.f = randomAccessFile;
      ptr = 0;
    }

    /** Read a single byte from the slice or {@code -1} at end of slice. */
    @Override
    public int read() throws IOException {
      if (ptr >= length) return -1;
      int x = f.read();
      if (x != -1) ptr++;
      return x;
    }

    /**
     * Read up to {@code len} bytes, clamped so the read does not pass the end of the slice.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read(byte @NotNull [] buf, int offset, int len) throws IOException {
      if (ptr >= length) return -1;
      len = (int) Math.min(len, length - ptr);
      int x = f.read(buf, offset, len);
      ptr += x;
      return x;
    }

    /** Convenience overload that reads into the entire buffer. */
    @Override
    public int read(byte @NotNull [] buf) throws IOException {
      return read(buf, 0, buf.length);
    }

    /** Close the underlying {@link RandomAccessFile}. */
    @Override
    public void close() throws IOException {
      f.close();
    }
  }

  /**
   * Exception indicating the slice cannot be read from the backing file.
   *
   * <p>Used to wrap common failures at stream construction time, such as missing files or truncated
   * backing data.
   */
  public static class ReadOnlyFileSliceBucketException extends IOException {

    @Serial private static final long serialVersionUID = -1;

    /**
     * Construct with the missing-file cause and a human-readable message.
     *
     * @param e original {@link FileNotFoundException}.
     */
    public ReadOnlyFileSliceBucketException(FileNotFoundException e) {
      super("File not found: " + e.getMessage());
      initCause(e);
    }

    /**
     * Construct with a descriptive message.
     *
     * @param string detail message.
     */
    public ReadOnlyFileSliceBucketException(String string) {
      super(string);
    }
  }

  /**
   * Free resources associated with this bucket.
   *
   * <p>This implementation is a no-op because the bucket does not hold open resources; the lifetime
   * of file descriptors is scoped to streams returned by this instance.
   */
  @Override
  public void free() {
    // No-op by design.
  }

  /**
   * Create a shallow read-only copy that references the same file slice.
   *
   * <p>The returned bucket is independent as an object, but both instances read from the same
   * underlying file region.
   *
   * @return a new read-only bucket over the same slice.
   */
  @Override
  public Bucket createShadow() {
    String fnam = file.getPath();
    File newFile = new File(fnam);
    return new ReadOnlyFileSliceBucket(newFile, startAt, length);
  }

  /**
   * Lifecycle callback invoked after restoring from persistence.
   *
   * <p>No action is required for this bucket type.
   *
   * @param context runtime context (unused).
   */
  @Override
  public void onResume(ResumeContext context) {
    // Intentional no-op.
  }

  // Serialization constants for {@link #storeTo(DataOutputStream)} persistence format.
  static final int MAGIC = 0x99e54c4;
  static final int VERSION = 1;

  /**
   * Write enough information to reconstruct this bucket later.
   *
   * <p>Emits, in order: {@code MAGIC} (int), {@code VERSION} (int), file path (UTF), {@code
   * startAt} (long), and {@code length} (long).
   *
   * <p>Note: The protected constructor below begins by reading {@code VERSION}. The caller is
   * responsible for consuming any outer framing (e.g., {@code MAGIC}) before invoking it.
   *
   * @param dos target stream; not closed by this method.
   * @throws IOException if writing fails.
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeUTF(file.toString());
    dos.writeLong(startAt);
    dos.writeLong(length);
  }

  /**
   * Reconstruct an instance from a data stream written by {@link #storeTo(DataOutputStream)} or an
   * equivalent serializer.
   *
   * <p>Reads the following fields, in order: {@code VERSION} (int), file path (UTF), {@code
   * startAt} (long), and {@code length} (long). Validates non-negativity and that the slice fits in
   * the current file.
   *
   * <p>Note: The {@code MAGIC} prefix (if present) must be consumed by the caller before invoking
   * this constructor.
   *
   * @param dis source stream positioned at the version field; not closed by this constructor.
   * @throws StorageFormatException if the version is unexpected, fields are invalid, the file does
   *     not exist, or the slice exceeds file length.
   * @throws IOException on I/O errors while reading.
   */
  ReadOnlyFileSliceBucket(DataInputStream dis) throws StorageFormatException, IOException {
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
