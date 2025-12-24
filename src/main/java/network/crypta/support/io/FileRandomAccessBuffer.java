package network.crypta.support.io;

import java.io.*;
import java.nio.file.Files;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * File-backed {@link LockableRandomAccessBuffer} using a {@link RandomAccessFile}.
 *
 * <p>This implementation provides fixed-size, random read/write access to a file. The logical size
 * is determined at construction and enforced by bounds checks in {@link #pread(long, byte[], int,
 * int)} and {@link #pwrite(long, byte[], int, int)}. Instances may be created in read-only or
 * read/write mode. When {@link #free()} is called, the underlying file is deleted; optional secure
 * deletion can be enabled via {@link #setSecureDelete(boolean)}.
 *
 * <p><strong>Threading:</strong> Operations synchronize on {@code this} to serialize access to the
 * shared {@link RandomAccessFile} position. As a result, calls are safe from concurrent races but
 * do not permit true parallel I/O. The {@link #lockOpen()} method returns a no-op lock because the
 * backing file remains open for the lifetime of this object.
 *
 * <p><strong>Persistence:</strong> Minimal metadata required to re-open the buffer is written by
 * {@link #storeTo(DataOutputStream)} and consumed by the {@linkplain
 * #FileRandomAccessBuffer(DataInputStream) restoring constructor}. The persisted data includes the
 * file path, mode, length, and secure-deletion flag.
 */
public class FileRandomAccessBuffer implements LockableRandomAccessBuffer, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(FileRandomAccessBuffer.class);

  @Serial private static final long serialVersionUID = 1L;
  transient RandomAccessFile raf;
  final File file;
  private boolean closed = false;
  private final long length;
  private final boolean readOnly;
  private boolean secureDelete;

  /**
   * Creates a buffer over an existing {@link RandomAccessFile}.
   *
   * <p>The buffer adopts the given file handle and will {@link #close()} it. The logical size is
   * set to the current file length and is not permitted to grow.
   *
   * @param raf the file handle to adopt; must not be {@code null}
   * @param filename the file on disk that backs {@code raf}; used for deletion and resume
   * @param readOnly whether this buffer is read-only; affects future write operations and how the
   *     file is re-opened during resume
   * @throws IOException if obtaining the current length fails
   */
  public FileRandomAccessBuffer(RandomAccessFile raf, File filename, boolean readOnly)
      throws IOException {
    this.raf = raf;
    this.file = filename;
    length = raf.length();
    this.readOnly = readOnly;
  }

  /**
   * Creates or truncates/extends a file to the requested length and opens a buffer on it.
   *
   * <p>The file is opened in mode {@code "rw"} when {@code readOnly} is {@code false}, otherwise in
   * mode {@code "r"}. The file is then set to the given {@code length}. If the file cannot be
   * written when a resize is required, an {@link IOException} is thrown.
   *
   * @param filename the file to back the buffer
   * @param length the fixed logical size in bytes
   * @param readOnly whether to open {@code filename} read-only
   * @throws IOException if the file cannot be opened or resized to {@code length}
   */
  public FileRandomAccessBuffer(File filename, long length, boolean readOnly) throws IOException {
    raf = new RandomAccessFile(filename, readOnly ? "r" : "rw");
    raf.setLength(length);
    this.length = length;
    this.file = filename;
    this.readOnly = readOnly;
  }

  /**
   * Opens a buffer on an existing file using its current length.
   *
   * @param filename the file to back the buffer
   * @param readOnly whether to open read-only ({@code "r"}) or read/write ({@code "rw"})
   * @throws IOException if the file cannot be opened or its length cannot be obtained
   */
  public FileRandomAccessBuffer(File filename, boolean readOnly) throws IOException {
    raf = new RandomAccessFile(filename, readOnly ? "r" : "rw");
    this.length = raf.length();
    this.file = filename;
    this.readOnly = readOnly;
  }

  /**
   * Reads bytes from the given file offset into the provided buffer.
   *
   * <p>This method does not perform partial reads; it blocks until {@code length} bytes have been
   * copied or an error occurs. Access is serialized across threads.
   *
   * @param fileOffset starting position in the file (bytes), must be {@code >= 0}
   * @param buf destination array
   * @param bufOffset offset in {@code buf} at which to start writing
   * @param length number of bytes to read
   * @throws IllegalArgumentException if {@code fileOffset < 0}
   * @throws IOException if the read would exceed the logical size, or an I/O error occurs, or EOF
   *     is reached before reading {@code length} bytes
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if (fileOffset < 0) throw new IllegalArgumentException();
    if (fileOffset + length > this.length)
      throw new IOException(
          "Length limit exceeded reading "
              + length
              + " bytes from "
              + fileOffset
              + " of "
              + this.length);
    // Serialize access through this instance; RAF itself is not position-safe for concurrency.
    synchronized (this) {
      raf.seek(fileOffset);
      raf.readFully(buf, bufOffset, length);
    }
  }

  /**
   * Writes bytes from the provided buffer to the file at the given offset.
   *
   * <p>Access is serialized across threads. Writes beyond the fixed logical size are rejected.
   *
   * @param fileOffset starting position in the file (bytes), must be {@code >= 0}
   * @param buf source array
   * @param bufOffset offset in {@code buf} at which to start reading
   * @param length number of bytes to write
   * @throws IllegalArgumentException if {@code fileOffset < 0}
   * @throws IOException if the writing would exceed the logical size, if the buffer is read-only,
   *     or if an I/O error occurs
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if (fileOffset < 0) throw new IllegalArgumentException();
    if (fileOffset + length > this.length)
      throw new IOException(
          "Length limit exceeded writing "
              + length
              + " bytes from "
              + fileOffset
              + " of "
              + this.length);
    if (readOnly) throw new IOException("Read only");
    // Serialize access through this instance; RAF writes also move the shared file pointer.
    synchronized (this) {
      raf.seek(fileOffset);
      raf.write(buf, bufOffset, length);
    }
  }

  /**
   * Returns the fixed logical size of this buffer in bytes.
   *
   * @return size in bytes (never negative)
   */
  @Override
  public long size() {
    return length;
  }

  /**
   * Closes the underlying {@link RandomAccessFile}.
   *
   * <p>The operation is idempotent. This method does not delete the backing file; use {@link
   * #free()} to close and delete.
   */
  @Override
  public void close() {
    synchronized (this) {
      if (closed) return;
      closed = true;
    }
    try {
      raf.close();
    } catch (IOException e) {
      LOG.error("Could not close {} : {} for {}", raf, e, this, e);
    }
  }

  /**
   * Returns a lock object representing an open handle to the buffer.
   *
   * <p>The returned lock performs no additional action on unlock because this implementation keeps
   * the file open for the lifetime of the buffer. The lock exists to satisfy the {@link
   * LockableRandomAccessBuffer} contract.
   *
   * @return a no-op lock
   */
  @Override
  public RAFLock lockOpen() {
    return new RAFLock() {

      @Override
      protected void innerUnlock() {
        // No-op; the RandomAccessFile remains open for the buffer lifetime.
      }
    };
  }

  /**
   * Closes the buffer and deletes the backing file.
   *
   * <p>If {@link #setSecureDelete(boolean) secure delete} is enabled, deletion is performed via
   * {@link FileUtil#secureDelete(File)}. Otherwise, a best-effort {@link
   * java.nio.file.Files#delete(java.nio.file.Path)} is attempted. Failures are logged and not
   * thrown to the caller.
   */
  @Override
  public void free() {
    close();
    if (secureDelete) {
      try {
        FileUtil.secureDelete(file);
      } catch (IOException e) {
        LOG.error("Unable to delete {} : {}", file, e, e);
      }
    } else {
      try {
        Files.delete(file.toPath());
      } catch (IOException e) {
        LOG.warn("Unable to delete temporary file {}", file, e);
      }
    }
  }

  /**
   * Enables or disables secure deletion for subsequent {@link #free()} calls.
   *
   * @param secureDelete {@code true} to overwrite before unlink; {@code false} for regular delete
   */
  public void setSecureDelete(boolean secureDelete) {
    this.secureDelete = secureDelete;
  }

  /**
   * Re-opens the underlying file after a persistence resume.
   *
   * <p>This method validates that the target file still exists and matches the expected length,
   * then re-opens it in the recorded mode.
   *
   * @param context client context provided by the caller (not used here but part of the contract)
   * @throws ResumeFailedException if the file is missing or the length differs
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    if (!file.exists()) throw new ResumeFailedException("File does not exist any more");
    if (file.length() != length) throw new ResumeFailedException("File is wrong length");
    try {
      raf = new RandomAccessFile(file, readOnly ? "r" : "rw");
    } catch (FileNotFoundException _) {
      throw new ResumeFailedException("File does not exist any more");
    }
  }

  // Magic and version used for lightweight persistence of buffer metadata.
  static final int MAGIC = 0xdd0f4ab2;
  static final int VERSION = 1;

  /**
   * Writes the identifying header and state required to reconstruct this buffer later.
   *
   * <p>Format (in order):
   *
   * <ul>
   *   <li>{@code int MAGIC}
   *   <li>{@code int VERSION}
   *   <li>{@code UTF file path}
   *   <li>{@code boolean readOnly}
   *   <li>{@code long length}
   *   <li>{@code boolean secureDelete}
   * </ul>
   *
   * @param dos destination stream
   * @throws IOException if an I/O error occurs while writing
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeUTF(file.toString());
    dos.writeBoolean(readOnly);
    dos.writeLong(length);
    dos.writeBoolean(secureDelete);
  }

  /**
   * Restores a buffer from a stream previously written by {@link #storeTo(DataOutputStream)}.
   *
   * <p>The constructor validates that the file exists and is at least the recorded length, then
   * opens it in the recorded mode.
   *
   * @param dis source stream
   * @throws IOException if an I/O error occurs while reading
   * @throws StorageFormatException if the version is unsupported or the length is invalid
   * @throws ResumeFailedException if the file is missing or truncated compared to the recorded
   *     length
   */
  public FileRandomAccessBuffer(DataInputStream dis)
      throws IOException, StorageFormatException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    file = new File(dis.readUTF());
    readOnly = dis.readBoolean();
    length = dis.readLong();
    secureDelete = dis.readBoolean();
    if (length < 0) throw new StorageFormatException("Bad length");
    // Validate existence/length before opening since an RAF is needed immediately after.
    if (!file.exists()) throw new ResumeFailedException("File does not exist");
    if (length > file.length()) throw new ResumeFailedException("Bad length");
    this.raf = new RandomAccessFile(file, readOnly ? "r" : "rw");
  }

  /**
   * Computes a hash code based on file identity, logical size, mode, and deletion preference.
   *
   * @return a hash code consistent with {@link #equals(Object)}
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((file == null) ? 0 : file.hashCode());
    result = prime * result + Long.hashCode(length);
    result = prime * result + (readOnly ? 1231 : 1237);
    result = prime * result + (secureDelete ? 1231 : 1237);
    return result;
  }

  /**
   * Compares for equality with another object.
   *
   * <p>Two buffers are equal when they reference the same file path and have identical logical
   * length, read-only mode, and secure-deletion setting. The current open/closed state and file
   * contents are not considered.
   *
   * @param obj the object to compare
   * @return {@code true} if equal as described above; otherwise {@code false}
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    FileRandomAccessBuffer other = (FileRandomAccessBuffer) obj;
    if (!file.equals(other.file)) {
      return false;
    }
    if (length != other.length) {
      return false;
    }
    if (readOnly != other.readOnly) {
      return false;
    }
    return secureDelete == other.secureDelete;
  }
}
