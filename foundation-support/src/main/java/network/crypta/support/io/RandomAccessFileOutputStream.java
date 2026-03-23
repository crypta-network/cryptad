package network.crypta.support.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link OutputStream} view over a {@link RandomAccessFile} that delegates all write operations
 * to the underlying file.
 *
 * <p>This adapter writes at the current file pointer of the provided {@code RandomAccessFile} and
 * advances that pointer accordingly. It does not perform any buffering and does not change the
 * file's seek position beyond what the delegated writes imply. Closing this stream closes the
 * underlying {@code RandomAccessFile}.
 *
 * <p>Thread-safety: this class provides no additional synchronization. If the same {@code
 * RandomAccessFile} is shared across threads, external coordination is recommended.
 */
public class RandomAccessFileOutputStream extends OutputStream {

  // Underlying file; owned by this stream. close() will close this instance.
  final RandomAccessFile raf;

  /**
   * Creates a stream that writes to the given {@link RandomAccessFile}.
   *
   * <p>Preconditions: the {@code raf} reference should be non-{@code null} and opened in a mode
   * that permits writing (for example, "rw", "rws", or "rwd"). If the file is opened read-only,
   * subsequent write operations will fail with {@link IOException}. This constructor does not
   * validate these conditions.
   *
   * @param raf the target file to receive writes; not validated for nullity
   */
  public RandomAccessFileOutputStream(RandomAccessFile raf) {
    this.raf = raf;
  }

  /**
   * Writes the low eight bits of the given value to the file at the current file pointer.
   *
   * <p>This method delegates to {@link RandomAccessFile#writeByte(int)}. The file pointer advances
   * by one byte, and the file length may increase if writing beyond the current end.
   *
   * @param arg0 the value whose least-significant 8 bits are written
   * @throws IOException if an I/O error occurs or the file does not permit writing
   */
  @Override
  public void write(int arg0) throws IOException {
    raf.writeByte(arg0);
  }

  /**
   * Writes the entire byte array at the current file pointer.
   *
   * <p>This method delegates to {@link RandomAccessFile#write(byte[])}. The file pointer advances
   * by {@code buf.length} bytes.
   *
   * @param buf the data to write
   * @throws NullPointerException if {@code buf} is {@code null}
   * @throws IOException if an I/O error occurs
   */
  @Override
  public void write(byte @NotNull [] buf) throws IOException {
    raf.write(buf);
  }

  /**
   * Writes a portion of the given byte array starting at {@code offset} for {@code length} bytes at
   * the current file pointer.
   *
   * <p>This method delegates to {@link RandomAccessFile#write(byte[], int, int)}. The file pointer
   * advances by {@code length} bytes.
   *
   * @param buf the source array
   * @param offset the starting index in {@code buf}
   * @param length the number of bytes to write
   * @throws NullPointerException if {@code buf} is {@code null}
   * @throws IndexOutOfBoundsException if the offset/length are out of bounds
   * @throws IOException if an I/O error occurs
   */
  @Override
  public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
    raf.write(buf, offset, length);
  }

  /**
   * Closes this stream and the underlying {@link RandomAccessFile}.
   *
   * <p>After a successful close, subsequent operations on this stream will fail, typically with an
   * {@link IOException} from the underlying file.
   *
   * @throws IOException if an I/O error occurs while closing the file
   */
  @Override
  public void close() throws IOException {
    raf.close();
  }
}
