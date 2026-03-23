package network.crypta.support.io;

import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * Output stream that periodically checks available disk space before writing.
 *
 * <p>This class delegates all writes to an underlying {@link OutputStream} but consults a {@link
 * DiskSpaceChecker} at configurable intervals. A disk-space check is performed only when the number
 * of bytes written since the last successful check plus the size of the pending write is greater
 * than or equal to {@code bufferSize}. If the check fails, the current write does not proceed and
 * an {@link InsufficientDiskSpaceException} is thrown.
 *
 * <p>The supplied {@link File} identifies the file being created or extended and is passed to the
 * checker. Implementations typically use it to resolve the containing directory or filesystem.
 *
 * <p>Thread-safety: {@link #write(byte[], int, int)} is {@code synchronized}. The other overloads
 * delegate to it, so writes are serialized per instance.
 */
public class DiskSpaceCheckingOutputStream extends FilterOutputStream {

  /**
   * Creates a stream that performs periodic disk-space checks during writes.
   *
   * @param out the underlying stream to write to; must not be {@code null}.
   * @param checker the strategy used to decide whether a write may proceed; must not be {@code
   *     null}.
   * @param file the path of the file being written. It is passed to the checker, which may use it
   *     to locate the target directory or filesystem; must not be {@code null}.
   * @param bufferSize the threshold in bytes that controls how often checks are performed. This
   *     value is also passed to {@link DiskSpaceChecker#checkDiskSpace(File, int, int)}; see that
   *     contract for details on its interpretation.
   */
  public DiskSpaceCheckingOutputStream(
      OutputStream out, DiskSpaceChecker checker, File file, int bufferSize) {
    super(out);
    this.checker = checker;
    this.file = file;
    this.bufferSize = bufferSize;
  }

  private final File file;
  private final DiskSpaceChecker checker;
  private final int bufferSize;
  // Total number of bytes successfully written through this stream so far.
  private long written;
  // Value of {@code written} at the time of the last successful disk-space check.
  private long lastChecked;

  /**
   * Writes the entire buffer, performing a disk-space check when required.
   *
   * @param buf the data to write; must not be {@code null}.
   * @throws InsufficientDiskSpaceException if the checker reports insufficient free space for the
   *     pending write.
   * @throws IOException if the underlying stream throws an I/O error.
   */
  @Override
  public void write(byte @NotNull [] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  /**
   * Writes a single byte, delegating to the array-based overload.
   *
   * @param i the byte to write, as an {@code int}.
   * @throws InsufficientDiskSpaceException if the checker reports insufficient free space for the
   *     pending write.
   * @throws IOException if the underlying stream throws an I/O error.
   */
  @Override
  public void write(int i) throws IOException {
    write(new byte[] {(byte) i});
  }

  /**
   * Writes a subrange of the given array, checking disk space at most once per threshold interval.
   *
   * <p>A check is triggered when {@code written + length - lastChecked >= bufferSize}. When a check
   * occurs and {@link DiskSpaceChecker#checkDiskSpace(File, int, int)} returns {@code false}, no
   * bytes are written and an {@link InsufficientDiskSpaceException} is thrown.
   *
   * @param buf the source buffer; must not be {@code null}.
   * @param offset the start offset in the data.
   * @param length the number of bytes to write.
   * @throws InsufficientDiskSpaceException if there is not enough free space to allow to write.
   * @throws IOException if the underlying stream throws an I/O error.
   */
  @Override
  public synchronized void write(byte @NotNull [] buf, int offset, int length) throws IOException {
    // Trigger a check when the next write would push the distance since the last check
    // to at least the configured threshold.
    if (written + length - lastChecked >= bufferSize) {
      if (!checker.checkDiskSpace(file, length, bufferSize))
        throw new InsufficientDiskSpaceException();
      // Record the position at which the check was performed so the threshold comparison includes
      // the size of the pending write. This biases checks conservatively.
      lastChecked = written;
    }
    out.write(buf, offset, length);
    written += length;
  }
}
