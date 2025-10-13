package network.crypta.support.io;

import java.io.File;

/**
 * Contract for validating that sufficient free space exists before writing more data.
 *
 * <p>Callers use this interface to decide whether a pending write should proceed based on the
 * available space of the filesystem containing the target file. Implementations define the specific
 * policy (for example, reserving a minimum amount of free bytes, or allowing writes only when a
 * threshold is met) and may incorporate additional context such as write buffering or throttling
 * intervals.
 *
 * <p><strong>Units:</strong> All sizes are in bytes.
 *
 * <p><strong>Threading:</strong> Implementations may be invoked from multiple threads. Any
 * thread-safety guarantees should be documented by the implementing class.
 */
public interface DiskSpaceChecker {

  /**
   * Determines whether a proposed write should be allowed given current free space.
   *
   * <p>The {@code file} identifies the destination whose containing filesystem is evaluated. The
   * file may or may not already exist (implementation-dependent). The {@code toWrite} value
   * represents the number of additional bytes the caller intends to write next. {@code bufferSize}
   * can be used by implementations to incorporate the amount written since the last check, enabling
   * periodic rather than per-byte evaluation.
   *
   * <p>This method does not declare checked exceptions. Implementations should return {@code false}
   * to signal insufficient space rather than throwing, unless a fatal error unrelated to low disk
   * space occurs.
   *
   * @param file target file; used to determine the filesystem to check; must be non-null
   * @param toWrite number of additional bytes the caller intends to write (bytes; non-negative)
   * @param bufferSize number of bytes written since the last check (bytes; non-negative)
   * @return {@code true} if the write is allowed under the implementation's policy; {@code false}
   *     otherwise
   */
  boolean checkDiskSpace(File file, int toWrite, int bufferSize);
}
