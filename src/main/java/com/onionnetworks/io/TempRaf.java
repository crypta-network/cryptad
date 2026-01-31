package com.onionnetworks.io;

import com.onionnetworks.util.*;
import java.io.*;

/**
 * Temporary {@link RAF}-backed random access file that lives in a scratch location until a keep
 * policy decides whether it should be removed or preserved.
 *
 * <p>The class creates or wraps an underlying temporary file and forwards all random access
 * operations to a {@link FilterRAF} delegate while tracking whether the file has been renamed. Use
 * it to stage writes safely: callers can write to the temporary path, atomically rename to the
 * final destination, and rely on deterministic cleanup on close. When no rename occurs—or when a
 * rename happens but writing has not been finalized—the keep policy can delete the scratch file to
 * avoid littering disks after partial operations or failures.
 *
 * <p>Lifecycle considerations include synchronized {@link #renameTo(File)} and {@link #close()}
 * methods that guard the rename flag and cleanup logic; other I/O operations are delegated and may
 * follow the concurrency guarantees of the wrapped {@link RAF}. Keep policies control deletion or
 * retention, with {@link #DEFAULT_KEEP_POLICY} mapping to {@link #NEVER}. Choose stricter policies
 * for short-lived staging buffers, and {@link #ALWAYS} when the temporary file must outlive the
 * wrapper.
 *
 * <ul>
 *   <li>Staging workflow: write to the temporary path, optionally call {@link #renameTo(File)},
 *       then close.
 *   <li>Cleanup behavior: enforced on {@link #close()} based on the keep policy and rename status.
 *   <li>Threading: rename and close are synchronized; other methods inherit delegate semantics.
 * </ul>
 *
 * @author Justin Chapweske (justin@chapweske.com)
 */
public class TempRaf extends FilterRAF {

  /**
   * Keep policy that always removes the temporary file during {@link #close()}, regardless of
   * rename status or access mode, ensuring scratch data never persists beyond the wrapper.
   */
  public static final int NEVER = 0;

  /**
   * Keep policy that removes the temporary file on {@link #close()} unless the file has been
   * renamed and the RAF is currently opened in read-only mode, indicating writing has completed.
   */
  public static final int RENAMED_AND_DONE_WRITING = 1;

  /**
   * Keep policy that removes the temporary file unless {@link #renameTo(File)} was called before
   * {@link #close()}, enabling callers to persist only when an explicit rename occurs.
   */
  public static final int RENAMED = 2;

  /**
   * Keep policy that never removes the temporary file, preserving the underlying data even when no
   * rename occurs; suited to callers that manage cleanup manually or reuse the file elsewhere.
   */
  public static final int ALWAYS = 3;

  /** Default keep policy; identical to {@link #NEVER} for conservative automatic cleanup. */
  public static final int DEFAULT_KEEP_POLICY = 0;

  int keepPolicy;
  boolean renamedFlag = false;

  /**
   * Create a temporary RAF using {@link #DEFAULT_KEEP_POLICY} and a scratch file allocated via
   * {@link FileUtil#createTempFile(File)}.
   *
   * <p>This convenience constructor chooses the safest cleanup behavior by deleting the temporary
   * file on {@link #close()} even if a rename occurred. The underlying file is created in the user
   * or system temporary directory with read/write access. Use this when callers simply need short-
   * * lived staging storage without coordinating explicit retention.
   *
   * @throws IOException if the temporary file cannot be created or opened for random access I/O.
   */
  @SuppressWarnings("unused")
  public TempRaf() throws IOException {
    this(DEFAULT_KEEP_POLICY);
  }

  /**
   * Create a temporary RAF that cleans up according to a caller-provided keep policy.
   *
   * <p>The constructor allocates a new scratch file, opens it in read/write mode, and installs the
   * supplied keep policy so {@link #close()} can decide whether to delete or retain the file. Use
   * {@link #RENAMED} or {@link #RENAMED_AND_DONE_WRITING} when you want deletion only if a rename
   * does not occur; use {@link #ALWAYS} to opt out of automatic cleanup.
   *
   * <pre>{@code
   * try (TempRaf raf = new TempRaf(TempRaf.RENAMED)) {
   *   // write, then persist explicitly
   *   raf.renameTo(new File("target.bin"));
   * }
   * }</pre>
   *
   * @param keepPolicy deletion strategy constant such as {@link #NEVER} or {@link #RENAMED}.
   * @throws IOException if the temporary file cannot be created or opened for random access I/O.
   */
  public TempRaf(int keepPolicy) throws IOException {
    // Create a temp file in the user temp dir, or failing that, the
    // system temp dir.
    this(new RAF(FileUtil.createTempFile(null), "rw"), keepPolicy);
  }

  /**
   * Wrap an existing {@link RAF} using {@link #DEFAULT_KEEP_POLICY} so the temporary file is
   * removed on {@link #close()} regardless of subsequent renames.
   *
   * <p>Use this overload when an external component has already provisioned a suitable scratch
   * file, but the caller still wants deterministic cleanup semantics enforced by this wrapper.
   *
   * @param raf underlying random access file to wrap; must reference a temporary file path.
   */
  @SuppressWarnings("unused")
  public TempRaf(RAF raf) {
    this(raf, DEFAULT_KEEP_POLICY);
  }

  /**
   * Wrap an existing {@link RAF} and apply a specific keep policy to govern cleanup on close.
   *
   * <p>The constructor delegates to the superclass with the provided RAF, records the keep policy,
   * and registers a JVM shutdown hook via {@link File#deleteOnExit()} unless deletion is disabled
   * by {@link #ALWAYS}. This ensures that temporary files do not linger after abrupt termination.
   *
   * @param raf underlying random access file that represents the temporary storage location.
   * @param keepPolicy deletion strategy constant controlling cleanup when {@link #close()} runs.
   */
  public TempRaf(RAF raf, int keepPolicy) {
    super(raf);
    if (keepPolicy != ALWAYS) {
      // clean up in case of force shutdown.
      raf.getFile().deleteOnExit();
    }

    this.keepPolicy = keepPolicy;
  }

  /**
   * Rename the underlying temporary file to a caller-specified destination and record that a rename
   * occurred for subsequent cleanup decisions.
   *
   * <p>The rename flag allows {@link #close()} to distinguish between temporary files that were
   * staged but never persisted and those intentionally promoted to a final location. The method is
   * synchronized to serialize concurrent rename attempts with closing.
   *
   * @param newFile destination file path to which the temporary file should be moved.
   * @throws IOException if the delegate rename fails or the target cannot be written or replaced.
   */
  @Override
  public synchronized void renameTo(File newFile) throws IOException {
    renamedFlag = true;
    super.renameTo(newFile);
  }

  /**
   * Close the wrapped RAF and delete the temporary file according to the configured keep policy.
   *
   * <p>The method evaluates {@link #keepPolicy} and {@link #renamedFlag}: {@link #NEVER} always
   * removes the file; {@link #RENAMED} removes it unless a rename occurred; {@link
   * #RENAMED_AND_DONE_WRITING} removes it unless renamed while in read-only mode; {@link #ALWAYS}
   * never deletes. The logic runs before delegating to {@link FilterRAF#close()}, and the method is
   * synchronized to avoid races with {@link #renameTo(File)}.
   *
   * @throws IOException if closing the delegate RAF fails or underlying I/O errors occur.
   */
  @SuppressWarnings("StatementSwitchToExpressionSwitch")
  @Override
  public synchronized void close() throws IOException {

    // keep as a switch statement for readability.
    switch (keepPolicy) {
      case NEVER:
        deleteOnClose();
        break;
      case RENAMED:
        if (!renamedFlag) {
          deleteOnClose();
        }
        break;
      case RENAMED_AND_DONE_WRITING:
        if (!renamedFlag || !getMode().equals("r")) {
          deleteOnClose();
        }
        break;
      default:
        break;
    }

    super.close();
  }
}
