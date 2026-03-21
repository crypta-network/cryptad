package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs best-effort file replacement with an atomic-first strategy for low-level persistence
 * code.
 *
 * <p>Use this helper when code needs to publish a fully written temporary file over an existing
 * target without pulling in broader daemon utilities. The class first asks the filesystem for an
 * atomic move, then falls back to a bounded replace-existing retry loop. That behavior matches the
 * needs of config and localization persistence, where callers prefer a complete replacement over
 * partial in-place writes but must still cope with platforms that do not support atomic rename.
 *
 * <p>This helper is stateless and thread-safe. It does not fsync, coordinate locking between
 * processes, or guarantee recovery after all retries fail. Callers remain responsible for creating
 * the temporary file, choosing an appropriate directory, and reacting to a {@code false} result.
 *
 * <ul>
 *   <li>Prefers atomic replacement when the platform supports it.
 *   <li>Falls back to replace-existing moves with bounded backoff.
 *   <li>Preserves interruption if retry sleep is cut short.
 * </ul>
 *
 * @see network.crypta.config.FilePersistentConfig
 * @see network.crypta.l10n.BaseL10n
 */
public final class AtomicFileMoves {
  private static final Logger LOG = LoggerFactory.getLogger(AtomicFileMoves.class);

  private static final int REPLACE_MOVE_MAX_ATTEMPTS = 5;
  private static final long REPLACE_MOVE_BASE_BACKOFF_MILLIS = 50;
  private static final long REPLACE_MOVE_MAX_BACKOFF_MILLIS = 400;

  private AtomicFileMoves() {}

  /**
   * Moves a file to a destination path while allowing replacement of an existing target.
   *
   * <p>This convenience overload delegates to {@link #moveTo(File, File, boolean)} with {@code
   * overwrite} enabled. It fits the common Cryptad pattern of writing a fresh temporary file and
   * then publishing it over the previous config or override file in one step. The method returns
   * {@code false} when both the atomic move and every retrying fallback path fail.
   *
   * @param orig file that already contains the complete replacement contents
   * @param dest destination path that should receive the replacement file
   * @return {@code true} when the move succeeds; {@code false} when all supported strategies fail
   */
  public static boolean moveTo(File orig, File dest) {
    return moveTo(orig, dest, true);
  }

  /**
   * Moves a file to a destination path, optionally refusing to replace an existing target.
   *
   * <p>The method first attempts an atomic move so readers either observe the old file or the new
   * file, never an in-place partial write. When the platform rejects that operation, the code falls
   * back to replace-existing moves with bounded retries and exponential backoff. If {@code
   * overwrite} is {@code false} and the destination already exists, the method returns {@code
   * false} immediately without touching either path.
   *
   * @param orig file that should be moved or renamed into place
   * @param dest destination path that should receive {@code orig}
   * @param overwrite whether an existing destination may be replaced in place
   * @return {@code true} if the move succeeds; {@code false} if replacement is disallowed or the
   *     move still fails after the fallback strategy is exhausted
   */
  public static boolean moveTo(File orig, File dest, boolean overwrite) {
    if (!overwrite && dest.exists()) {
      return false;
    }
    Path source = orig.toPath();
    Path target = dest.toPath();
    if (tryAtomicMove(source, target, orig, dest)) {
      return true;
    }
    return moveWithReplaceRetries(source, target, orig, dest);
  }

  private static boolean tryAtomicMove(Path source, Path target, File orig, File dest) {
    try {
      Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
      return true;
    } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Atomic move unavailable for {} -> {}: {}", orig, dest, e.toString());
      }
    } catch (IOException e) {
      if (LOG.isWarnEnabled()) {
        LOG.warn(
            "Atomic move failed for {} -> {}, retrying non-atomically: {}",
            orig,
            dest,
            e.toString());
      }
    }
    return false;
  }

  private static boolean moveWithReplaceRetries(Path source, Path target, File orig, File dest) {
    IOException lastFailure = null;
    for (int attempt = 1; attempt <= REPLACE_MOVE_MAX_ATTEMPTS; attempt++) {
      try {
        Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        return true;
      } catch (IOException e) {
        lastFailure = e;
        if (attempt == 1) {
          LOG.warn(
              "Replace-existing move failed for {} -> {} (attempt {}/{}), retrying: {}",
              orig,
              dest,
              attempt,
              REPLACE_MOVE_MAX_ATTEMPTS,
              e.toString());
        } else if (attempt < REPLACE_MOVE_MAX_ATTEMPTS && LOG.isDebugEnabled()) {
          LOG.debug(
              "Replace-existing move retry failed for {} -> {} (attempt {}/{}): {}",
              orig,
              dest,
              attempt,
              REPLACE_MOVE_MAX_ATTEMPTS,
              e.toString());
        }
        if (attempt == REPLACE_MOVE_MAX_ATTEMPTS) {
          break;
        }
        if (!sleepBeforeReplaceMoveRetry(orig, dest, attempt)) {
          return false;
        }
      }
    }
    LOG.error(
        "Replace-existing move failed for {} -> {} after {} attempts: {}",
        orig,
        dest,
        REPLACE_MOVE_MAX_ATTEMPTS,
        lastFailure,
        lastFailure);
    return false;
  }

  private static boolean sleepBeforeReplaceMoveRetry(File orig, File dest, int attempt) {
    long backoffMillis = retryBackoffMillis(attempt);
    try {
      Thread.sleep(backoffMillis);
      return true;
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      LOG.error(
          "Interrupted while retrying replace-existing move for {} -> {} (attempt {}/{}).",
          orig,
          dest,
          attempt,
          REPLACE_MOVE_MAX_ATTEMPTS,
          interrupted);
      return false;
    }
  }

  private static long retryBackoffMillis(int failedAttempt) {
    long backoff = REPLACE_MOVE_BASE_BACKOFF_MILLIS;
    int shifts = failedAttempt - 1;
    if (shifts > 0) {
      backoff <<= Math.min(shifts, 30);
    }
    return Math.min(backoff, REPLACE_MOVE_MAX_BACKOFF_MILLIS);
  }
}
