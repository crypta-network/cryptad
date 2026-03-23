package network.crypta.support.io;

import java.io.File;

/**
 * Contract for resolving and relocating persistent temporary files.
 *
 * <p>Persistence-oriented code uses this interface to recover the stable file path associated with
 * a persisted identifier and to reconcile that path with the current on-disk layout after restart
 * or directory moves. The contract is intentionally narrow: it exposes only the operations needed
 * by the generic resume and persistence surface and avoids coupling callers to any concrete
 * filename generation strategy.
 *
 * <p>Typical callers are persistent buckets, pooled file buffers, and resume helpers that need to
 * reopen or relocate files created in an earlier process. Those callers should treat the interface
 * as a path-resolution contract, not as a general-purpose temp-file factory. Implementations may
 * keep a richer internal state, but cross-boundary APIs should rely only on this minimal surface,
 * so generic support code can move independently of the concrete filename generator implementation.
 */
public interface PersistentFilenameGenerator {

  /**
   * Returns the file associated with the supplied persistent identifier.
   *
   * <p>The returned path is stable for the current persistent filename namespace. It may already
   * exist because a previous run created the file, or it may merely describe the location where
   * resume code should recreate an empty file before continuing. Callers should not infer anything
   * about file ownership beyond the identifier-to-path mapping exposed here.
   *
   * @param id persistent identifier whose stable backing-file path should be resolved
   * @return the file currently associated with {@code id} in this namespace
   */
  File getFilename(long id);

  /**
   * Reconciles a stored file path with the current persistent filename namespace.
   *
   * <p>If the supplied file already belongs to the current namespace, implementations may return it
   * unchanged. If the namespace has moved or the persisted path is stale, implementations may move
   * the file into the expected location or otherwise recover the file that should now back the
   * supplied identifier. Callers typically invoke this during resume after validating that some
   * on-disk file still exists and before re-registering it with persistent tracking.
   *
   * @param file file to reconcile against the current namespace; must not be {@code null}
   * @param id persistent identifier used to derive the expected current file path
   * @return the file that resume code should use after reconciliation completes
   * @throws ResumeFailedException if the stored file cannot be recovered into the current namespace
   */
  File maybeMove(File file, long id) throws ResumeFailedException;
}
