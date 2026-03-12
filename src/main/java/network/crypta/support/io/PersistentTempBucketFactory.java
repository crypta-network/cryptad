package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages persistent temporary buckets stored on disk for restart-safe workflows.
 *
 * <p>This factory creates {@link RandomAccessBucket} instances backed by files under a directory
 * managed by {@link PersistentFileTracker}. It is used for long-lived temporary data such as
 * persistent downloads: callers allocate buckets, register the resulting files on startup, and
 * allow the factory to delete unclaimed files once initialization completes. Buckets can be
 * encrypted with an ephemeral key when configured, and encryption can be toggled for newly created
 * buckets without rewriting existing files.
 *
 * <p>The deletion lifecycle is coordinated with persistence: buckets are freed only after the
 * transaction recording their deletion is durably committed. The factory is recreated on startup
 * and relies on callers to re-register their files, which prevents reuse after an unclean shutdown.
 * This class is thread-safe; it synchronizes around mutable state and uses a dedicated lock for
 * encryption settings.
 *
 * <p><strong>Notable behaviors:</strong>
 *
 * <ul>
 *   <li>Tracks unclaimed files seen at startup and deletes them after {@link #completedInit()}.
 *   <li>Defers file deletion until after {@link #finishDelayedFree(DelayedFree[])} is called.
 *   <li>Wraps buckets with encryption and delayed-free layers when configured.
 * </ul>
 */
public final class PersistentTempBucketFactory implements BucketFactory, PersistentFileTracker {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentTempBucketFactory.class);

  /**
   * Original contents of directory. This used to be used to delete any files that we can't account
   * for. However, at the moment we do not support garbage collection for non-blob persistent temp
   * files. When we implement it, it will probably not use this structure.
   */
  private HashSet<File> originalFiles;

  /**
   * Filename generator used for persistent temp files. It tracks the active directory and prefix,
   * supports directory moves initiated by the tracker, and produces unique filenames for new
   * buckets. The reference is immutable, but its internal configuration can change as the tracked
   * directory changes.
   */
  public final FilenameGenerator fg;

  /**
   * Buckets to free. When buckets are freed, we write them to this list, and delete the files
   * *after* the transaction recording the buckets being deleted hits the disk.
   */
  private final ArrayList<DelayedFree> bucketsToFree;

  private final Object encryptLock = new Object();

  /** Should we encrypt temporary files? */
  private boolean encrypt;

  private MasterSecret secret;

  private DiskSpaceChecker checker;

  private long commitID;

  /**
   * Creates a persistent temporary bucket factory rooted at a specific directory.
   *
   * <p>The factory scans the directory for pre-existing files matching the provided prefix and
   * records them as candidates for cleanup during {@link #completedInit()}. The supplied random
   * generator is used only for filename construction and need not be cryptographically strong.
   * Encryption configuration affects only buckets created after construction; existing buckets are
   * left unchanged.
   *
   * @param dir directory that stores persistent temporary files; must exist or be creatable.
   * @param prefix filename prefix used to recognize and generate persistent temp files.
   * @param weakPRNG fast, non-cryptographic random source for filename generation.
   * @param encrypt whether to encrypt newly created temporary buckets.
   * @throws IOException if the directory cannot be created, listed, or is not a directory.
   */
  public PersistentTempBucketFactory(
      File dir, final String prefix, Random weakPRNG, boolean encrypt) throws IOException {
    /* Cryptographically strong random number generator */
    /* Weak but fast random number generator. */
    this.encrypt = encrypt;
    this.fg = new FilenameGenerator(weakPRNG, false, dir, prefix);
    if (!dir.exists() && !dir.mkdir()) {
      throw new IOException("Directory does not exist and cannot be created: " + dir);
    }
    if (!dir.isDirectory()) throw new IOException("Directory is not a directory: " + dir);
    originalFiles = new HashSet<>();
    File[] files =
        dir.listFiles(
            pathname -> {
              if (!pathname.exists() || pathname.isDirectory()) return false;
              String name = pathname.getName();
              return name.startsWith(prefix);
            });
    if (files == null) {
      throw new IOException("Unable to list files in directory: " + dir);
    }
    for (File f : files) {
      f = FileUtil.getCanonicalFile(f);
      if (LOG.isDebugEnabled()) LOG.debug("Found {}", f);
      originalFiles.add(f);
    }

    bucketsToFree = new ArrayList<>();
    commitID = 1; // Must start > 0.
  }

  /**
   * Installs the disk space checker consulted by {@link #checkDiskSpace(File, int, int)}.
   *
   * <p>This method simply replaces the active checker reference and performs no validation. It is
   * typically called during wiring at startup before any buckets are created. Callers should ensure
   * the provided checker is thread-safe because it may be invoked concurrently by bucket writes.
   *
   * @param checker implementation to use for disk space validation; must not be {@code null}.
   */
  public void setDiskSpaceChecker(DiskSpaceChecker checker) {
    this.checker = checker;
  }

  /**
   * Sets the master secret used when encrypting new persistent temporary buckets.
   *
   * <p>The secret is stored under the encryption lock to keep updates consistent with {@link
   * #makeBucket(long)}. Changing the secret does not re-encrypt existing buckets; it only affects
   * buckets created after the update while encryption is enabled. Callers typically set the secret
   * during startup before creating any buckets to avoid inconsistent encryption settings across a
   * single run.
   *
   * @param secret master secret used to derive ephemeral encryption keys; may be {@code null} only
   *     if encryption is disabled.
   */
  public void setMasterSecret(MasterSecret secret) {
    synchronized (encryptLock) {
      this.secret = secret;
    }
  }

  /**
   * Records a temporary file as in-use so it is not deleted during initialization cleanup.
   *
   * <p>Callers should invoke this during startup for every persisted bucket that still exists. The
   * method removes the canonical file from the startup snapshot taken by the constructor. If {@link
   * #completedInit()} has already been called, this method throws an {@link IllegalStateException}
   * because cleanup is complete.
   *
   * @param file temporary bucket file to preserve; must resolve to an existing file.
   * @throws IllegalStateException if initialization has already completed.
   * @see #completedInit()
   */
  @Override
  public void register(File file) {
    synchronized (this) {
      if (originalFiles == null)
        throw new IllegalStateException("completed Init has already been called!");
      file = FileUtil.getCanonicalFile(file);
      if (LOG.isDebugEnabled()) LOG.debug("Preserving {}", file);
      if (!originalFiles.remove(file)) LOG.error("Preserving {} but it wasn't found!", file);
    }
  }

  /**
   * Finalizes startup cleanup by deleting any unclaimed temporary files.
   *
   * <p>After this method runs, the startup snapshot is discarded and later calls to {@link
   * #register(File)} are rejected. Deletions are best-effort: failures are logged and do not abort
   * startup. This method is synchronized to prevent concurrent cleanup with registration. It should
   * be invoked once, after all persisted buckets have had a chance to register.
   */
  public synchronized void completedInit() {
    if (originalFiles == null) {
      LOG.error("Completed init called twice");
      return;
    }
    for (File f : originalFiles) {
      if (LOG.isDebugEnabled()) LOG.debug("Deleting old tempfile {}", f);
      try {
        Files.deleteIfExists(f.toPath());
      } catch (IOException e) {
        LOG.warn("Failed to delete old tempfile {}", f, e);
      }
    }
    originalFiles = null;
  }

  /**
   * Creates a persistent temporary bucket with delayed deletion semantics.
   *
   * <p>The returned bucket is file-backed and may be wrapped with padding and encryption when
   * enabled. It is also wrapped in a delayed-free layer so that {@link #delayedFree(DelayedFree,
   * long)} can defer deletion until a transaction commit is durably recorded. The {@code size}
   * parameter is accepted for interface compatibility and does not preallocate storage.
   *
   * @param size desired bucket size in bytes; used for accounting only and may be ignored.
   * @return a new persistent, delayed-free random access bucket.
   * @throws IOException if the backing file cannot be created or initialized.
   */
  @Override
  public RandomAccessBucket makeBucket(long size) throws IOException {
    RandomAccessBucket rawBucket = new PersistentTempFileBucket(fg.makeRandomFilename(), fg, this);
    synchronized (encryptLock) {
      if (encrypt) {
        rawBucket = new PaddedRandomAccessBucket(rawBucket);
        rawBucket =
            new EncryptedRandomAccessBucket(TempBucketFactory.CRYPT_TYPE, rawBucket, secret);
      }
    }
    rawBucket = new DelayedFreeRandomAccessBucket(this, rawBucket);
    return rawBucket;
  }

  /**
   * Schedules a bucket for deletion once the commit boundary has advanced.
   *
   * <p>If the bucket was created in the current commit, the method frees it immediately. Otherwise,
   * it enqueues the bucket so the caller can flush the pending frees and later invoke {@link
   * #finishDelayedFree(DelayedFree[])} after the corresponding transaction has been persisted. This
   * method is thread-safe and may be called concurrently.
   *
   * @param b bucket wrapper that can be freed after a durable commit.
   * @param createdCommitID commit identifier captured when the bucket was created.
   */
  @Override
  public void delayedFree(DelayedFree b, long createdCommitID) {
    synchronized (this) {
      if (createdCommitID != commitID) {
        bucketsToFree.add(b);
        return;
      }
    }
    b.realFree();
  }

  /**
   * Returns the buckets pending deletion and advances the commit identifier.
   *
   * <p>The returned array is a snapshot of the current delayed-free queue and is safe for the
   * caller to persist alongside a checkpoint. After the checkpoint is durably written, the caller
   * should invoke {@link #finishDelayedFree(DelayedFree[])} with the same array. Each invocation
   * clears the queue and increments the commit identifier.
   *
   * @return array of buckets to free, or an empty array if none are pending.
   */
  public DelayedFree[] grabBucketsToFree() {
    synchronized (this) {
      if (bucketsToFree.isEmpty()) return new DelayedFree[0];
      DelayedFree[] buckets = bucketsToFree.toArray(new DelayedFree[0]);
      bucketsToFree.clear();
      commitID++;
      return buckets;
    }
  }

  /**
   * Returns the current commit identifier used for delayed-free coordination.
   *
   * <p>The identifier starts at {@code 1} and increments each time {@link #grabBucketsToFree()} is
   * called. Callers should treat the value as a monotonically increasing token that scopes when a
   * bucket may be freed. The value has process-local meaning only and should not be persisted
   * across restarts.
   *
   * @return the current commit identifier.
   */
  @Override
  public synchronized long commitID() {
    return commitID;
  }

  /**
   * Returns the directory where persistent temporary files are created.
   *
   * <p>This value reflects the current directory tracked by {@link #fg}. Callers should avoid
   * caching the value across directory changes and instead query when needed. The directory is
   * expected to exist and be writable when buckets are created.
   *
   * @return the active directory for persistent temporary files.
   */
  @Override
  public File dir() {
    return fg.getDir();
  }

  /**
   * Returns the filename generator responsible for persistent temp file naming.
   *
   * <p>The generator exposes the current directory and prefix and can relocate files when the
   * tracked directory changes. Callers should not mutate its configuration directly and should rely
   * on the factory methods to create new filenames.
   *
   * @return the filename generator used by this factory.
   */
  @Override
  public FilenameGenerator getGenerator() {
    return fg;
  }

  /**
   * Reports whether newly created temporary buckets are encrypted.
   *
   * <p>The value is guarded by the encryption lock and reflects only the configuration for new
   * buckets. Existing buckets are not rewritten if encryption settings change. Callers that need to
   * reason about existing data should track encryption state externally.
   *
   * @return {@code true} if new buckets will be encrypted; {@code false} otherwise.
   */
  public boolean isEncrypting() {
    synchronized (encryptLock) {
      return encrypt;
    }
  }

  /**
   * Sets whether to encrypt new persistent temporary buckets.
   *
   * <p>This setting affects buckets created after the update and does not re-encrypt or decrypt
   * existing files. Callers should set the {@link MasterSecret} first when enabling encryption to
   * avoid creating unencrypted buckets unexpectedly. Disabling encryption does not remove padding
   * or other wrappers from previously created buckets.
   *
   * @param encrypt {@code true} to encrypt new buckets, {@code false} to leave them unencrypted.
   */
  public void setEncryption(boolean encrypt) {
    synchronized (encryptLock) {
      this.encrypt = encrypt;
    }
  }

  /**
   * Finalizes deletion for previously delayed buckets.
   *
   * <p>The method iterates over the provided array and frees buckets that are still eligible for
   * deletion. It is safe to pass {@code null} or an empty array. Exceptions from individual bucket
   * frees are logged and do not halt the loop. This method does not retry failures; the caller may
   * choose to requeue a bucket if needed.
   *
   * @param buckets buckets previously returned by {@link #grabBucketsToFree()}, or {@code null}.
   */
  public void finishDelayedFree(DelayedFree[] buckets) {
    if (buckets != null) {
      for (DelayedFree bucket : buckets) {
        try {
          if (bucket.toFree()) bucket.realFree();
        } catch (Exception e) {
          LOG.error("Caught {} freeing bucket {} after transaction commit", e, bucket, e);
        }
      }
    }
  }

  /**
   * Delegates disk space checks to the configured {@link DiskSpaceChecker}.
   *
   * <p>This method does not apply additional logic beyond delegation and may throw a {@link
   * NullPointerException} if no checker has been configured. Callers should set the checker during
   * startup to ensure write paths can validate available space. The return value is used directly
   * by bucket writers to decide whether to proceed.
   *
   * @param file file that will be written; used to resolve the target filesystem.
   * @param toWrite number of bytes expected to be written in the current operation.
   * @param bufferSize write buffer size in bytes used by the caller.
   * @return {@code true} if the checker reports adequate space; {@code false} otherwise.
   */
  @Override
  public boolean checkDiskSpace(File file, int toWrite, int bufferSize) {
    return checker.checkDiskSpace(file, toWrite, bufferSize);
  }
}
