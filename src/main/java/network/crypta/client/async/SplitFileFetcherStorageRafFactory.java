package network.crypta.client.async;

import java.io.File;
import java.io.IOException;
import network.crypta.crypt.RandomSource;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import org.slf4j.Logger;

/**
 * Creates random-access buffers used by splitfile fetcher storage.
 *
 * <p>This utility encapsulates the decision between file-backed and in-memory {@link
 * LockableRandomAccessBuffer} instances for fetch operations. Callers typically invoke {@link
 * #createRafOrThrow(File, long, LockableRandomAccessBufferFactory, FileRandomAccessBufferFactory,
 * RandomSource, Logger)} during fetcher initialization, after any on-disk storage file has been
 * created. When a storage file is supplied, the factory enforces that it already exists and is
 * empty, then delegates creation to a disk-space-checking factory; otherwise it delegates to the
 * in-memory factory. The class is stateless and does not retain the returned buffer, so lifecycle
 * management remains with the caller. It is safe to call concurrently as long as the provided
 * factories are safe for the same usage.
 *
 * <ul>
 *   <li>Selects file-backed or in-memory RAF creation based on inputs.
 *   <li>Validates preconditions for complete-via-truncation file storage.
 * </ul>
 *
 * @see LockableRandomAccessBufferFactory
 * @see FileRandomAccessBufferFactory
 */
public final class SplitFileFetcherStorageRafFactory {
  private SplitFileFetcherStorageRafFactory() {}

  /**
   * Creates a random-access buffer for splitfile fetch storage based on inputs.
   *
   * <p>The method chooses between file-backed and in-memory storage using {@code storageFile}. For
   * file-backed storage, it requires an already-created, empty file, logs the creation event, and
   * delegates to the disk-space-checking factory. For in-memory storage, it delegates to {@code
   * rafFactory} without logging. The method performs no truncation or cleanup and does not cache
   * the result; the caller owns the returned buffer and manages its lifecycle.
   *
   * <pre>{@code
   * LockableRandomAccessBuffer raf =
   *     SplitFileFetcherStorageRafFactory.createRafOrThrow(
   *         storageFile, totalLength, memoryFactory, diskFactory, random, log);
   * }</pre>
   *
   * @param storageFile optional on-disk file; when non-null triggers file-backed RAF creation
   * @param totalLength length forwarded to the factory; units are defined by the factory
   * @param rafFactory non-null factory for in-memory buffers when {@code storageFile} is null
   * @param diskSpaceCheckingRafFactory non-null factory for file-backed RAFs when a file is used
   * @param random randomness source forwarded to file-backed creation; null is not checked here
   * @param log logger receiving a single info message for file-backed creation paths
   * @return a newly created lockable RAF whose lifecycle is managed by the caller
   * @throws IOException if preconditions fail or the selected factory cannot create storage
   */
  public static LockableRandomAccessBuffer createRafOrThrow(
      File storageFile,
      long totalLength,
      LockableRandomAccessBufferFactory rafFactory,
      FileRandomAccessBufferFactory diskSpaceCheckingRafFactory,
      RandomSource random,
      Logger log)
      throws IOException {
    if (storageFile != null) {
      if (diskSpaceCheckingRafFactory == null) {
        throw new IOException("Disk-space checking RAF factory required for file-backed storage");
      }
      if (!storageFile.exists()) throw new IOException("Must have already created storage file");
      if (storageFile.length() > 0) throw new IOException("Storage file must be empty");
      log.info("Creating splitfile storage file for complete-via-truncation: {}", storageFile);
      return diskSpaceCheckingRafFactory.createNewRAF(storageFile, totalLength, random);
    }
    return rafFactory.makeRAF(totalLength);
  }
}
