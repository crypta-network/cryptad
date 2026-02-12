package network.crypta.support.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.config.Config;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStarter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helpers for determining sensible datastore sizes.
 *
 * <p>This utility provides:
 *
 * <ul>
 *   <li>{@link #maxDatastoreSize()} — a hard upper bound derived from JVM memory limits and the
 *       free space of the Cryptad data directory.
 *   <li>{@link #autodetectDatastoreSize(NodeClientCore, Config)} — a user‑facing suggestion based
 *       on simple thresholds for first‑time configuration.
 * </ul>
 *
 * <p>Units: sizes are expressed in bytes. Methods are side‑effect-free and thread‑safe.
 */
public final class DatastoreUtil {
  private static final Logger LOG = LoggerFactory.getLogger(DatastoreUtil.class);

  /** Size of one mebibyte (MiB) in bytes. */
  public static final long ONE_MIB = 1024L * 1024L;

  /** Size of one gibibyte (GiB) in bytes. */
  public static final long ONE_GIB = 1024L * 1024L * 1024L;

  /**
   * Not instantiable utility class.
   *
   * <p>Prevents accidental construction; all members are static.
   */
  private DatastoreUtil() {
    throw new AssertionError("No instances");
  }

  /**
   * Computes a hard upper bound for the datastore size.
   *
   * <p>The result is the minimum of:
   *
   * <ol>
   *   <li>a memory‑derived limit based on {@link NodeStarter#getMemoryLimitBytes()}, reserving
   *       100&nbsp;MiB, using 50% of the remainder for slot filters (4&nbsp;bytes/slot, three key
   *       types), then converting slot count to bytes on disk via {@link
   *       network.crypta.node.subsystem.NodeStorageSubsystem#SIZE_PER_KEY}; and
   *   <li>the unallocated space of the Cryptad data directory (resolved to use the same
   *       service/user detection as the launcher).
   * </ol>
   *
   * <p>On {@link IOException} while querying the filesystem, the method returns the memory‑derived
   * limit.
   *
   * @return maximum datastore size in bytes
   */
  public static long maxDatastoreSize() {
    long maxDatastoreSize = getMaxDatastoreSize();

    // Compare against free space of the Cryptad data directory (not CWD).
    try {
      AppEnv env = new AppEnv();
      Resolved dirs = env.isServiceMode() ? new ServiceDirs().resolve() : new AppDirs().resolve();
      Path dataDirPath = dirs.getDataDir();
      long unallocatedSpace = Files.getFileStore(dataDirPath).getUnallocatedSpace();
      // Constrain by the lesser of disk-free space and the memory-derived cap.
      // Any additional reserve policy is handled elsewhere.
      return Math.min(unallocatedSpace, maxDatastoreSize);
    } catch (IOException e) {
      LOG.error("Error querying space", e);
    }

    return maxDatastoreSize;
  }

  private static long getMaxDatastoreSize() {
    long maxDatastoreSize;

    // check ram limitations
    long maxMemory = NodeStarter.getMemoryLimitBytes();
    if (maxMemory == Long.MAX_VALUE || maxMemory < 128 * ONE_MIB) {
      maxDatastoreSize = ONE_GIB; // 1GB default if we don't know or very small memory.
    } else {
      // Don't use the first 100MB for slot filters.
      long available = maxMemory - 100 * ONE_MIB;
      // Don't use more than 50% of available memory for slot filters.
      available = available / 2;
      // Slot filters are 4 bytes per slot.
      long slots = available / 4;
      // There are 3 types of keys. We want the number of { SSK, CHK, pubkey } i.e., the number of
      // slots in each store.
      slots /= 3;
      // We return the total size, so we don't need to worry about cache vs. store or even client
      // cache.
      // One key of all 3 types combined uses NodeStorageSubsystem.SIZE_PER_KEY bytes on disk.
      maxDatastoreSize =
          slots
              * network.crypta.node.subsystem.NodeStorageSubsystem
                  .SIZE_PER_KEY; // in total this is (RAM - 100 MiB) / 24 * ~32 KiB
    }
    return maxDatastoreSize;
  }

  /**
   * Suggests a datastore size for first‑time setup based on free space.
   *
   * <p>Heuristic:
   *
   * <ul>
   *   <li>if free space &gt; 50&nbsp;GiB → 20% of free space, at least 10&nbsp;GiB, capped at
   *       256&nbsp;GiB;
   *   <li>else if free space &gt; 5&nbsp;GiB → 20% of free space, at least 2&nbsp;GiB;
   *   <li>else if free space &gt; 2&nbsp;GiB → 512&nbsp;MiB;
   *   <li>else → 256&nbsp;MiB.
   * </ul>
   *
   * <p>Returns {@code -1} when the {@code node.storeSize} option is explicitly set, or when free
   * space is non‑positive, to indicate that no suggestion should be presented.
   *
   * @param core node core used to get the store directory and its free space
   * @param config configuration root used to inspect {@code node.storeSize}
   * @return suggested datastore size in bytes, or {@code -1} when not applicable
   */
  public static long autodetectDatastoreSize(NodeClientCore core, Config config) {
    if (!config.get("node").getOption("storeSize").isDefault()) {
      return -1;
    }

    long freeSpace = core.getNode().getStoreDir().getUsableSpace();

    if (freeSpace <= 0) {
      return -1;
    } else {
      long shortSize;
      // Maximum for Freenet: 256GB. That's a 128MiB bloom filter.
      long bloomFilter128MiBMax = 256 * ONE_GIB;
      // SSD era: disk I/O cap equals bloom-filter cap; use that as the upper bound.

      // Choose a suggested store size based on available free space.
      if (freeSpace > 50 * ONE_GIB) {
        // > 50 GiB: Use 20% free space; minimum 10 GiB. Limited by bloom filters.
        shortSize = Math.clamp(freeSpace / 5, 10 * ONE_GIB, bloomFilter128MiBMax);
      } else if (freeSpace > 5 * ONE_GIB) {
        // > 5 GiB: Use 20% free space, minimum 2 GiB.
        shortSize = Math.max(freeSpace / 5, 2 * ONE_GIB);
      } else if (freeSpace > 2 * ONE_GIB) {
        // > 2 GiB: 512 MiB.
        shortSize = 512 * ONE_MIB;
      } else {
        // <= 2 GiB: 256 MiB.
        shortSize = 256 * ONE_MIB;
      }

      return shortSize;
    }
  }
}
