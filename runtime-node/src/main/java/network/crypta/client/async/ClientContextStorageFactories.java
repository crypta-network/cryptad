package network.crypta.client.async;

import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;

/**
 * Groups storage-related factories and filename generators used by {@link ClientContext}.
 *
 * <p>The factories in this record create temporary buckets and file-backed buffers for both
 * transient and persistent operations. The filename generators are used to derive unique names for
 * files created by client requests.
 *
 * @param persistentBucketFactory factory for persistent temporary buckets
 * @param tempBucketFactory factory for transient temporary buckets
 * @param persistentFileTracker tracker for persistent files created by client requests
 * @param filenameGenerator generator for transient filenames
 * @param persistentFilenameGenerator generator for persistent filenames
 * @param fileRAFTransient file factory for transient random-access buffers
 * @param fileRAFPersistent file factory for persistent random-access buffers
 */
public record ClientContextStorageFactories(
    PersistentTempBucketFactory persistentBucketFactory,
    TempBucketFactory tempBucketFactory,
    PersistentFileTracker persistentFileTracker,
    FilenameGenerator filenameGenerator,
    FilenameGenerator persistentFilenameGenerator,
    FileRandomAccessBufferFactory fileRAFTransient,
    FileRandomAccessBufferFactory fileRAFPersistent) {}
