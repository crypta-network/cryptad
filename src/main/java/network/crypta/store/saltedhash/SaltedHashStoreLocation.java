package network.crypta.store.saltedhash;

import java.io.File;

/**
 * Describes the filesystem location and logical name of a salted-hash store.
 *
 * <p>This record groups the base directory and store name used to derive on-disk file paths for a
 * store instance. It is intended for configuration and dependency-injection layers where the
 * location and naming details are passed around independently of other store options. The values
 * are stored as provided and are not normalized, validated, or created on disk by this type.
 *
 * <p>Instances are immutable and thread-safe as long as the referenced {@link File} object is
 * treated as immutable by callers. Use this record together with {@link
 * SaltedHashStoreDependencies} and {@link SaltedHashStoreSizing} to build {@link
 * SaltedHashStoreParams} for store construction.
 *
 * <ul>
 *   <li>Captures the base directory where store files reside.
 *   <li>Captures the logical name used as a filename prefix.
 * </ul>
 *
 * @param baseDir directory reference used as the root for store files; not validated or created.
 * @param name logical store name used as a filename prefix; stored verbatim.
 */
public record SaltedHashStoreLocation(File baseDir, String name) {}
