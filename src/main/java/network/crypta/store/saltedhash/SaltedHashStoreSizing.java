package network.crypta.store.saltedhash;

/**
 * Captures capacity and lifecycle sizing options for a salted-hash store.
 *
 * <p>This record groups the sizing-related inputs used during store initialization and startup. It
 * is intended for configuration wiring where capacity, filter usage, preallocation, and
 * resize-on-start policy are set together. The values are stored verbatim and are not validated or
 * normalized by this type; any enforcement is handled by the store implementation.
 *
 * <p>The record is immutable and thread-safe for callers that treat its values as read-only.
 * Typical usage is to combine it with {@link SaltedHashStoreLocation} and {@link
 * SaltedHashStoreDependencies} when building {@link SaltedHashStoreParams} for store construction.
 * Changes to sizing require constructing a new instance.
 *
 * <ul>
 *   <li>Defines the logical capacity of the store in number of slots.
 *   <li>Controls whether the on-disk slot filter structure is enabled.
 *   <li>Controls preallocation and startup resizing behavior.
 * </ul>
 *
 * @param maxKeys logical capacity expressed as a count of slots; stored verbatim.
 * @param useSlotFilter whether to enable the on-disk slot filter index.
 * @param preallocate whether to preallocate store files up to the configured capacity.
 * @param resizeOnStart whether to finish any in-progress resize during startup.
 */
public record SaltedHashStoreSizing(
    long maxKeys, boolean useSlotFilter, boolean preallocate, boolean resizeOnStart) {}
