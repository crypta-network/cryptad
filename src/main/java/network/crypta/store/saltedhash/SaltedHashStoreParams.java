package network.crypta.store.saltedhash;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the initialization inputs required to construct a salted-hash store.
 *
 * <p>This type groups the full creation surface used by {@link SaltedHashFreenetStore} factories so
 * callers can pass a single value object without losing configurability. It is intended for
 * configuration-driven wiring, dependency injection, and repeatable store construction where large
 * parameter lists are error-prone. The instance is immutable in the sense that its fields are
 * assigned once; the referenced objects themselves may be mutable and remain owned by the caller.
 *
 * <p>The parameter bundle performs no validation, file I/O, or store initialization. It preserves
 * object identity for references such as the {@link StoreCallback} and the master key array, so
 * callers must manage lifetimes and contents carefully. Use a new instance to change any option or
 * to target a different directory.
 *
 * <ul>
 *   <li>Captures filesystem and naming details for store files.
 *   <li>Captures crypto inputs and sizing policies that must remain consistent.
 *   <li>Captures lifecycle wiring such as shutdown hooks and preallocation policy.
 * </ul>
 *
 * @param <T> concrete {@link StorableBlock} type produced by the callback.
 */
public final class SaltedHashStoreParams<T extends StorableBlock> {
  private final File baseDir;
  private final String name;
  private final StoreCallback<T> callback;
  private final Random random;
  private final long maxKeys;
  private final boolean useSlotFilter;
  private final SemiOrderedShutdownHook shutdownHook;
  private final boolean preallocate;
  private final boolean resizeOnStart;
  private final byte[] masterKey;

  /**
   * Creates a parameter bundle for a salted-hash store from grouped inputs.
   *
   * <p>This constructor assembles the store parameters from three conceptual groups: location,
   * dependencies, and sizing. It performs no validation or defensive copying and simply records the
   * provided references for later consumption by store factories. Callers should ensure that
   * referenced objects remain valid for the lifetime of any constructed store and that the caller
   * manages the supplied master key array safely.
   *
   * <p>Construction is idempotent with respect to the supplied values: multiple calls with the same
   * references yield distinct parameter objects that describe identical store inputs.
   *
   * @param location filesystem and naming details for store files and prefixes.
   * @param dependencies callback, randomness, shutdown hook, and master key references.
   * @param sizing capacity and lifecycle sizing policies for the target store.
   */
  public SaltedHashStoreParams(
      SaltedHashStoreLocation location,
      SaltedHashStoreDependencies<T> dependencies,
      SaltedHashStoreSizing sizing) {
    this.baseDir = location.baseDir();
    this.name = location.name();
    this.callback = dependencies.callback();
    this.random = dependencies.random();
    this.maxKeys = sizing.maxKeys();
    this.useSlotFilter = sizing.useSlotFilter();
    this.shutdownHook = dependencies.shutdownHook();
    this.preallocate = sizing.preallocate();
    this.resizeOnStart = sizing.resizeOnStart();
    this.masterKey = dependencies.masterKey();
  }

  /**
   * Returns the base directory where the store files live.
   *
   * <p>The directory reference is the same object provided at construction time and is not
   * validated or normalized. The store implementation may create the directory if it is missing, so
   * callers should ensure the path is suitable for creation and has the expected permissions. This
   * method is side-effect-free and always returns the stored reference.
   *
   * @return the base directory reference used for store file placement.
   */
  public File baseDir() {
    return baseDir;
  }

  /**
   * Returns the logical store name used as a filename prefix.
   *
   * <p>The name is stored verbatim and is typically concatenated with file extensions to produce
   * on-disk filenames. Callers should supply a stable value so that the following runs open the
   * same store. This method does not sanitize or validate the string and always returns the stored
   * reference.
   *
   * @return the logical store name used for file naming and identification.
   */
  public String name() {
    return name;
  }

  /**
   * Returns the callback used to size and (de-)serialize store entries.
   *
   * <p>The callback reference is recorded without validation and is not invoked by this parameter
   * object. It is expected to supply header/data lengths and block construction logic for the
   * concrete {@link StorableBlock} type. The returned value is the original reference and should be
   * treated as shared across any stores built from these parameters.
   *
   * @return the callback implementation associated with this store configuration.
   */
  public StoreCallback<T> callback() {
    return callback;
  }

  /**
   * Returns the randomness source used by the store for cryptographic decisions.
   *
   * <p>The random instance is stored as provided, with no defensive copying or reseeding. Store
   * construction and later operations may rely on it for encryption material or placement
   * tie-breakers, so callers should provide a suitable implementation for their threat model. This
   * method simply returns the stored reference.
   *
   * @return the randomness source used by the store implementation.
   */
  public Random random() {
    return random;
  }

  /**
   * Returns the configured maximum number of keys for the store.
   *
   * <p>The value represents the logical capacity, typically interpreted as a non-negative count of
   * slots. This parameter object does not enforce bounds or consistency; any validation is deferred
   * to the store implementation. The returned value is the exact long supplied at construction
   * time.
   *
   * @return the logical store capacity as a count of slots.
   */
  public long maxKeys() {
    return maxKeys;
  }

  /**
   * Returns whether the on-disk slot filter index is enabled.
   *
   * <p>When enabled, the store maintains a slot filter structure to speed up lookups. This flag is
   * stored verbatim and does not trigger any immediate initialization work in this parameter
   * object. Callers should use a consistent value when reopening the same store to avoid unexpected
   * behaviors during initialization.
   *
   * @return {@code true} to enable the slot filter index; {@code false} otherwise.
   */
  public boolean useSlotFilter() {
    return useSlotFilter;
  }

  /**
   * Returns the shutdown hook used to register store close tasks.
   *
   * <p>The hook reference is stored without validation or wrapping. Store creation may register a
   * close task on this hook during initialization, so callers should supply a suitable lifecycle
   * manager for their environment. This parameter object does not interact with the hook directly
   * and simply returns the stored reference.
   *
   * @return the shutdown hook reference associated with this configuration.
   */
  public SemiOrderedShutdownHook shutdownHook() {
    return shutdownHook;
  }

  /**
   * Returns whether store files should be pre-allocated up to the configured capacity.
   *
   * <p>Preallocation can reduce runtime fragmentation or startup latency by reserving space up
   * front, but may increase the time and disk I/O required for initial creation. This flag is
   * stored verbatim and does not cause any immediate side effects in this parameter object.
   *
   * @return {@code true} if the store should preallocate to its capacity.
   */
  public boolean preallocate() {
    return preallocate;
  }

  /**
   * Returns whether the store should finish any in-progress resize on startup.
   *
   * <p>When enabled, the store may complete a previous resize operation during initialization
   * before returning control to the caller. This flag is stored without validation and is
   * interpreted by the store implementation during construction and start-up. The parameter object
   * itself performs no resizing work.
   *
   * @return {@code true} to finish any in-progress resize during startup.
   */
  public boolean resizeOnStart() {
    return resizeOnStart;
  }

  /**
   * Returns the master key bytes used to derive per-store salts.
   *
   * <p>The returned array is the original reference provided at construction time; it is not copied
   * or zeroed. Callers must manage the lifetime, mutability, and secrecy of the array themselves.
   * Store implementations may read from this array during initialization or configuration loading,
   * so modifications after construction can affect later store behavior.
   *
   * @return the master key byte array reference as provided by the caller.
   */
  public byte[] masterKey() {
    return masterKey;
  }

  /**
   * Compares this parameter bundle to another object for equality.
   *
   * <p>Equality is defined by the stored configuration values: base directory, name, callback,
   * randomness source, capacity and flags, shutdown hook, and the content of the master key array.
   * The master key is compared using {@link Arrays#equals(byte[], byte[])} rather than reference
   * identity. This method is deterministic, side-effect-free, and returns {@code true} when the
   * other object is the same instance.
   *
   * @param other the candidate object to compare against, possibly {@code null}.
   * @return {@code true} when all stored fields represent the same configuration.
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof SaltedHashStoreParams<?> params)) return false;
    return maxKeys == params.maxKeys
        && useSlotFilter == params.useSlotFilter
        && preallocate == params.preallocate
        && resizeOnStart == params.resizeOnStart
        && Objects.equals(baseDir, params.baseDir)
        && Objects.equals(name, params.name)
        && Objects.equals(callback, params.callback)
        && Objects.equals(random, params.random)
        && Objects.equals(shutdownHook, params.shutdownHook)
        && Arrays.equals(masterKey, params.masterKey);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash is derived from all stored configuration fields, including the contents of the
   * master key array. This ensures that two equal parameter bundles produce the same hash code and
   * can be used reliably in hash-based collections. The computation does not mutate any referenced
   * objects and is safe to call repeatedly.
   *
   * @return a hash code representing the full store configuration.
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            baseDir,
            name,
            callback,
            random,
            maxKeys,
            useSlotFilter,
            shutdownHook,
            preallocate,
            resizeOnStart);
    result = 31 * result + Arrays.hashCode(masterKey);
    return result;
  }

  /**
   * Returns a human-readable description of the stored configuration.
   *
   * <p>The string includes the base directory, name, callback, randomness source, capacity, flags,
   * and shutdown hook values. The master key bytes are intentionally redacted to avoid accidental
   * disclosure in logs or debugging output. The returned string is intended for diagnostics and
   * does not imply that the referenced objects are safe to share or serialize.
   *
   * @return a descriptive string with sensitive key material redacted.
   */
  @Override
  public @NotNull String toString() {
    return "SaltedHashStoreParams[baseDir="
        + baseDir
        + ", name="
        + name
        + ", callback="
        + callback
        + ", random="
        + random
        + ", maxKeys="
        + maxKeys
        + ", useSlotFilter="
        + useSlotFilter
        + ", shutdownHook="
        + shutdownHook
        + ", preallocate="
        + preallocate
        + ", resizeOnStart="
        + resizeOnStart
        + ", masterKey=<redacted>"
        + "]";
  }

  /**
   * Creates a {@link SaltedHashStoreParams} instance from grouped inputs.
   *
   * <p>This factory mirrors the public constructor while emphasizing the three conceptual groups of
   * parameters: location, dependencies, and sizing. It performs no validation and preserves object
   * identity for inputs such as the {@code callback} and {@code masterKey} array; callers remain
   * responsible for ensuring those values remain valid for the lifetime of the store. The returned
   * instance is immutable and safe to reuse for repeated store creation when inputs are stable.
   *
   * <pre>{@code
   * SaltedHashStoreParams<CHKBlock> params = SaltedHashStoreParams.of(
   *     new SaltedHashStoreLocation(baseDir, "datastore"),
   *     new SaltedHashStoreDependencies<>(callback, random, shutdownHook, masterKey),
   *     new SaltedHashStoreSizing(maxKeys, true, false, true));
   * }</pre>
   *
   * <p>The returned parameter bundle is a pure data carrier and does not open or validate the store
   * directory; those responsibilities are handled by {@link SaltedHashFreenetStore}.
   *
   * @param <T> concrete {@link StorableBlock} type produced by the callback.
   * @param location filesystem and naming details for the store files and prefixes.
   * @param dependencies callback, randomness source, shutdown hook, and master key references.
   * @param sizing capacity and lifecycle sizing options for the store.
   * @return immutable parameters object encapsulating the provided configuration values.
   */
  public static <T extends StorableBlock> SaltedHashStoreParams<T> of(
      SaltedHashStoreLocation location,
      SaltedHashStoreDependencies<T> dependencies,
      SaltedHashStoreSizing sizing) {
    return new SaltedHashStoreParams<>(location, dependencies, sizing);
  }
}
