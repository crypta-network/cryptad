package network.crypta.store.saltedhash;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import org.jetbrains.annotations.NotNull;

/// Parameters required to construct a salted-hash store instance.
///
/// This record bundles the full initialization surface used by [SaltedHashFreenetStore]
/// factories, ensuring callers can pass around a single value object without losing
/// configurability.
/// It is intended for code that wires stores from configuration files or dependency injection,
/// where
/// keeping related arguments together avoids long parameter lists and makes auditing easier. The
/// values are treated as immutable once created; callers should construct a new instance to change
/// any option or to target a different store directory.
///
/// The record is a pure data carrier: it does not validate the filesystem, does not read the
/// store, and does not mutate the referenced [StoreCallback]. The caller
/// manages the lifetime of the referenced objects. Use this object to keep the construction inputs
/// in sync between
/// primary and alternate stores, or to cache a template of initialization values for repeated store
/// creation.
///
///     - Captures filesystem and naming details for the store files.
///     - Captures crypto and sizing inputs that must be consistent across runs.
///     - Captures lifecycle wiring such as shutdown hooks and preallocation policy.
///
///
/// @param <T> concrete [StorableBlock] type produced by the callback.
/// @param baseDir directory where the store files live; created if missing by the store.
/// @param name logical name; also used as a filename prefix for store files.
/// @param callback callback used to get header/data lengths and to (de-)serialize blocks.
/// @param random randomness source for encryption and placement tie-breakers.
/// @param maxKeys number of slots in the store (capacity), treated as a non-negative count.
/// @param useSlotFilter whether to enable the on-disk slot filter index for lookups.
/// @param shutdownHook hook on which the store registers a close task during initialization.
/// @param preallocate whether to preallocate files up to `maxKeys` for startup latency.
/// @param resizeOnStart when true, finishes any in-progress resize before returning to the caller.
/// @param masterKey master key used to derive per-store salts; reference copies contents.
public record SaltedHashStoreParams<T extends StorableBlock>(
    File baseDir,
    String name,
    StoreCallback<T> callback,
    Random random,
    long maxKeys,
    boolean useSlotFilter,
    SemiOrderedShutdownHook shutdownHook,
    boolean preallocate,
    boolean resizeOnStart,
    byte[] masterKey) {

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other
        instanceof
        SaltedHashStoreParams(
            File otherBaseDir,
            String otherName,
            StoreCallback<?> otherCallback,
            Random otherRandom,
            long otherMaxKeys,
            boolean otherUseSlotFilter,
            SemiOrderedShutdownHook otherShutdownHook,
            boolean otherPreallocate,
            boolean otherResizeOnStart,
            byte[] otherMasterKey))) return false;
    return maxKeys == otherMaxKeys
        && useSlotFilter == otherUseSlotFilter
        && preallocate == otherPreallocate
        && resizeOnStart == otherResizeOnStart
        && Objects.equals(baseDir, otherBaseDir)
        && Objects.equals(name, otherName)
        && Objects.equals(callback, otherCallback)
        && Objects.equals(random, otherRandom)
        && Objects.equals(shutdownHook, otherShutdownHook)
        && Arrays.equals(masterKey, otherMasterKey);
  }

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
   * Creates a {@link SaltedHashStoreParams} instance from discrete inputs.
   *
   * <p>This factory mirrors the record components so callers can migrate from older constructor
   * signatures without manually repeating the type name. It performs no validation and preserves
   * object identity for inputs such as {@code callback} and {@code masterKey}; callers remain
   * responsible for ensuring those values remain valid for the lifetime of the store. The returned
   * instance is immutable and safe to reuse for repeated store creation when inputs are stable.
   *
   * <pre>{@code
   * SaltedHashStoreParams<CHKBlock> params = SaltedHashStoreParams.of(
   *     baseDir,
   *     "datastore",
   *     callback,
   *     random,
   *     maxKeys,
   *     true,
   *     shutdownHook,
   *     false,
   *     true,
   *     masterKey);
   * }</pre>
   *
   * @param <T> concrete {@link StorableBlock} type produced by the callback.
   * @param baseDir directory where the store files live; created if missing by the store.
   * @param name logical name; also used as a filename prefix for store files.
   * @param callback callback used to get header/data lengths and to (de-)serialize blocks.
   * @param random randomness source for encryption and placement tie-breakers.
   * @param maxKeys number of slots in the store (capacity), treated as a non-negative count.
   * @param useSlotFilter whether to enable the on-disk slot filter index for lookups.
   * @param shutdownHook hook on which the store registers a close task during initialization.
   * @param preallocate whether to preallocate files up to {@code maxKeys} for startup latency.
   * @param resizeOnStart when true, finishes any in-progress resize before returning to the caller.
   * @param masterKey master key used to derive per-store salts; reference copies contents.
   * @return immutable parameters object encapsulating the provided store configuration values.
   */
  public static <T extends StorableBlock> SaltedHashStoreParams<T> of(
      File baseDir,
      String name,
      StoreCallback<T> callback,
      Random random,
      long maxKeys,
      boolean useSlotFilter,
      SemiOrderedShutdownHook shutdownHook,
      boolean preallocate,
      boolean resizeOnStart,
      byte[] masterKey) {
    return new SaltedHashStoreParams<>(
        baseDir,
        name,
        callback,
        random,
        maxKeys,
        useSlotFilter,
        shutdownHook,
        preallocate,
        resizeOnStart,
        masterKey);
  }
}
