package network.crypta.config;

import java.util.function.BooleanSupplier;

/**
 * Callback for reading and writing a boolean configuration value.
 *
 * <p>This specialization of {@link ConfigCallback} is the canonical boolean callback type for new
 * code in {@code :foundation-config}. It is used by option implementations such as {@link
 * BooleanOption} and by configuration owners that register boolean settings through {@link
 * SubConfig}. Implementations provide the current effective value via {@link ConfigCallback#get()}
 * and accept a new value via {@link ConfigCallback#set(Object)}.
 *
 * <p>The class currently extends the deprecated bridge in {@link
 * network.crypta.support.api.BooleanCallback}. That arrangement keeps callback objects assignable
 * through both package names while the codebase migrates toward {@code network.crypta.config}.
 * Callers adding new APIs should use this type directly. Existing consumers compiled against the
 * legacy package continue to observe compatible runtime types.
 *
 * <p>Details:
 *
 * <ul>
 *   <li><strong>Purpose:</strong> reflect and apply a boolean configuration flag.
 *   <li><strong>Inputs/outputs:</strong> {@link ConfigCallback#get()} returns the current value;
 *       {@link ConfigCallback#set(Object)} receives the requested new value.
 *   <li><strong>Preconditions:</strong> provided values are expected to be non-{@code null}.
 *   <li><strong>Postconditions:</strong> if {@link ConfigCallback#set(Object)} returns normally,
 *       the value is accepted; some implementations may defer activation until a restart.
 *   <li><strong>Side effects:</strong> implementations may persist to disk and/or perform
 *       validation.
 *   <li><strong>Threading:</strong> this type defines no synchronization; thread-safety depends on
 *       concrete implementations.
 * </ul>
 */
@SuppressWarnings("deprecation")
public abstract class BooleanCallback extends network.crypta.support.api.BooleanCallback {

  /**
   * Creates a boolean callback base instance.
   *
   * <p>This constructor performs no initialization. Concrete implementations usually appear as
   * anonymous classes, dedicated callback implementations, or singleton adapters registered through
   * {@link SubConfig}. It remains public to preserve the access level of the implicit constructor
   * that existed before the package move.
   */
  public BooleanCallback() {}

  /**
   * Creates a callback that delegates to the supplied functions.
   *
   * <p>The returned instance delegates {@link ConfigCallback#get()} to {@link
   * BooleanSupplier#getAsBoolean()} and {@link ConfigCallback#set(Object)} to {@link
   * ConfigConsumer#accept(Object)}. No caching or additional validation occurs in this adapter.
   *
   * <p>Preconditions: {@code get} and {@code set} must be non-{@code null}. The {@code value}
   * passed to {@link ConfigCallback#set(Object)} is expected to be non-{@code null}.
   *
   * @param get supplies the current effective value.
   * @param set accepts and applies a new value.
   * @return a {@link BooleanCallback} that delegates to the provided functions.
   */
  public static BooleanCallback from(BooleanSupplier get, ConfigConsumer<Boolean> set) {
    // Delegate directly to the provided supplier/consumer; this adapter adds no caching.
    return new BooleanCallback() {

      @Override
      public Boolean get() {
        return get.getAsBoolean();
      }

      @Override
      public void set(Boolean value) throws InvalidConfigValueException, NodeNeedRestartException {
        set.accept(value);
      }
    };
  }
}
