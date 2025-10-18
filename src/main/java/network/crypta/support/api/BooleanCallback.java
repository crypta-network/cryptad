package network.crypta.support.api;

import java.util.function.BooleanSupplier;
import network.crypta.config.ConfigCallback;
import network.crypta.config.ConfigConsumer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;

/**
 * Callback for reading and writing a boolean configuration value.
 *
 * <p>This specialization of {@link ConfigCallback} is used by components that expose a boolean
 * setting. Implementations provide the current effective value via {@link #get()} and accept a new
 * value via {@link #set(Boolean)}.
 *
 * <p>Details:
 *
 * <ul>
 *   <li><strong>Purpose:</strong> reflect and apply a boolean configuration flag.
 *   <li><strong>Inputs/outputs:</strong> {@link #get()} returns the current value; {@link
 *       #set(Boolean)} receives the requested new value.
 *   <li><strong>Preconditions:</strong> provided values are expected to be non-{@code null}.
 *   <li><strong>Postconditions:</strong> if {@link #set(Boolean)} returns normally, the value is
 *       accepted; some implementations may defer activation until a restart.
 *   <li><strong>Side effects:</strong> implementations may persist to disk and/or perform
 *       validation.
 *   <li><strong>Threading:</strong> no synchronization is defined by this type; thread-safety
 *       depends on concrete implementations.
 * </ul>
 */
public abstract class BooleanCallback extends ConfigCallback<Boolean> {

  /**
   * Creates a callback that delegates to the supplied functions.
   *
   * <p>The returned instance delegates {@link #get()} to {@link BooleanSupplier#getAsBoolean()} and
   * {@link #set(Boolean)} to {@link ConfigConsumer#accept(Object)}. No caching or additional
   * validation occurs in this adapter.
   *
   * <p>Preconditions: {@code get} and {@code set} must be non-{@code null}. The {@code value}
   * passed to {@link #set(Boolean)} is expected to be non-{@code null}.
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
