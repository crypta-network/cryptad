package network.crypta.support.api;

import java.util.function.BooleanSupplier;
import network.crypta.config.ConfigCallback;
import network.crypta.config.ConfigConsumer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;

/**
 * Deprecated compatibility bridge for the callback package move to {@code network.crypta.config}.
 *
 * @deprecated Use {@link network.crypta.config.BooleanCallback}. Retained to preserve source and
 *     binary compatibility for existing {@code foundation-config} consumers.
 */
@Deprecated
public abstract class BooleanCallback extends ConfigCallback<Boolean> {

  /**
   * Creates a compatibility callback that delegates to the supplied functions.
   *
   * @deprecated Use {@link network.crypta.config.BooleanCallback#from(BooleanSupplier,
   *     ConfigConsumer)}.
   */
  @Deprecated
  public static BooleanCallback from(BooleanSupplier get, ConfigConsumer<Boolean> set) {
    return new network.crypta.config.BooleanCallback() {

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
