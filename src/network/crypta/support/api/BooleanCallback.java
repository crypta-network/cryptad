/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.support.api;

import java.util.function.Supplier;

import network.crypta.config.ConfigCallback;
import network.crypta.config.ConfigConsumer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;

/**
 * A callback to be called when a config value of integer type changes.
 * Also reports the current value.
 */
public abstract class BooleanCallback extends ConfigCallback<Boolean> {

  /**
   * Create a config callback from lambdas.
   *
   * @param set accepts the new value.
   */
  public static BooleanCallback from(Supplier<Boolean> get, ConfigConsumer<Boolean> set) {
    return new BooleanCallback() {

      @Override
      public Boolean get() {
        return get.get();
      }

      @Override
      public void set(Boolean value) throws InvalidConfigValueException, NodeNeedRestartException {
        set.accept(value);
      }
    };
  }
}
