package network.crypta.config;

/**
 * Adapts deprecated legacy callback instances into canonical config-package callback types.
 *
 * <p>The package move needs both directions of runtime compatibility:
 *
 * <ul>
 *   <li>new callbacks must still be visible as deprecated {@code support.api} types
 *   <li>deprecated overloads must return callbacks that are also visible as new {@code
 *       network.crypta.config} types
 * </ul>
 *
 * <p>The public bridge hierarchy handles the first case. These adapters handle the second by
 * wrapping pure legacy callback implementations in new-package callback subclasses when deprecated
 * constructors or overloads are used.
 */
@SuppressWarnings("deprecation")
final class LegacyCallbackAdapters {

  private LegacyCallbackAdapters() {}

  static BooleanCallback adapt(network.crypta.support.api.BooleanCallback callback) {
    if (callback == null) {
      return null;
    }
    if (callback instanceof BooleanCallback adapted) {
      return adapted;
    }
    return new BooleanCallback() {
      @Override
      public Boolean get() {
        return callback.get();
      }

      @Override
      public void set(Boolean value) throws InvalidConfigValueException, NodeNeedRestartException {
        callback.set(value);
      }

      @Override
      public boolean isReadOnly() {
        return callback.isReadOnly();
      }
    };
  }

  static IntCallback adapt(network.crypta.support.api.IntCallback callback) {
    if (callback == null) {
      return null;
    }
    if (callback instanceof IntCallback adapted) {
      return adapted;
    }
    return new IntCallback() {
      @Override
      public Integer get() {
        return callback.get();
      }

      @Override
      public void set(Integer value) throws InvalidConfigValueException, NodeNeedRestartException {
        callback.set(value);
      }

      @Override
      public boolean isReadOnly() {
        return callback.isReadOnly();
      }
    };
  }

  static LongCallback adapt(network.crypta.support.api.LongCallback callback) {
    if (callback == null) {
      return null;
    }
    if (callback instanceof LongCallback adapted) {
      return adapted;
    }
    return new LongCallback() {
      @Override
      public Long get() {
        return callback.get();
      }

      @Override
      public void set(Long value) throws InvalidConfigValueException, NodeNeedRestartException {
        callback.set(value);
      }

      @Override
      public boolean isReadOnly() {
        return callback.isReadOnly();
      }
    };
  }

  static ShortCallback adapt(network.crypta.support.api.ShortCallback callback) {
    if (callback == null) {
      return null;
    }
    if (callback instanceof ShortCallback adapted) {
      return adapted;
    }
    return new ShortCallback() {
      @Override
      public Short get() {
        return callback.get();
      }

      @Override
      public void set(Short value) throws InvalidConfigValueException, NodeNeedRestartException {
        callback.set(value);
      }

      @Override
      public boolean isReadOnly() {
        return callback.isReadOnly();
      }
    };
  }

  static StringCallback adapt(network.crypta.support.api.StringCallback callback) {
    if (callback == null) {
      return null;
    }
    if (callback instanceof StringCallback adapted) {
      return adapted;
    }
    return new StringCallback() {
      @Override
      public String get() {
        return callback.get();
      }

      @Override
      public void set(String value) throws InvalidConfigValueException, NodeNeedRestartException {
        callback.set(value);
      }

      @Override
      public boolean isReadOnly() {
        return callback.isReadOnly();
      }
    };
  }

  static StringArrCallback adapt(network.crypta.support.api.StringArrCallback callback) {
    if (callback == null) {
      return null;
    }
    if (callback instanceof StringArrCallback adapted) {
      return adapted;
    }
    return new StringArrCallback() {
      @Override
      public String[] get() {
        return callback.get();
      }

      @Override
      public void set(String[] value) throws InvalidConfigValueException, NodeNeedRestartException {
        callback.set(value);
      }

      @Override
      public boolean isReadOnly() {
        return callback.isReadOnly();
      }
    };
  }
}
