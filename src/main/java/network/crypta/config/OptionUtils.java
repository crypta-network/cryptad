package network.crypta.config;

/** Utility helpers for working with typed {@link Option} instances. */
public final class OptionUtils {

  private OptionUtils() {}

  /**
   * Returns a numeric {@code Option<Long>} from the provided {@link SubConfig} by key.
   *
   * <p>Performs a runtime {@link Option.DataType} check before doing a localized unchecked cast.
   */
  @SuppressWarnings("unchecked")
  public static Option<Long> longOption(SubConfig subConfig, String key) {
    Option<?> opt = subConfig.getOption(key);
    if (opt.getDataType() != Option.DataType.NUMBER) {
      throw new ClassCastException("Option '" + key + "' is not numeric: " + opt.getDataType());
    }
    return (Option<Long>) opt;
  }
}
