package network.crypta.config;

import network.crypta.l10n.NodeL10n;

/**
 * Configuration option representing a boolean value.
 *
 * <p>This type provides parsing and formatting for {@code true}/{@code false} values and accepts
 * common synonyms when parsing ("yes"/"no", case-insensitive). Error messages are localized via
 * {@link NodeL10n}. All life-cycle, threading, and initialization semantics follow those of the
 * base {@link Option} class.
 */
public class BooleanOption extends Option<Boolean> {

  /**
   * Creates a boolean option with the given metadata and callback.
   *
   * <p>The option's declared data type is {@link Option.DataType#BOOLEAN}. Upon construction the
   * {@code defaultValue} is stored as both the default and the initial current value; no callback
   * invocation occurs here.
   *
   * @param conf owning {@link SubConfig}; typically non-null for registered options
   * @param optionName canonical name used in config files and APIs
   * @param defaultValue default and initial value
   * @param meta descriptive and ordering metadata for the option
   * @param cb callback used to read/apply values
   */
  public BooleanOption(
      SubConfig conf,
      String optionName,
      boolean defaultValue,
      Option.Meta meta,
      BooleanCallback cb) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Boolean>) cb);
  }

  private BooleanOption(
      SubConfig conf,
      String optionName,
      boolean defaultValue,
      Option.Meta meta,
      ConfigCallback<Boolean> cb) {
    super(conf, optionName, cb, meta, Option.DataType.BOOLEAN);
    this.defaultValue = defaultValue;
    this.currentValue = defaultValue;
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #BooleanOption(SubConfig, String, boolean, Option.Meta,
   *     network.crypta.config.BooleanCallback)}.
   */
  @Deprecated
  public BooleanOption(
      SubConfig conf,
      String optionName,
      boolean defaultValue,
      Option.Meta meta,
      network.crypta.support.api.BooleanCallback cb) {
    this(conf, optionName, defaultValue, meta, LegacyCallbackAdapters.adapt(cb));
  }

  /**
   * Parses a textual boolean.
   *
   * <p>Accepted values are {@code "true"} and {@code "false"}, as well as the synonyms {@code
   * "yes"} and {@code "no"}. Matching is case-insensitive.
   *
   * @param val text to parse; must be non-null
   * @return {@code true} or {@code false} according to {@code val}
   * @throws OptionFormatException if {@code val} is not a recognized boolean token; the message is
   *     localized through {@link NodeL10n}
   */
  @Override
  public Boolean parseString(String val) throws InvalidConfigValueException {
    if (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("yes")) {
      return true;
    } else if (val.equalsIgnoreCase("false") || val.equalsIgnoreCase("no")) {
      return false;
    } else
      throw new OptionFormatException(
          NodeL10n.getBase().getString("BooleanOption.parseError", "val", val));
  }

  /**
   * Formats a boolean as its canonical lowercase string.
   *
   * @param val value to format; typically non-null
   * @return {@code "true"} or {@code "false"}
   */
  @Override
  protected String toString(Boolean val) {
    return val.toString();
  }
}
