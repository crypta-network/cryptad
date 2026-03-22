package network.crypta.config;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.Fields;

/**
 * Option representing a {@link Long} configuration value.
 *
 * <p>This option parses textual input using {@link Fields#parseLong(String)}, which accepts plain
 * numbers as well as quantities with SI/IEC suffixes (e.g., {@code 10k}, {@code 4M}, {@code 2GiB}).
 * Invalid inputs are reported as {@link InvalidConfigValueException}s with a localized message.
 *
 * <p>Formatting distinguishes between persistence and display:
 *
 * <ul>
 *   <li>{@link #toString(Long)} returns a canonical form suitable for config files and APIs. It
 *       uses plain numbers or SI multiples of 1000 when an even division exists (e.g., {@code 2000
 *       -> "2k"}).
 *   <li>{@link #toDisplayString(Long)} uses {@code isSize} to decide whether IEC units may be shown
 *       for human‑readable output (e.g., {@code 2048 -> "2KiB"} when {@code isSize} is {@code
 *       true}).
 * </ul>
 */
public class LongOption extends Option<Long> {
  /**
   * When {@code true}, display formatting may use IEC size suffixes (e.g., {@code KiB}, {@code
   * MiB}). When {@code false}, only SI multiples of 1000 are considered for compact forms.
   */
  protected final boolean isSize;

  /**
   * Constructs a long option with a string default.
   *
   * <p>The {@code defaultValueString} is parsed via {@link Fields#parseLong(String)}. See that
   * method for the accepted syntax and units.
   *
   * @param conf Owning {@link SubConfig}.
   * @param optionName Canonical option name within {@code conf}.
   * @param defaultValueString Default value in text form.
   * @param meta Presentation and ordering metadata.
   * @param cb Callback used to read/apply values.
   * @param isSize Enables IEC size formatting for display when {@code true}.
   */
  public LongOption(
      SubConfig conf,
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      LongCallback cb,
      boolean isSize) {
    this(
        conf,
        optionName,
        Fields.parseLong(defaultValueString),
        meta,
        (ConfigCallback<Long>) cb,
        isSize);
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #LongOption(SubConfig, String, String, Option.Meta,
   *     network.crypta.config.LongCallback, boolean)}.
   */
  @Deprecated
  public LongOption(
      SubConfig conf,
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      network.crypta.support.api.LongCallback cb,
      boolean isSize) {
    this(
        conf,
        optionName,
        Fields.parseLong(defaultValueString),
        meta,
        (ConfigCallback<Long>) cb,
        isSize);
  }

  /**
   * Constructs a long option with a typed default.
   *
   * @param conf Owning {@link SubConfig}.
   * @param optionName Canonical option name within {@code conf}.
   * @param defaultValue Default numeric value.
   * @param meta Presentation and ordering metadata.
   * @param cb Callback used to read/apply values.
   * @param isSize Enables IEC size formatting for display when {@code true}.
   */
  public LongOption(
      SubConfig conf,
      String optionName,
      Long defaultValue,
      Option.Meta meta,
      LongCallback cb,
      boolean isSize) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Long>) cb, isSize);
  }

  private LongOption(
      SubConfig conf,
      String optionName,
      Long defaultValue,
      Option.Meta meta,
      ConfigCallback<Long> cb,
      boolean isSize) {
    super(conf, optionName, cb, meta, Option.DataType.NUMBER);
    this.defaultValue = defaultValue;
    this.currentValue = defaultValue;
    this.isSize = isSize;
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #LongOption(SubConfig, String, Long, Option.Meta,
   *     network.crypta.config.LongCallback, boolean)}.
   */
  @Deprecated
  public LongOption(
      SubConfig conf,
      String optionName,
      Long defaultValue,
      Option.Meta meta,
      network.crypta.support.api.LongCallback cb,
      boolean isSize) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Long>) cb, isSize);
  }

  /**
   * Parses a long value from text.
   *
   * <p>Delegates to {@link Fields#parseLong(String)} and converts any parse failure into an {@link
   * InvalidConfigValueException} with a localized message.
   *
   * @param val Textual representation (supports SI/IEC suffixes).
   * @return Parsed {@link Long} value.
   * @throws InvalidConfigValueException if the input cannot be parsed.
   */
  @Override
  protected Long parseString(String val) throws InvalidConfigValueException {
    // Delegate to Fields to keep parsing consistent across the codebase (supports SI/IEC suffixes
    // and decimal multipliers). Convert any format errors into a localized config exception.
    long x;
    try {
      x = Fields.parseLong(val);
    } catch (NumberFormatException _) {
      throw new InvalidConfigValueException(parseErrorMessage(val));
    }
    return x;
  }

  /** Returns a localized parse error message for the given invalid value. */
  private String parseErrorMessage(String value) {
    return NodeL10n.getBase().getString("LongOption.parseError", "val", value);
  }

  /**
   * Formats a value for end‑user display.
   *
   * @param val Value to format.
   * @return Human‑readable string; may include IEC units when {@code isSize} is {@code true}.
   */
  @Override
  protected String toDisplayString(Long val) {
    // Human‑readable form; may use IEC units when isSize is true.
    return Fields.longToString(val, isSize);
  }

  /**
   * Formats a value for persistence and APIs.
   *
   * @param val Value to format.
   * @return Canonical form using plain numbers or SI multiples.
   */
  @Override
  protected String toString(Long val) {
    // Canonical/persistence form; restricts to plain numbers or SI multiples.
    return Fields.longToString(val, false);
  }
}
