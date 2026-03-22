package network.crypta.config;

import network.crypta.l10n.NodeL10n;

/**
 * Integer-backed configuration option with optional unit/duration semantics.
 *
 * <p>This option stores an {@link Integer} and can interpret and format values according to a
 * {@link Dimension}:
 *
 * <ul>
 *   <li>{@link Dimension#NOT}: treat the value as a plain number.
 *   <li>{@link Dimension#SIZE}: allow human-friendly size suffixes when parsing and prefer compact
 *       IEC/SI forms when formatting.
 *   <li>{@link Dimension#DURATION}: parse durations (via {@code TimeUtil}) and format as a
 *       human-readable time span.
 * </ul>
 *
 * <p>Parsing is locale-agnostic and tolerant: when a dimension-aware parse fails, the code falls
 * back to parsing a plain integer to preserve historical behavior and interoperability with
 * existing configuration files.
 */
public class IntOption extends Option<Integer> {
  private final Dimension dimension;

  /**
   * Creates an integer option whose default value is provided as text.
   *
   * @param conf owning sub-configuration.
   * @param optionName stable key used to persist and retrieve the option.
   * @param defaultValueString textual default; interpreted using {@code dimension}.
   * @param meta option metadata (sort order, expert flag, descriptions).
   * @param cb callback invoked on value change; may be {@code null} when no side effect is needed.
   * @param dimension interpretation of numeric text and preferred display format.
   */
  public IntOption(
      SubConfig conf,
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      IntCallback cb,
      Dimension dimension) {
    this(
        conf,
        optionName,
        parseString(defaultValueString, dimension),
        meta,
        (ConfigCallback<Integer>) cb,
        dimension);
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #IntOption(SubConfig, String, String, Option.Meta,
   *     network.crypta.config.IntCallback, Dimension)}.
   */
  @Deprecated
  public IntOption(
      SubConfig conf,
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      network.crypta.support.api.IntCallback cb,
      Dimension dimension) {
    this(
        conf,
        optionName,
        parseString(defaultValueString, dimension),
        meta,
        (ConfigCallback<Integer>) cb,
        dimension);
  }

  /**
   * Creates an integer option with a typed default value.
   *
   * @param conf owning sub-configuration.
   * @param optionName stable key used to persist and retrieve the option.
   * @param defaultValue default value stored as an {@link Integer}.
   * @param meta option metadata (sort order, expert flag, descriptions).
   * @param cb callback invoked on value change; may be {@code null} when no side effect is needed.
   * @param dimension interpretation of numeric text and preferred display format.
   */
  public IntOption(
      SubConfig conf,
      String optionName,
      Integer defaultValue,
      Option.Meta meta,
      IntCallback cb,
      Dimension dimension) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Integer>) cb, dimension);
  }

  IntOption(
      SubConfig conf,
      String optionName,
      Integer defaultValue,
      Option.Meta meta,
      ConfigCallback<Integer> cb,
      Dimension dimension) {
    super(conf, optionName, cb, meta, Option.DataType.NUMBER);
    this.defaultValue = defaultValue;
    this.currentValue = defaultValue;
    this.dimension = dimension;
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #IntOption(SubConfig, String, Integer, Option.Meta,
   *     network.crypta.config.IntCallback, Dimension)}.
   */
  @Deprecated
  public IntOption(
      SubConfig conf,
      String optionName,
      Integer defaultValue,
      Option.Meta meta,
      network.crypta.support.api.IntCallback cb,
      Dimension dimension) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Integer>) cb, dimension);
  }

  /**
   * Parses textual input into an {@link Integer} using the configured {@link Dimension}.
   *
   * <p>On failure, the method falls back to a plain integer parse (equivalent to {@link
   * Dimension#NOT}). If parsing still fails, a localized error message is returned via {@link
   * InvalidConfigValueException}.
   *
   * @param val input string from configuration.
   * @return the parsed value.
   * @throws InvalidConfigValueException if the string cannot be parsed.
   */
  @Override
  protected Integer parseString(String val) throws InvalidConfigValueException {
    try {
      return parseString(val, dimension);
    } catch (NumberFormatException _) {
      throw new InvalidConfigValueException(l10nParseError(val));
    }
  }

  // Parse either a dimension-aware or a plain integer form. If the dimension-aware parse fails,
  // fall back to {@code Dimension.NOT} to maintain compatibility with existing config files.
  private static Integer parseString(String val, Dimension dimension) throws NumberFormatException {
    try {
      return DimensionValueSupport.parseInt(val, dimension);
    } catch (NumberFormatException _) {
      return DimensionValueSupport.parseInt(val, Dimension.NOT);
    }
  }

  private static final String PARSE_ERROR_KEY = "IntOption.parseError";
  private static final String VAL_PATTERN = "val";

  /** Returns a localized parse error string for display in UIs and logs. */
  private String l10nParseError(String value) {
    return NodeL10n.getBase().getString(PARSE_ERROR_KEY, VAL_PATTERN, value);
  }

  /**
   * Converts a value to user-facing text using the configured {@link Dimension}.
   *
   * <p>For example, durations are formatted as time spans and sizes may use compact unit suffixes
   * when evenly divisible.
   *
   * @param val value to format; never {@code null}.
   * @return formatted string for UI display.
   */
  @Override
  protected String toDisplayString(Integer val) {
    return DimensionValueSupport.intToString(val, dimension);
  }

  /**
   * Converts a value to a stable, non-localized string suitable for persistence.
   *
   * <p>This preserves the historical dimensionless formatting path used by configuration files and
   * APIs.
   *
   * @param val value to encode; never {@code null}.
   * @return non-localized persistence string.
   */
  @Override
  protected String toString(Integer val) {
    return DimensionValueSupport.intToString(val, Dimension.NOT);
  }
}
