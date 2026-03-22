package network.crypta.config;

/**
 * Configuration option representing a bandwidth limit as an integer rate.
 *
 * <p>This class specializes {@link IntOption} for bandwidth values. It accepts human-friendly size
 * forms and tolerates optional per-second qualifiers such as {@code "/s"}, {@code "/sec"}, and
 * {@code "/second"}. Any per-second qualifier is removed before parsing so inputs like {@code
 * "10MiB/s"} and {@code "8192b/s"} are interpreted correctly. By default, values are treated as
 * bytes; a trailing {@code 'b'} denotes bits and is converted to bytes during parsing.
 *
 * <p>Display formatting follows {@link Dimension#SIZE}, which prefers compact unit suffixes when
 * evenly divisible. No global state is modified; instances are safe for use by configuration UIs
 * and loaders.
 */
public class BandwidthOption extends IntOption {
  /**
   * Creates a bandwidth option whose default value is provided as text.
   *
   * <p>The textual default may include size suffixes and an optional per‑second qualifier; the
   * latter is ignored during parsing.
   *
   * @param conf owning sub‑configuration.
   * @param optionName stable key used to persist and retrieve the option.
   * @param defaultValueString textual default; interpreted as a size and converted to bytes.
   * @param meta option metadata (sort order, expert flag, descriptions).
   * @param cb callback invoked on value change; may be {@code null} when no side effect is needed.
   */
  public BandwidthOption(
      SubConfig conf,
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      IntCallback cb) {
    this(
        conf,
        optionName,
        parseDefaultValue(defaultValueString),
        meta,
        (ConfigCallback<Integer>) cb);
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #BandwidthOption(SubConfig, String, String, Option.Meta,
   *     network.crypta.config.IntCallback)}.
   */
  @Deprecated
  public BandwidthOption(
      SubConfig conf,
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      network.crypta.support.api.IntCallback cb) {
    this(
        conf,
        optionName,
        parseDefaultValue(defaultValueString),
        meta,
        LegacyCallbackAdapters.adapt(cb));
  }

  /**
   * Creates a bandwidth option with a typed default value.
   *
   * @param conf owning sub‑configuration.
   * @param optionName stable key used to persist and retrieve the option.
   * @param defaultValue default value in bytes per second.
   * @param meta option metadata (sort order, expert flag, descriptions).
   * @param cb callback invoked on value change; may be {@code null} when no side effect is needed.
   */
  public BandwidthOption(
      SubConfig conf, String optionName, Integer defaultValue, Option.Meta meta, IntCallback cb) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Integer>) cb);
  }

  private BandwidthOption(
      SubConfig conf,
      String optionName,
      Integer defaultValue,
      Option.Meta meta,
      ConfigCallback<Integer> cb) {
    super(conf, optionName, defaultValue, meta, cb, Dimension.SIZE);
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #BandwidthOption(SubConfig, String, Integer, Option.Meta,
   *     network.crypta.config.IntCallback)}.
   */
  @Deprecated
  public BandwidthOption(
      SubConfig conf,
      String optionName,
      Integer defaultValue,
      Option.Meta meta,
      network.crypta.support.api.IntCallback cb) {
    this(conf, optionName, defaultValue, meta, LegacyCallbackAdapters.adapt(cb));
  }

  /**
   * Parses user input after removing an optional per‑second qualifier.
   *
   * <p>Examples accepted by this option include {@code "2048"}, {@code "2MiB/s"}, and {@code
   * "8192b/s"}. The {@code /s} (or localized equivalent) is stripped before delegating to
   * dimension-aware parsing in the base class.
   *
   * @param val input string from configuration.
   * @return the parsed value in bytes per second.
   * @throws InvalidConfigValueException if the string cannot be parsed.
   */
  @Override
  protected Integer parseString(String val) throws InvalidConfigValueException {
    return super.parseString(DimensionValueSupport.trimPerSecond(val));
  }

  private static int parseDefaultValue(String defaultValueString) {
    return DimensionValueSupport.parseInt(
        DimensionValueSupport.trimPerSecond(defaultValueString), Dimension.SIZE);
  }
}
