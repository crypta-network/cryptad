package network.crypta.config;

import network.crypta.support.Fields;
import network.crypta.support.api.IntCallback;

/**
 * Configuration option representing a bandwidth limit as an integer rate.
 *
 * <p>This class specializes {@link IntOption} for bandwidth values. It accepts human‑friendly size
 * forms (see {@link Fields#parseInt(String)}), and tolerates optional “per second” qualifiers such
 * as {@code "/s"}, {@code "/sec"}, and {@code "/second"}. Any per‑second qualifier is removed
 * before parsing so inputs like {@code "10MiB/s"} and {@code "8192b/s"} are interpreted correctly.
 * By default, values are treated as bytes; a trailing {@code 'b'} denotes bits and is converted to
 * bytes during parsing.
 *
 * <p>Display formatting follows {@link Dimension#SIZE} via {@link Fields#intToString(int,
 * Dimension)}, which prefers compact unit suffixes when evenly divisible. No global state is
 * modified; instances are safe for use by configuration UIs and loaders.
 *
 * @see Fields#trimPerSecond(String)
 * @see Fields#parseInt(String)
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
    this(conf, optionName, Fields.parseInt(defaultValueString), meta, cb);
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
    super(
        conf,
        optionName,
        defaultValue,
        meta.sortOrder(),
        meta.expert(),
        meta.forceWrite(),
        meta.shortDesc(),
        meta.longDesc(),
        cb,
        Dimension.SIZE);
  }

  /**
   * Parses user input after removing an optional per‑second qualifier.
   *
   * <p>Examples accepted by this option include {@code "2048"}, {@code "2MiB/s"}, and {@code
   * "8192b/s"}. The {@code /s} (or localized equivalent) is stripped via {@link
   * Fields#trimPerSecond(String)} before delegating to dimension‑aware parsing in the base class.
   *
   * @param val input string from configuration.
   * @return the parsed value in bytes per second.
   * @throws InvalidConfigValueException if the string cannot be parsed.
   */
  @Override
  protected Integer parseString(String val) throws InvalidConfigValueException {
    // Strip optional per‑second suffix, then parse using Dimension.SIZE rules.
    return super.parseString(Fields.trimPerSecond(val));
  }
}
