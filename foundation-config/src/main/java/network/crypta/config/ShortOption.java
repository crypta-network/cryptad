package network.crypta.config;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.Fields;

/**
 * Configuration option that stores a {@link Short} value.
 *
 * <p>This implementation parses textual input into a 16-bit signed integer and provides two string
 * representations:
 *
 * <ul>
 *   <li>{@link #toDisplayString(Short)} — human‑readable, optionally formatted as a size (e.g.,
 *       using units) when {@code isSize} is enabled.
 *   <li>{@link #toString(Short)} — canonical form intended for serialization and config files,
 *       without size formatting.
 * </ul>
 *
 * <p>Error messages for invalid input are localized via {@link NodeL10n}.
 */
public class ShortOption extends Option<Short> {
  /**
   * When {@code true}, display formatting treats the value as a byte size for {@link
   * #toDisplayString(Short)}; parsing and canonical {@link #toString(Short)} are unaffected.
   */
  protected final boolean isSize;

  /**
   * Creates a short-valued configuration option.
   *
   * @param conf the owning configuration section
   * @param optionName unique key within {@code conf}
   * @param defaultValue value used when no explicit value is set
   * @param meta option metadata (ordering, expert flag, descriptions)
   * @param cb optional callback invoked when the value changes
   * @param isSize whether display formatting should treat values as sizes
   */
  public ShortOption(
      SubConfig conf,
      String optionName,
      short defaultValue,
      Option.Meta meta,
      ShortCallback cb,
      boolean isSize) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Short>) cb, isSize);
  }

  private ShortOption(
      SubConfig conf,
      String optionName,
      short defaultValue,
      Option.Meta meta,
      ConfigCallback<Short> cb,
      boolean isSize) {
    super(conf, optionName, cb, meta, Option.DataType.NUMBER);
    this.defaultValue = defaultValue;
    this.currentValue = defaultValue;
    this.isSize = isSize;
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #ShortOption(SubConfig, String, short, Option.Meta,
   *     network.crypta.config.ShortCallback, boolean)}.
   */
  @Deprecated
  public ShortOption(
      SubConfig conf,
      String optionName,
      short defaultValue,
      Option.Meta meta,
      network.crypta.support.api.ShortCallback cb,
      boolean isSize) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<Short>) cb, isSize);
  }

  /** Builds a localized error message for an unparseable short value. */
  private String unrecognisedShortMessage(String value) {
    return NodeL10n.getBase().getString("ShortOption.unrecognisedShort", "val", value);
  }

  /**
   * Parses a textual value to a {@link Short}.
   *
   * <p>On failure, a localized message is provided.
   *
   * @param val source text
   * @return parsed short value
   * @throws InvalidConfigValueException if the text cannot be parsed as a short
   */
  @Override
  protected Short parseString(String val) throws InvalidConfigValueException {
    short x;
    try {
      x = Fields.parseShort(val);
    } catch (NumberFormatException _) {
      throw new InvalidConfigValueException(unrecognisedShortMessage(val));
    }
    return x;
  }

  /**
   * Returns a human‑readable representation for UI display.
   *
   * <p>When {@code isSize} is {@code true}, the value is formatted as a size (units may be applied
   * by {@link Fields#shortToString(short, boolean)}). This method must not be used for persistence.
   *
   * @param val value to render; may be {@code null} if allowed by the caller
   * @return display string
   */
  @Override
  protected String toDisplayString(Short val) {
    return Fields.shortToString(val, isSize);
  }

  /**
   * Returns the canonical string form for persistence and configuration files.
   *
   * <p>Formatting as a size is disabled to avoid unit annotations; callers that need a UI-friendly
   * form should use {@link #toDisplayString(Short)} instead.
   *
   * @param val value to render; may be {@code null} if allowed by the caller
   * @return canonical string without size formatting
   */
  @Override
  protected String toString(Short val) {
    return Fields.shortToString(val, false);
  }
}
