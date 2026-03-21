package network.crypta.config;

import network.crypta.support.api.StringCallback;

/**
 * String-valued configuration option.
 *
 * <p>This specialization of {@link Option} stores and exposes textual values. Parsing and
 * formatting are identity operations: the input string is returned as-is by {@link
 * #parseString(String)} and {@link #toString(String)}. The declared data type reported to external
 * UIs is {@link Option.DataType#STRING}.
 *
 * <p>The constructor records the provided default value as both the initial default and current
 * value. Subsequent reads after {@link SubConfig#finishedInitialization()} reflect the value
 * supplied by the associated {@link StringCallback}.
 */
public class StringOption extends Option<String> {
  /**
   * Creates a string option and registers its descriptive metadata.
   *
   * @param conf Owning {@link SubConfig} that manages registration and lookups.
   * @param optionName Canonical name used in configuration files and APIs.
   * @param defaultValue Initial value used before callbacks become authoritative.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback used to read/apply values for this option.
   */
  public StringOption(
      SubConfig conf, String optionName, String defaultValue, Option.Meta meta, StringCallback cb) {
    super(conf, optionName, cb, meta, Option.DataType.STRING);
    this.defaultValue = defaultValue;
    this.currentValue = defaultValue;
  }

  /**
   * Parses a textual value.
   *
   * <p>For string options, parsing is an identity conversion and returns the provided text
   * unchanged.
   *
   * @param val Text to parse; not {@code null}.
   * @return The same string instance or an equivalent value.
   * @throws InvalidConfigValueException Never thrown by this implementation.
   */
  @Override
  protected String parseString(String val) throws InvalidConfigValueException {
    return val;
  }

  /**
   * Formats a value for persistence and programmatic APIs.
   *
   * <p>For string options, formatting is an identity operation and returns the provided value.
   *
   * @param val Value to format; may be {@code null} only if the owning subsystem permits it.
   * @return The same string instance or an equivalent value.
   */
  @Override
  protected String toString(String val) {
    return val;
  }
}
