package network.crypta.config;

import java.util.Arrays;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.URLEncoder;

/**
 * Configuration option whose value is a sequence of strings.
 *
 * <p>Values are persisted and exchanged as a single semicolon-delimited list where each element is
 * URL-encoded. The delimiter is {@link #VALUE_DELIMITER} ({@code ;}). Within an element, unsafe
 * characters (including the delimiter itself) are percent-encoded via {@link URLEncoder}; Unicode
 * characters may pass through unescaped. Empty elements are represented by the single-character
 * token {@code ":"}.
 *
 * <p>Parsing accepts the format produced by {@link #toString(String[])} and tolerates certain
 * malformed escapes only until the first successful decoding (see {@link URLDecoder}). Truncated or
 * otherwise invalid encodings result in {@link InvalidConfigValueException}.
 *
 * <p>Unless coordinated by the surrounding configuration subsystem, this class performs no internal
 * synchronization. Arrays returned to or received from the callback are treated as mutable by
 * convention of the concrete implementation.
 */
public class StringArrOption extends Option<String[]> {
  /**
   * Delimiter used to persist and parse string arrays.
   *
   * <p>Values themselves never contain this delimiter in clear form because {@link URLEncoder}
   * percent-encodes it inside elements. External callers should prefer {@link #toString(String[])}
   * and {@link #parseString(String)} rather than constructing formats manually.
   */
  public static final String VALUE_DELIMITER = ";";

  /**
   * Creates an option backed by a {@link StringArrCallback}.
   *
   * @param conf parent configuration container
   * @param optionName canonical option name used in config and APIs
   * @param defaultValue default sequence when unspecified; {@code null} is treated as an empty
   *     array
   * @param meta descriptive and ordering metadata
   * @param cb callback that provides and accepts the effective value
   */
  public StringArrOption(
      SubConfig conf,
      String optionName,
      String[] defaultValue,
      Option.Meta meta,
      StringArrCallback cb) {
    this(conf, optionName, defaultValue, meta, (ConfigCallback<String[]>) cb);
  }

  private StringArrOption(
      SubConfig conf,
      String optionName,
      String[] defaultValue,
      Option.Meta meta,
      ConfigCallback<String[]> cb) {
    super(conf, optionName, cb, meta, Option.DataType.STRING_ARRAY);
    this.defaultValue = (defaultValue == null) ? new String[0] : defaultValue;
    this.currentValue = (defaultValue == null) ? new String[0] : defaultValue;
  }

  /**
   * Deprecated compatibility constructor for consumers compiled against the old callback package.
   *
   * @deprecated Use {@link #StringArrOption(SubConfig, String, String[], Option.Meta,
   *     network.crypta.config.StringArrCallback)}.
   */
  @Deprecated
  public StringArrOption(
      SubConfig conf,
      String optionName,
      String[] defaultValue,
      Option.Meta meta,
      network.crypta.support.api.StringArrCallback cb) {
    this(conf, optionName, defaultValue, meta, LegacyCallbackAdapters.adapt(cb));
  }

  /**
   * Parses a semicolon-delimited, URL-encoded list into an array of strings.
   *
   * <p>Rules:
   *
   * <ul>
   *   <li>An empty input yields an empty array.
   *   <li>Each element is separated by {@link #VALUE_DELIMITER}.
   *   <li>A token equal to {@code ":"} maps to the empty string.
   *   <li>All other tokens are URL-decoded (tolerant mode; see {@link URLDecoder}).
   * </ul>
   *
   * @param val non-{@code null} string to parse
   * @return newly allocated array containing decoded elements
   * @throws InvalidConfigValueException if decoding fails or the input violates the expected format
   */
  @Override
  public String[] parseString(String val) throws InvalidConfigValueException {
    if (val.isEmpty()) return new String[0];
    String[] out = val.split(VALUE_DELIMITER);

    try {
      for (int i = 0; i < out.length; i++) {
        // Map sentinel token to an empty element; otherwise decode percent-encoding.
        if (out[i].equals(":")) out[i] = "";
        else out[i] = URLDecoder.decode(out[i], true /* tolerant mode */);
      }
    } catch (URLEncodedFormatException e) {
      throw new InvalidConfigValueException(l10nParseError(e.getLocalizedMessage()));
    }
    return out;
  }

  /**
   * Sets the in-memory value without invoking the callback or performing parsing.
   *
   * <p>Intended for initialization flows that provide a typed value directly.
   *
   * @param val sequence to record as current
   */
  public void setInitialValue(String[] val) {
    this.currentValue = val;
  }

  private String l10nParseError(String value) {
    return NodeL10n.getBase().getString("StringArrOption.parseError", "error", value);
  }

  /**
   * Formats an array as a semicolon-delimited, URL-encoded list.
   *
   * <p>Rules:
   *
   * <ul>
   *   <li>{@code null} returns {@code null}.
   *   <li>Each element is URL-encoded via {@link URLEncoder#encode(String, boolean)} with {@code
   *       ascii=false} and followed by {@link #VALUE_DELIMITER}.
   *   <li>Empty strings are encoded as the token {@code ":"} to distinguish them from missing
   *       elements.
   *   <li>The trailing delimiter is removed from the final result.
   * </ul>
   *
   * @param arr array to format; may be {@code null}
   * @return canonical string form or {@code null}
   */
  @Override
  public String toString(String[] arr) {
    if (arr == null) return null;
    StringBuilder sb = new StringBuilder();
    for (String val : arr) {
      if (val.isEmpty()) sb.append(":").append(VALUE_DELIMITER);
      else sb.append(URLEncoder.encode(val, false)).append(VALUE_DELIMITER);
    }
    // Drop the surplus delimiter appended after the last element, if any.
    if (!sb.isEmpty()) sb.setLength(sb.length() - 1);
    return sb.toString();
  }

  /**
   * Decodes a single URL-encoded token using strict rules.
   *
   * <p>This is a convenience for callers that need to interpret an element outside the context of a
   * full list.
   *
   * @param s token to decode
   * @return decoded string, or {@code null} when the input is malformed
   */
  public static String decode(String s) {
    try {
      return URLDecoder.decode(s, false);
    } catch (URLEncodedFormatException _) {
      return null;
    }
  }

  /**
   * Returns whether the current sequence equals the default sequence.
   *
   * <p>Equality is determined via {@link Arrays#equals(Object[], Object[])}. When the configuration
   * subsystem has finished initialization, {@link Option#getValue()} refreshes the current value
   * from the callback before comparison.
   *
   * @return {@code true} if equal to the default; otherwise {@code false}
   */
  @Override
  public boolean isDefault() {
    getValue();
    return currentValue != null && Arrays.equals(currentValue, defaultValue);
  }
}
