package network.crypta.config;

import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

/**
 * Base type for a single configuration option.
 *
 * <p>An {@code Option<T>} represents one typed setting belonging to a {@link SubConfig}. It
 * encapsulates:
 *
 * <ul>
 *   <li>Parsing from and formatting to strings for persistence and UI
 *   <li>Tracking of a default value versus the current value
 *   <li>Descriptive metadata (short/long description, ordering, expert flag)
 *   <li>Application of changes via a {@link ConfigCallback} supplied by the owner
 * </ul>
 *
 * <p>Unless stated otherwise by a subclass, no internal synchronization is performed. Typical
 * access occurs through the configuration subsystem (e.g., {@link SubConfig}), which coordinates
 * registration and lookups.
 */
public abstract class Option<T> {
  private static final String DEFAULT_L10N_KEY = "default";

  /**
   * Metadata for an option that groups descriptive and ordering properties.
   *
   * <p>Using a record keeps constructor parameter lists compact without changing behavior.
   *
   * @param sortOrder Relative ordering among sibling options in UI and exports.
   * @param expert Whether this option targets advanced users. UIs may hide it by default.
   * @param forceWrite Whether to write the value even when it equals the default.
   * @param shortDesc Message key (not the translated text) for a brief label.
   * @param longDesc Message key (not the translated text) for a longer description.
   */
  public record Meta(
      int sortOrder, boolean expert, boolean forceWrite, String shortDesc, String longDesc) {}

  /** Parent {@link SubConfig} that owns this option. */
  protected final SubConfig config;

  /** Canonical option name as used in config files and APIs. */
  protected final String name;

  /** Relative ordering among options in the same {@link SubConfig}. */
  protected final int sortOrder;

  /** Whether this option is intended for expert users. */
  protected final boolean expert;

  /** Whether to persist the value even when it equals the default. */
  protected final boolean forceWrite;

  /** Message key for a brief label (e.g., {@code "FCP port"}). */
  protected final String shortDesc;

  /**
   * Message key for a detailed description (e.g., {@code "The TCP port to listen for FCP
   * connections on"}).
   */
  protected final String longDesc;

  /** Callback used to read/apply the effective value. */
  protected final ConfigCallback<T> cb;

  protected T defaultValue;
  protected T currentValue;

  public enum DataType {
    /** Arbitrary text value. */
    STRING,
    /** Numeric value (integral or fixed-format as defined by the subclass). */
    NUMBER,
    /** {@code true}/{@code false}. */
    BOOLEAN,
    /** Ordered list of text values. */
    STRING_ARRAY
  }

  /** Declared data type used by external UIs (FCP/HTTP) to render appropriate editors. */
  final DataType dataType;

  Option(SubConfig config, String name, ConfigCallback<T> cb, Meta meta, DataType dataType) {
    this.config = config;
    this.name = name;
    this.cb = cb;
    this.sortOrder = meta != null ? meta.sortOrder() : 0;
    this.expert = meta != null && meta.expert();
    this.shortDesc = (meta != null) ? meta.shortDesc() : null;
    this.longDesc = (meta != null) ? meta.longDesc() : null;
    this.forceWrite = meta != null && meta.forceWrite();
    this.dataType = dataType;
  }

  /**
   * Parses the provided string and applies it as the current value.
   *
   * <p>This method always delegates to the {@link ConfigCallback} regardless of whether the new
   * value equals the current one.
   *
   * @param val String representation of the value (format defined by the subclass).
   * @throws InvalidConfigValueException If {@link #parseString(String)} rejects {@code val}, or if
   *     the callback refuses the value.
   * @throws NodeNeedRestartException If applying the value succeeds, but a restart is required.
   */
  public final void setValue(String val)
      throws InvalidConfigValueException, NodeNeedRestartException {
    T x = parseString(val);
    set(x);
  }

  /**
   * Converts a textual representation into a typed value.
   *
   * @param val Text to parse. Never {@code null}.
   * @return Parsed value used by this option and its callback. May be {@code null} if the subtype
   *     permits {@code null} as a valid state.
   * @throws InvalidConfigValueException If the text cannot be parsed or violates constraints.
   */
  protected abstract T parseString(String val) throws InvalidConfigValueException;

  /**
   * Formats a value for persistence and programmatic APIs.
   *
   * <p>Subclasses must ensure the result can be consumed by {@link #parseString(String)}.
   *
   * @param val Value to format.
   * @return Canonical string form.
   */
  protected abstract String toString(T val);

  /**
   * Formats a value for end‑user display. Defaults to {@link #toString(Object)}.
   *
   * @param val Value to display.
   * @return Human‑readable form suitable for UI.
   */
  protected String toDisplayString(T val) {
    return toString(val);
  }

  /**
   * Applies a typed value via the callback and records it as current.
   *
   * <p>If the callback throws {@link NodeNeedRestartException}, the {@code currentValue} is still
   * updated and the exception is rethrown so callers can surface the restart requirement.
   *
   * @param val New typed value.
   * @throws InvalidConfigValueException If the callback rejects the value.
   * @throws NodeNeedRestartException If a restart is required after applying the value.
   */
  protected final void set(T val) throws InvalidConfigValueException, NodeNeedRestartException {
    try {
      cb.set(val);
      currentValue = val;
    } catch (NodeNeedRestartException e) {
      currentValue = val;
      throw e;
    }
  }

  /**
   * Returns the current value formatted for persistence and APIs.
   *
   * @return Canonical string form of the current value.
   */
  public final String getValueString() {
    return toString(currentValue);
  }

  /**
   * Returns the current value in a form suitable for end‑user display.
   *
   * @return Human‑readable string form of the current value.
   */
  public final String getValueDisplayString() {
    return toDisplayString(currentValue);
  }

  /**
   * Sets the initial value loaded from a configuration source.
   *
   * <p>This does not call the {@link ConfigCallback}. It allows the owning component to finish its
   * initialization first and then explicitly apply values. The callback is considered valid only
   * after the client calls {@code finishedInitialization()} on the owning {@link SubConfig}.
   *
   * @param val Text to parse from the configuration.
   * @throws InvalidConfigValueException If parsing fails.
   */
  public final void setInitialValue(String val) throws InvalidConfigValueException {
    currentValue = parseString(val);
  }

  /**
   * Re-applies the current value through the callback.
   *
   * @throws InvalidConfigValueException If the callback rejects the value.
   * @throws NodeNeedRestartException If the new value requires a restart.
   */
  public void forceUpdate() throws InvalidConfigValueException, NodeNeedRestartException {
    setValue(getValueString());
  }

  /**
   * Returns the canonical name of this option.
   *
   * @return Non-null option name.
   */
  public String getName() {
    return name;
  }

  /**
   * Returns the short description message key used for labels.
   *
   * <p>Callers may use this in UI elements (e.g., an {@code alt} attribute) after localizing it via
   * {@link #getLocalisedShortDesc()}.
   */
  public String getShortDesc() {
    return shortDesc;
  }

  /** Returns the long description message key. */
  private String getLongDesc() {
    return longDesc;
  }

  /**
   * Indicates whether this option is intended for expert users.
   *
   * @return {@code true} if expert‑only; otherwise {@code false}.
   */
  public boolean isExpert() {
    return expert;
  }

  /**
   * Indicates whether the value should be written even when it equals the default.
   *
   * @return {@code true} if the option is force‑written; otherwise {@code false}.
   */
  public boolean isForcedWrite() {
    return forceWrite;
  }

  /**
   * Returns the sort order within the parent {@link SubConfig}.
   *
   * @return Relative ordering value; lower values sort first.
   */
  public int getSortOrder() {
    return sortOrder;
  }

  /**
   * Returns the declared data type, which guides external UI rendering.
   *
   * @return Data type enum value.
   */
  public DataType getDataType() {
    return dataType;
  }

  /**
   * Returns the data type as a stable lower‑camel string.
   *
   * <p>Intended for FCP/HTTP clients that do not directly depend on the enum.
   *
   * @return One of {@code "string"}, {@code "number"}, {@code "boolean"}, or {@code "stringArray"}.
   */
  public String getDataTypeStr() {
    return switch (dataType) {
      case STRING -> "string";
      case NUMBER -> "number";
      case BOOLEAN -> "boolean";
      case STRING_ARRAY -> "stringArray";
    };
  }

  /**
   * Returns the effective typed value.
   *
   * <p>If the owning {@link SubConfig} has finished initialization, the value is refreshed from the
   * {@link ConfigCallback}. Otherwise, the last parsed value is returned (possibly the default).
   *
   * @return Current typed value; may be {@code null} if the subtype permits it.
   */
  public final T getValue() {
    if (config.hasFinishedInitialization()) {
      currentValue = cb.get();
    }
    return currentValue;
  }

  /**
   * Returns whether the current value equals the default value.
   *
   * @return {@code true} if current equals default; otherwise {@code false}.
   */
  public boolean isDefault() {
    getValue();
    return (currentValue != null && currentValue.equals(defaultValue));
  }

  /**
   * Sets the current value to the default without invoking the callback.
   *
   * <p>Do not use after completed initialization when side effects are required.
   */
  public final void setDefault() {
    currentValue = defaultValue;
  }

  /**
   * Returns the default value formatted for persistence and APIs.
   *
   * @return Canonical string form of the default value.
   */
  public final String getDefault() {
    return toString(defaultValue);
  }

  /**
   * Returns the callback used to read/apply values for this option.
   *
   * @return Non-null callback instance.
   */
  public final ConfigCallback<T> getCallback() {
    return cb;
  }

  /**
   * Resolves the localized short description using the provided localization bundle.
   *
   * @param l10n Localization source.
   * @return Localized short description; falls back to {@code getDefault()} when needed.
   */
  public String getLocalisedShortDesc(BaseL10n l10n) {
    return l10n.getString(getShortDesc(), DEFAULT_L10N_KEY, getDefault());
  }

  /** Returns the localized short description using the node's default bundle. */
  public String getLocalisedShortDesc() {
    return getLocalisedShortDesc(NodeL10n.getBase());
  }

  /**
   * Resolves the localized long description using the provided localization bundle.
   *
   * @param l10n Localization source.
   * @return Localized long description; falls back to {@code getDefault()} when needed.
   */
  public String getLocalisedLongDesc(BaseL10n l10n) {
    return l10n.getString(getLongDesc(), DEFAULT_L10N_KEY, getDefault());
  }

  /** Returns the localized long description using the node's default bundle. */
  public String getLocalisedLongDesc() {
    return getLocalisedLongDesc(NodeL10n.getBase());
  }

  /** Returns the localized short description as an {@link HTMLNode}. */
  public HTMLNode getShortDescNode() {
    return NodeL10n.getBase()
        .getHTMLNode(getShortDesc(), new String[] {DEFAULT_L10N_KEY}, new String[] {getDefault()});
  }

  /** Returns the localized long description as an {@link HTMLNode}. */
  public HTMLNode getLongDescNode() {
    return NodeL10n.getBase()
        .getHTMLNode(getLongDesc(), new String[] {DEFAULT_L10N_KEY}, new String[] {getDefault()});
  }
}
