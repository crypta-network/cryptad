package network.crypta.runtime.spi;

/**
 * Names the configuration sections that management-facing code may request from the runtime.
 *
 * <p>This enum preserves the existing FCP configuration export families while keeping the runtime
 * SPI free of daemon-only types such as {@code Config.RequestType}. Callers usually combine one or
 * more constants in a {@link java.util.Set} and pass that set to {@link
 * ConfigPort#export(java.util.Set)} to request only the slices needed for a specific response. The
 * enum does not define storage layout or wire encoding. It only names the logical views that the
 * runtime can export at a point in time.
 *
 * <p>The sections are intentionally small and stable:
 *
 * <ul>
 *   <li>value-oriented sections describe effective or default option values;
 *   <li>metadata sections describe presentation, ordering, or operator-facing text;
 *   <li>flag sections expose boolean attributes used by existing FCP clients.
 * </ul>
 *
 * @see ConfigPort
 * @see ConfigSnapshot
 */
public enum ConfigSection {
  /**
   * Exports the current effective values after defaults and persisted overrides have been applied.
   */
  CURRENT,
  /** Exports the default values that apply before an operator or node process overrides them. */
  DEFAULTS,
  /**
   * Exports relative ordering hints so clients can present sibling options in a stable sequence.
   */
  SORT_ORDER,
  /** Exports whether each option is marked as expert-only in the underlying configuration model. */
  EXPERT_FLAG,
  /** Exports whether each option is force-written even when persistence would otherwise omit it. */
  FORCE_WRITE_FLAG,
  /**
   * Exports the short operator-facing description string associated with each configuration item.
   */
  SHORT_DESCRIPTION,
  /** Exports the longer descriptive text that explains a configuration item in more detail. */
  LONG_DESCRIPTION,
  /** Exports the declared data-type label that existing clients use to interpret option values. */
  DATA_TYPES
}
