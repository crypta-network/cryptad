package network.crypta.config;

/**
 * Describes the unit category (dimension) associated with a configuration value.
 *
 * <p>Some configuration options represent dimensionless values, while others denote a size (e.g., a
 * data amount) or a time duration. This enum allows parsers, validators, and UIs to interpret,
 * validate, and present values consistently. Concrete units and accepted suffixes, if any, are
 * defined by the specific option and its parser.
 */
public enum Dimension {
  /** A dimensionless value; no unit semantics are applied. */
  NOT,

  /** A data-size quantity; unit handling is defined by the option/parser. */
  SIZE,

  /** A time-based duration; unit handling is defined by the option/parser. */
  DURATION
}
