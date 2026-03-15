package network.crypta.runtime.spi;

/**
 * Selects which node-reference export shape the runtime should produce.
 *
 * <p>The legacy FCP node-reference flow historically combined two booleans to choose between
 * darknet or opennet references and between public or private visibility. This enum preserves the
 * same four outcomes while presenting a clearer, type-safe contract at the runtime SPI boundary.
 * Callers can still pass the volatile-data choice separately without widening the port into a
 * broader stats API.
 *
 * <p>This enum is intentionally narrow. It exists to model only the current node-reference export
 * family that management-facing code needs today. Implementations should map each constant to the
 * same underlying export path that the legacy daemon already exposes, so higher layers can migrate
 * away from daemon-only booleans without changing wire behavior.
 */
public enum NodeReferenceView {
  /** Public darknet reference intended for standard outbound node-reference export. */
  DARKNET_PUBLIC,

  /** Private darknet reference that includes trusted-peer-only details. */
  DARKNET_PRIVATE,

  /** Public opennet reference intended for public opennet export. */
  OPENNET_PUBLIC,

  /** Private opennet reference that includes trusted-peer-only details. */
  OPENNET_PRIVATE
}
