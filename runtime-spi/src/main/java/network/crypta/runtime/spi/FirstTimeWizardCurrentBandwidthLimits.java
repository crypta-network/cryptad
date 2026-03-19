package network.crypta.runtime.spi;

/**
 * Carries the detached current-bandwidth row for the legacy first-time wizard rate page.
 *
 * <p>The legacy multipage wizard can show a "current settings" row ahead of its fixed presets when
 * the running node already has an explicit upload limit. This record transports just the two
 * byte-per-second values needed to render that row through the detached wizard snapshot, without
 * exposing HTTP-only helper types or live daemon objects across the runtime SPI boundary.
 *
 * <p>This type is intentionally small and immutable. Producers compute the values from live daemon
 * state at snapshot time, while consumers treat the record as detached display data. The record
 * does not encode whether the row should be shown; callers use the presence or absence of the
 * record in the surrounding snapshot to make that decision.
 *
 * @param downloadBytes effective downstream limit, expressed in bytes per second for detached UI
 *     rendering
 * @param uploadBytes effective upstream limit, expressed in bytes per second for detached UI
 *     rendering
 */
public record FirstTimeWizardCurrentBandwidthLimits(long downloadBytes, long uploadBytes) {}
