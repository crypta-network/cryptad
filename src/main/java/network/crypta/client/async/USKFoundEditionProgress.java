package network.crypta.client.async;

/**
 * Captures progress flags for a discovered USK edition notification.
 *
 * <p>This record represents the two boolean signals emitted alongside a USK discovery: whether the
 * highest known-good edition advanced and whether the highest known slot advanced at the same time.
 * It is typically created by fetchers or managers when they have enough context to explain the
 * significance of a found edition and then passed to {@link USKFoundEdition} as part of the
 * notification payload. The record is immutable and thread-safe as long as callers treat it as a
 * simple value object with no external side effects.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>Flags are stored exactly as supplied, with no inference or validation.
 *   <li>{@code newSlotToo} may be {@code true} only when {@code newKnownGood} is also true.
 * </ul>
 *
 * @param newKnownGood true when the highest known-good edition advances for this event, even if the
 *     slot index did not change.
 * @param newSlotToo true when the highest known slot advances alongside a known-good update,
 *     indicating both signals moved forward together.
 * @see USKFoundEdition
 */
public record USKFoundEditionProgress(boolean newKnownGood, boolean newSlotToo) {}
