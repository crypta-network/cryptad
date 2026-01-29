package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.keys.USK;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable notification payload describing a discovered USK edition.
 *
 * <p>This value object bundles the edition metadata, payload, and progress flags emitted by USK
 * fetchers and subscriptions. It is shared across callbacks to avoid long parameter lists and to
 * keep related data coherent during async handoff.
 *
 * @param edition The discovered logical edition number.
 * @param key A copy of the key with the discovered edition set for this notification.
 * @param context Execution context with client-layer services and schedulers for follow-up work.
 * @param metadata True when the bytes correspond to metadata for the edition rather than content.
 * @param codec Short identifier of the content codec associated with the returned byte payload.
 * @param data Raw byte payload for the discovered edition or its metadata, as provided by fetcher.
 * @param newKnownGood True when the highest known-good, successfully fetched edition has advanced.
 * @param newSlotToo True when the highest known SSK slot has also advanced alongside known-good.
 */
@SuppressWarnings("ArrayRecordComponent")
public record USKFoundEdition(
    long edition,
    USK key,
    ClientContext context,
    boolean metadata,
    short codec,
    byte[] data,
    boolean newKnownGood,
    boolean newSlotToo) {

  /**
   * Returns a copy of this payload with a different execution context.
   *
   * <p>This is useful when dispatching the same event through an alternate context, such as a
   * persistent job runner, without mutating the original record.
   *
   * @param context The execution context to carry.
   * @return A copy of this event with the supplied context.
   */
  public USKFoundEdition withContext(ClientContext context) {
    return new USKFoundEdition(
        edition, key, context, metadata, codec, data, newKnownGood, newSlotToo);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj
        instanceof
        USKFoundEdition(
            long otherEdition,
            USK otherKey,
            ClientContext otherContext,
            boolean otherMetadata,
            short otherCodec,
            byte[] otherData,
            boolean otherNewKnownGood,
            boolean otherNewSlotToo))) {
      return false;
    }
    return edition == otherEdition
        && metadata == otherMetadata
        && codec == otherCodec
        && newKnownGood == otherNewKnownGood
        && newSlotToo == otherNewSlotToo
        && Objects.equals(key, otherKey)
        && Objects.equals(context, otherContext)
        && Arrays.equals(data, otherData);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(edition, key, context, metadata, codec, newKnownGood, newSlotToo);
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "USKFoundEdition["
        + "edition="
        + edition
        + ", key="
        + key
        + ", context="
        + context
        + ", metadata="
        + metadata
        + ", codec="
        + codec
        + ", data="
        + Arrays.toString(data)
        + ", newKnownGood="
        + newKnownGood
        + ", newSlotToo="
        + newSlotToo
        + "]";
  }
}
