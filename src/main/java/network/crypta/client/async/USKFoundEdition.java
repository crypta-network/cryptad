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
 */
public final class USKFoundEdition {
  private final long edition;
  private final USK key;
  private final ClientContext context;
  private final boolean metadata;
  private final short codec;
  private final byte[] data;
  private final boolean newKnownGood;
  private final boolean newSlotToo;

  /**
   * Creates a notification payload for a discovered USK edition.
   *
   * @param edition The discovered logical edition number.
   * @param key A copy of the key with the discovered edition set for this notification.
   * @param context Execution context with client-layer services and schedulers for follow-up work.
   * @param metadata True when the bytes correspond to metadata for the edition rather than content.
   * @param codec Short identifier of the content codec associated with the returned byte payload.
   * @param data Raw byte payload for the discovered edition or its metadata, as provided by
   *     fetcher.
   * @param newKnownGood True when the highest known-good, successfully fetched edition has
   *     advanced.
   * @param newSlotToo True when the highest known SSK slot has also advanced alongside known-good.
   */
  public USKFoundEdition(
      long edition,
      USK key,
      ClientContext context,
      boolean metadata,
      short codec,
      byte[] data,
      boolean newKnownGood,
      boolean newSlotToo) {
    this.edition = edition;
    this.key = key;
    this.context = context;
    this.metadata = metadata;
    this.codec = codec;
    this.data = data;
    this.newKnownGood = newKnownGood;
    this.newSlotToo = newSlotToo;
  }

  public long edition() {
    return edition;
  }

  public USK key() {
    return key;
  }

  public ClientContext context() {
    return context;
  }

  public boolean metadata() {
    return metadata;
  }

  public short codec() {
    return codec;
  }

  public byte[] data() {
    return data;
  }

  public boolean newKnownGood() {
    return newKnownGood;
  }

  public boolean newSlotToo() {
    return newSlotToo;
  }

  /**
   * Returns a copy of this payload with a different execution context.
   *
   * <p>This is useful when dispatching the same event through an alternate context, such as a
   * persistent job runner, without mutating the original instance.
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
    if (!(obj instanceof USKFoundEdition other)) {
      return false;
    }
    return edition == other.edition
        && metadata == other.metadata
        && codec == other.codec
        && newKnownGood == other.newKnownGood
        && newSlotToo == other.newSlotToo
        && Objects.equals(key, other.key)
        && Objects.equals(context, other.context)
        && Arrays.equals(data, other.data);
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
