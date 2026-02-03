package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.keys.USK;
import org.jetbrains.annotations.NotNull;

/**
 * Describes a discovered USK edition for client callback delivery.
 *
 * <p>This immutable value object bundles edition identity, payload metadata, bytes, and progress
 * flags emitted by USK fetchers and subscriptions. It is created at the point where a fetcher has
 * enough information to notify observers and is typically passed through callbacks such as {@link
 * USKCallback#onFoundEdition(USKFoundEdition)} or {@link
 * USKFetcherCallback#onFoundEdition(USKFoundEdition)}. The class performs no validation or
 * defensive copying, preserving the historical behavior where callers control allocation and
 * ownership of the {@code byte[]} payload.
 *
 * <p>The instance is thread-safe only if the referenced {@link USK} and {@code data} array are
 * treated as effectively immutable. Equality and hashing compare the array contents rather than the
 * array identity, which makes the object suitable for caches or deduplication when data is stable.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>Fields are stored as provided, including {@code null} payload bytes.
 *   <li>The {@code context} is carried for follow-up scheduling or resource access.
 *   <li>Progress flags indicate whether known-good or slot boundaries advanced.
 * </ul>
 *
 * @see USKFoundEditionPayload
 * @see USKFoundEditionProgress
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
   * <p>The constructor copies values from the provided payload and progress objects without
   * validation or defensive copying. This preserves historical behavior and allows callers to share
   * buffers or reuse key instances. The resulting object represents a point-in-time snapshot that
   * can be handed across async boundaries.
   *
   * @param payload edition identity and bytes, possibly containing a {@code null} payload.
   * @param context execution context used for follow-up scheduling or service access.
   * @param progress progress flags describing known-good and slot transitions.
   */
  public USKFoundEdition(
      USKFoundEditionPayload payload, ClientContext context, USKFoundEditionProgress progress) {
    this.edition = payload.edition();
    this.key = payload.key();
    this.context = context;
    this.metadata = payload.metadata();
    this.codec = payload.codec();
    this.data = payload.data();
    this.newKnownGood = progress.newKnownGood();
    this.newSlotToo = progress.newSlotToo();
  }

  /**
   * Returns the discovered logical edition number for this notification.
   *
   * <p>The value is the same as provided by {@link USKFoundEditionPayload} and is not normalized or
   * validated by this class.
   *
   * @return the logical edition number carried by this event snapshot.
   */
  public long edition() {
    return edition;
  }

  /**
   * Returns the edition-specific {@link USK} associated with this notification.
   *
   * <p>The returned reference is the same object supplied in the payload. Callers should treat it
   * as immutable when sharing across threads.
   *
   * @return the key reference for the discovered edition, possibly {@code null} if provided as
   *     such.
   */
  public USK key() {
    return key;
  }

  /**
   * Returns the execution context carried with this notification.
   *
   * <p>The context is used by clients to access schedulers and services for follow-up work. This
   * class stores the reference as-is and does not enforce non-nullability.
   *
   * @return the client execution context associated with this event.
   */
  public ClientContext context() {
    return context;
  }

  /**
   * Indicates whether the payload bytes represent metadata rather than content.
   *
   * <p>This flag originates from the fetcher and is preserved without interpretation. Callers use
   * it to decide how to parse or store the byte payload.
   *
   * @return {@code true} when the payload represents metadata, {@code false} otherwise.
   */
  public boolean metadata() {
    return metadata;
  }

  /**
   * Returns the codec identifier associated with the payload bytes.
   *
   * <p>The fetcher supplies the codec value. It may be {@code -1} or another sentinel when the
   * codec is unknown or not applicable.
   *
   * @return the codec identifier for the payload, or a sentinel when absent.
   */
  public short codec() {
    return codec;
  }

  /**
   * Returns the raw payload bytes for the discovered edition.
   *
   * <p>The returned array reference is shared with the caller and may be {@code null}. Callers that
   * need immutability should copy the array before mutation.
   *
   * @return the payload byte array, or {@code null} when no bytes are available.
   */
  public byte[] data() {
    return data;
  }

  /**
   * Indicates whether the highest known-good edition advanced for this notification.
   *
   * <p>This flag allows callers to distinguish between slot discoveries and verified, fetchable
   * editions.
   *
   * @return {@code true} when the known-good marker advanced, {@code false} otherwise.
   */
  public boolean newKnownGood() {
    return newKnownGood;
  }

  /**
   * Indicates whether the highest known slot advanced alongside a known-good update.
   *
   * <p>When {@code true}, both slot and known-good indices moved forward together for this event.
   *
   * @return {@code true} when the slot index advanced with known-good, {@code false} otherwise.
   */
  public boolean newSlotToo() {
    return newSlotToo;
  }

  /**
   * Returns a copy of this payload with a different execution context.
   *
   * <p>The returned instance shares the same payload bytes and flags while carrying the supplied
   * context. This is useful when dispatching the same event through an alternate context, such as a
   * persistent job runner, without mutating the original instance.
   *
   * @param context execution context to carry with the copied notification.
   * @return a new {@link USKFoundEdition} instance with the updated context.
   */
  public USKFoundEdition withContext(ClientContext context) {
    return new USKFoundEdition(
        new USKFoundEditionPayload(edition, key, metadata, codec, data),
        context,
        new USKFoundEditionProgress(newKnownGood, newSlotToo));
  }

  /**
   * Compares this notification to another object for structural equality.
   *
   * <p>Equality compares primitive fields directly, the {@link USK} and {@link ClientContext} using
   * {@link Object#equals}, and the payload bytes using {@link Arrays#equals(byte[], byte[])}. This
   * makes equality sensitive to the contents of the {@code data} array rather than its identity.
   *
   * @param obj the candidate object to compare against, possibly {@code null}.
   * @return {@code true} when all fields match by value, {@code false} otherwise.
   */
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

  /**
   * Returns a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash incorporates the payload byte contents using {@link Arrays#hashCode(byte[])} along
   * with the remaining fields via {@link Objects#hash}.
   *
   * @return a hash code derived from the notification fields and payload bytes.
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(edition, key, context, metadata, codec, newKnownGood, newSlotToo);
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  /**
   * Returns a diagnostic string describing the notification fields.
   *
   * <p>The representation includes the edition, key, context, metadata flag, codec identifier, raw
   * data, and progress flags. It is intended for logging and debugging rather than stable parsing.
   *
   * @return a human-readable string representation of this notification.
   */
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
