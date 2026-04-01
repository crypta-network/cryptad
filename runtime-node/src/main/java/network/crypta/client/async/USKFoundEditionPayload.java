package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.keys.USK;
import org.jetbrains.annotations.NotNull;

/**
 * Captures the payload metadata and bytes for a discovered USK edition.
 *
 * <p>This immutable carrier bundles the edition number, the edition-specific {@link USK}, and
 * payload details produced by a fetch. It is typically created when an edition becomes available
 * and then handed through callbacks such as {@link USKFoundEdition} to keep related data together.
 * The class performs no validation or defensive copying so that callers preserve legacy behavior
 * and retain control over allocation and ownership of the byte array. As a result, the instance is
 * thread-safe only if callers treat the referenced key and byte array as effectively immutable.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>All fields are stored as-is, including a {@code null} payload.
 *   <li>The {@code data} array reference is shared and may be reused by callers.
 *   <li>Equality and hashing compare the array contents, not the reference.
 * </ul>
 *
 * @see USKFoundEdition
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class USKFoundEditionPayload {
  private final long edition;
  private final USK key;
  private final boolean metadata;
  private final short codec;
  private final byte[] data;

  /**
   * Creates a payload snapshot for a discovered edition.
   *
   * <p>The constructor stores references exactly as provided and performs no copying or validation.
   * This matches historical behavior and lets the caller control memory usage. Callers may pass
   * {@code null} for {@code data} to represent a metadata-only update or a discovery without bytes.
   *
   * @param edition logical edition number for the notification, expected non-negative.
   * @param key key instance already updated to the discovered edition.
   * @param metadata true when the payload represents metadata rather than content bytes.
   * @param codec short codec identifier associated with the payload, or {@code -1} when unknown.
   * @param data raw payload bytes, possibly {@code null} or shared by the caller.
   */
  public USKFoundEditionPayload(long edition, USK key, boolean metadata, short codec, byte[] data) {
    this.edition = edition;
    this.key = key;
    this.metadata = metadata;
    this.codec = codec;
    this.data = data;
  }

  /**
   * Returns the discovered logical edition number for this payload.
   *
   * <p>The value is stored exactly as supplied at construction time. It is typically non-negative
   * and corresponds to the edition embedded in the {@link USK} instance, but this class does not
   * enforce that relationship.
   *
   * @return the logical edition number carried by this payload snapshot.
   */
  public long edition() {
    return edition;
  }

  /**
   * Returns the {@link USK} instance associated with the discovered edition.
   *
   * <p>The returned reference is the same object passed to the constructor. Callers should treat it
   * as immutable for the lifetime of this payload, especially when sharing across threads.
   *
   * @return the edition-specific key reference, possibly {@code null} if provided as such.
   */
  public USK key() {
    return key;
  }

  /**
   * Indicates whether the payload bytes represent metadata rather than content.
   *
   * <p>This flag is provided by the fetcher and preserved without interpretation. A {@code true}
   * value usually implies a metadata payload, but the caller determines how the bytes are consumed.
   *
   * @return {@code true} when the payload corresponds to metadata, {@code false} otherwise.
   */
  public boolean metadata() {
    return metadata;
  }

  /**
   * Returns the codec identifier associated with the payload bytes.
   *
   * <p>The codec value is a short identifier supplied by the fetcher. It may be {@code -1} or
   * another sentinel when no codec applies or the content is unknown.
   *
   * @return the codec identifier for the payload, or a sentinel when absent.
   */
  public short codec() {
    return codec;
  }

  /**
   * Returns the raw payload bytes for the discovered edition.
   *
   * <p>The returned array reference is the same object provided at construction time. It may be
   * {@code null} to indicate the absence of bytes, and it may be shared across callbacks, so
   * callers should not mutate it unless they fully own the reference.
   *
   * @return the raw payload bytes, or {@code null} when no data was provided.
   */
  public byte[] data() {
    return data;
  }

  /**
   * Compares this payload to another object for structural equality.
   *
   * <p>Equality compares primitive fields directly, the {@link USK} using {@link Object#equals},
   * and the payload bytes using {@link Arrays#equals(byte[], byte[])}. This makes equality
   * sensitive to the contents of the {@code data} array rather than its identity.
   *
   * @param obj the candidate object to compare against, possibly {@code null}.
   * @return {@code true} when all fields match by value, {@code false} otherwise.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof USKFoundEditionPayload other)) {
      return false;
    }
    return edition == other.edition
        && metadata == other.metadata
        && codec == other.codec
        && Objects.equals(key, other.key)
        && Arrays.equals(data, other.data);
  }

  /**
   * Returns a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash incorporates the array contents using {@link Arrays#hashCode(byte[])} and the
   * remaining fields via {@link Objects#hash}. This allows equal payloads to hash identically.
   *
   * @return a hash code derived from the payload fields and byte contents.
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(edition, key, metadata, codec);
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  /**
   * Returns a diagnostic string describing the payload fields.
   *
   * <p>The representation includes the edition, key, metadata flag, codec identifier, and a
   * rendered view of the byte array. A {@code null} array is represented as {@code "null"} so that
   * logging does not throw when bytes are absent.
   *
   * @return a human-readable string for debugging and logging purposes.
   */
  @Override
  public @NotNull String toString() {
    return "USKFoundEditionPayload["
        + "edition="
        + edition
        + ", key="
        + key
        + ", metadata="
        + metadata
        + ", codec="
        + codec
        + ", data="
        + (data == null ? "null" : Arrays.toString(data))
        + "]";
  }
}
