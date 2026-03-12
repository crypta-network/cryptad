package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.keys.FreenetURI;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the original request details persisted for splitfile fetch recovery.
 *
 * <p>This value object groups the current key, original key, client detail bytes, and the
 * final-fetch flag so persistence helpers can pass a single parameter object instead of long
 * argument lists. Client detail bytes are defensively copied at construction and accessor read.
 *
 * <ul>
 *   <li>Captures the current and original request keys used for persistence.
 *   <li>Stores client detail bytes verbatim for later replay.
 *   <li>Includes whether the fetch is considered final.
 * </ul>
 */
public final class SplitFileFetchOriginalDetails {
  private final FreenetURI thisKey;
  private final FreenetURI origKey;
  private final byte[] clientDetails;
  private final boolean isFinalFetch;

  /**
   * Creates a persisted details bundle for splitfile fetch recovery.
   *
   * @param thisKey key of the fetch currently being persisted
   * @param origKey original request key that seeded the fetch
   * @param clientDetails client detail bytes written to storage; copied when non-null
   * @param isFinalFetch true when the request is a final-fetch operation
   */
  public SplitFileFetchOriginalDetails(
      FreenetURI thisKey, FreenetURI origKey, byte[] clientDetails, boolean isFinalFetch) {
    this.thisKey = thisKey;
    this.origKey = origKey;
    this.clientDetails = copyNullable(clientDetails);
    this.isFinalFetch = isFinalFetch;
  }

  public FreenetURI thisKey() {
    return thisKey;
  }

  public FreenetURI origKey() {
    return origKey;
  }

  public byte[] clientDetails() {
    return copyNullable(clientDetails);
  }

  private static byte[] copyNullable(byte[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
  }

  public boolean isFinalFetch() {
    return isFinalFetch;
  }

  /**
   * Compares this instance to another by value, including the client detail bytes.
   *
   * @param o object to compare against; may be {@code null}.
   * @return {@code true} when all components are equal, including array contents.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof SplitFileFetchOriginalDetails other)) {
      return false;
    }
    return isFinalFetch == other.isFinalFetch
        && Objects.equals(thisKey, other.thisKey)
        && Objects.equals(origKey, other.origKey)
        && Arrays.equals(clientDetails, other.clientDetails);
  }

  /**
   * Computes a hash code that incorporates the client detail bytes.
   *
   * @return a hash code derived from all components.
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(thisKey, origKey, isFinalFetch);
    result = 31 * result + Arrays.hashCode(clientDetails);
    return result;
  }

  /**
   * Returns a diagnostic string that includes array contents.
   *
   * @return a non-null string describing this instance.
   */
  @Override
  public @NotNull String toString() {
    return "SplitFileFetchOriginalDetails[thisKey="
        + thisKey
        + ", origKey="
        + origKey
        + ", clientDetails="
        + Arrays.toString(clientDetails)
        + ", isFinalFetch="
        + isFinalFetch
        + "]";
  }
}
