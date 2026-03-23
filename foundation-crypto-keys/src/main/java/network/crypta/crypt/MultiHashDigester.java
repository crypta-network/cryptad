package network.crypta.crypt;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import org.bitpedia.util.hash.StreamingHash;

/**
 * Computes several cryptographic hashes over the same byte stream in one pass.
 *
 * <p>This utility owns one {@link java.security.MessageDigest} per {@link HashType} selected via a
 * bit mask. Feed data through {@link #update(byte[], int, int)} and get all results via {@link
 * #getResults()}. The order of results follows {@link HashType#values()}.
 *
 * <p>Thread-safety: not thread-safe. Create a new instance per computation and use it from a single
 * thread.
 */
final class MultiHashDigester {

  private final Collection<Digester> digesters;

  private MultiHashDigester(Collection<Digester> digesters) {
    this.digesters = digesters;
  }

  /**
   * Feeds a slice of the input array to every configured digest.
   *
   * @param input source bytes (must not be {@code null})
   * @param offset start index within {@code input}
   * @param len number of bytes to read
   * @throws NullPointerException if {@code input} is {@code null}
   * @throws IndexOutOfBoundsException if the range {@code [offset, offset+len)} is out of bounds
   * @throws IllegalArgumentException if {@code offset < 0} or {@code len < 0}
   */
  void update(byte[] input, int offset, int len) {
    digesters.forEach(digester -> digester.update(input, offset, len));
  }

  /**
   * Finalizes all digests and returns their values.
   *
   * <p>Each call completes the underlying {@link StreamingHash} instances (they are reset after
   * completion). Subsequent calls to {@link #update(byte[], int, int)} start a new computation.
   *
   * <p>The returned list is unmodifiable and ordered according to {@link HashType#values()}.
   *
   * @return unmodifiable list of results; may be empty when no hash types were selected
   */
  List<HashResult> getResults() {
    // Use Stream.toList() so callers cannot mutate the returned list.
    return digesters.stream().map(Digester::getResult).toList();
  }

  /**
   * Creates a digester configured for the hash types indicated by {@code bitmask}.
   *
   * <p>For each {@link HashType} whose {@link HashType#bitmask} bit is set in {@code bitmask}, a
   * corresponding digester is included. Result ordering produced by {@link #getResults()} matches
   * the declaration order of {@link HashType#values()}.
   *
   * @param bitmask bit set of desired hash types
   * @return a new digester for the selected types
   * @see HashType#bitmask
   */
  static MultiHashDigester fromBitmask(long bitmask) {
    List<Digester> digesters =
        Arrays.stream(HashType.values())
            .filter(hashType -> (bitmask & hashType.bitmask) == hashType.bitmask)
            .map(Digester::new)
            // Stream.toList() returns an unmodifiable list; we never mutate it.
            .toList();

    return new MultiHashDigester(digesters);
  }

  private static class Digester {
    private final HashType hashType;
    private final java.security.MessageDigest digest;

    Digester(HashType hashType) {
      this.hashType = hashType;
      digest = hashType.get();
    }

    HashResult getResult() {
      // Complete and reset this MessageDigest; safe because each instance is owned here.
      return new HashResult(hashType, digest.digest());
    }

    void update(byte[] input, int offset, int len) {
      // Delegate bounds validation to JCA; exceptions propagate unchanged.
      digest.update(input, offset, len);
    }
  }
}
