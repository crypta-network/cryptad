package network.crypta.client;

import network.crypta.keys.FreenetURI;

/**
 * Immutable pair of a Freenet {@link FreenetURI} and a filename inside an archive/manifest.
 *
 * <p>This value object is commonly used by fetchers and manifest handlers to identify a specific
 * member within a container that is addressed by a single network key. The {@code key} refers to
 * the manifest or top-level object on the network (e.g., a CHK/SSK/USK/KSK), and {@code filename}
 * provides the intra-archive path of the desired member. Instances are immutable after construction
 * and can safely be used as map keys or elements in sets, provided that callers do not pass {@code
 * null} fields.
 *
 * <p>Equality and hashing are defined in terms of both components: two {@code ArchiveKey} values
 * are equal only when the {@link #key} values are equal and the {@link #filename} strings are
 * equal. The {@link #hashCode()} is derived from both in a way that is stable for the lifetime of
 * the instance. The class performs no normalization of filenames; callers should provide canonical
 * names if that is significant for their use case.
 *
 * <ul>
 *   <li>Thread-safety: instances are thread-safe due to immutability.
 *   <li>Nullability: the constructor does not defensively reject {@code null} values; invoking
 *       {@link #equals(Object)} or {@link #hashCode()} on objects containing {@code null} fields
 *       may raise {@link NullPointerException}. Prefer passing non-null values.
 * </ul>
 */
public class ArchiveKey {

  final FreenetURI key;
  final String filename;

  /**
   * Create a new {@code ArchiveKey} from a network {@link FreenetURI} and an archive member name.
   *
   * <p>No validation or normalization is performed. In particular, {@code filename2} is used as-is
   * (including path separators, case, or leading {@code ./}). For deterministic behavior across
   * components, callers should supply canonicalized values where appropriate.
   *
   * @param key2 The network key that identifies the archive or manifest holding the member. May be
   *     {@code null}, but subsequent calls to {@link #equals(Object)} or {@link #hashCode()} may
   *     then throw {@link NullPointerException}.
   * @param filename2 The filename or entry name inside the addressed archive or manifest. May be
   *     {@code null}, with the same caveats regarding {@link NullPointerException} as for {@code
   *     key2}.
   */
  public ArchiveKey(FreenetURI key2, String filename2) {
    key = key2;
    filename = filename2;
  }

  /**
   * Compare for equality with another object.
   *
   * <p>Returns {@code true} only if the argument is an {@code ArchiveKey} and both the network key
   * and the filename are equal to this instance's corresponding values. The comparison is
   * reference-safe (it first checks for identity), but it does not guard against {@code null}
   * components that may have been supplied at construction time.
   *
   * @param o The object to compare with this instance; may be {@code null} or of another type.
   * @return {@code true} when both {@link #key} and {@link #filename} are equal; {@code false} for
   *     {@code null} or incompatible types.
   * @throws NullPointerException If either this instance or the compared instance was constructed
   *     with {@code null} fields, equality may dereference a {@code null} and raise this exception.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ArchiveKey cmp)) return false;
    if (this == o) return true;

    return (cmp.key.equals(key) && cmp.filename.equals(filename));
  }

  /**
   * Compute a hash code suitable for hash-based collections.
   *
   * <p>The hash is derived from both components and is consistent with {@link #equals(Object)}. As
   * the instance is immutable, the returned value is stable for the lifetime of the object.
   *
   * @return A hash composed of the network key and filename; identical objects produce identical
   *     values.
   * @throws NullPointerException If either component is {@code null}, hashing will dereference it
   *     and raise this exception.
   */
  @Override
  public int hashCode() {
    return key.hashCode() ^ filename.hashCode();
  }

  /**
   * Return a diagnostic string of the form {@code <key>:<filename>}.
   *
   * <p>The method delegates to {@link FreenetURI#toString()} for the key and performs simple
   * concatenation with a colon separator. No quoting or escaping is applied. If either component is
   * {@code null}, the literal string {@code "null"} will appear in the output.
   *
   * @return A concise {@code key:filename} rendering intended for logs and diagnostics.
   */
  @Override
  public String toString() {
    return key + ":" + filename;
  }
}
