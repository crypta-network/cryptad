package network.crypta.client;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import network.crypta.keys.FreenetURI;

/**
 * Tracks archive traversal state during recursive fetch operations.
 *
 * <p>This context object accompanies a fetch that may descend into container formats (for example,
 * manifests or archives that reference other items). It records the set of archives that have been
 * visited so far and applies a simple upper bound on the allowed nesting depth. The main purpose is
 * to prevent accidental or malicious cycles such as an archive that indirectly references itself or
 * a pair of archives that reference each other.
 *
 * <p>Instances are lightweight and are intended to be created per logical fetch. The class is
 * mutable but synchronizes its public methods; callers may share a single instance across threads
 * in a pipeline without additional locking. Loop detection is based on the {@link FreenetURI}
 * values provided by the caller; equality and hash semantics are those of {@code FreenetURI}. A
 * {@code null} key is a valid set element and therefore can detect a repeated {@code null} input as
 * a loop as well.
 *
 * <ul>
 *   <li><strong>Responsibilities</strong>:
 *       <ul>
 *         <li>Remember previously seen archive identifiers for the current traversal.
 *         <li>Enforce a maximum number of distinct archive levels.
 *         <li>Provide a reset hook to clear accumulated state between independent traversals.
 *       </ul>
 * </ul>
 *
 * <p><strong>Serialization notice:</strong> this class implements {@link Serializable}. Changing
 * non-transient fields affects the serialized form and can cause existing downloads to restart or
 * uploads to be lost when upgrading persisted state.
 *
 * @author amphibian (Matthew Toseland)
 */
public class ArchiveContext implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Set of archive identifiers already observed in the current traversal.
   *
   * <p>The set is lazily allocated on the first call to {@link #doLoopDetection(FreenetURI)} and is
   * cleared by {@link #clear()}. Elements are compared using {@link FreenetURI} equality; a {@code
   * null} key is also a valid element and can therefore detect repeated {@code null} inputs as a
   * loop. The collection is used only from synchronized methods.
   */
  private HashSet<FreenetURI> soFar;

  /**
   * Maximum number of distinct archives permitted during a traversal.
   *
   * <p>The value is treated as a strict bound on the cardinality of {@link #soFar}: when the number
   * of distinct elements already stored exceeds this value, additional attempts to add a new
   * archive are rejected. Typical values are small (for example, 1–10) to protect against cycles.
   */
  final int maxArchiveLevels;

  /**
   * Upper bound on archive size in bytes as supplied by the caller.
   *
   * <p>The context stores this limit to keep related settings together; it does not itself enforce
   * the size bound. Higher layers in the client fetch pipeline use the value to reject overlarge
   * archives before or during processing.
   */
  final long maxArchiveSize;

  /**
   * Create a new context with explicit limits.
   *
   * <p>The context maintains a set of distinct archive identifiers seen so far. A size check is
   * performed before adding a new identifier; if the set already contains more than {@code max}
   * elements, loop detection fails even before the new key is added. This means a context with
   * {@code max=0} still accepts the first unique key and rejects the second.
   *
   * @param maxArchiveSize maximum archive size in bytes used by higher-level components to bound
   *     processing; this class stores the value but does not enforce it directly.
   * @param max maximum number of distinct archive levels allowed in a traversal before detection
   *     fails; non-negative values are expected and typical callers use small integers.
   */
  public ArchiveContext(long maxArchiveSize, int max) {
    this.maxArchiveLevels = max;
    this.maxArchiveSize = maxArchiveSize;
  }

  /**
   * No-arg constructor for serialization frameworks.
   *
   * <p>The constructed instance has both {@code maxArchiveLevels} and {@code maxArchiveSize} set to
   * {@code 0}. With these defaults, the context allows exactly one unique archive before reporting
   * too many levels on the next distinct input.
   */
  protected ArchiveContext() {
    // For serialization.
    maxArchiveLevels = 0;
    maxArchiveSize = 0;
  }

  /**
   * Check whether adding the given key would introduce a loop and record it if allowed.
   *
   * <p>The method lazily initializes the internal set on first use, verifies the current depth
   * limit, and then attempts to add the key. If the set already contains more than {@code
   * maxArchiveLevels} elements, an exception is thrown without modifying the set. If the key was
   * already present, the operation fails with a loop-detected exception. Otherwise, the key is
   * recorded and the method returns normally.
   *
   * @param key archive identifier used for loop detection; may be {@code null}. Equality and hash
   *     semantics follow {@link FreenetURI} (or {@code null}) and determine whether two inputs are
   *     considered the same archive.
   * @throws ArchiveFailureException when the number of distinct archives exceeds the configured
   *     limit, or when the same key is observed again within the current traversal.
   */
  public synchronized void doLoopDetection(FreenetURI key) throws ArchiveFailureException {
    if (soFar == null) {
      soFar = new HashSet<>();
    }
    if (soFar.size() > maxArchiveLevels)
      throw new ArchiveFailureException(ArchiveFailureException.TOO_MANY_LEVELS);
    if (!soFar.add(key)) {
      throw new ArchiveFailureException(ArchiveFailureException.ARCHIVE_LOOP_DETECTED);
    }
  }

  /**
   * Clear all accumulated state so a new traversal can start fresh.
   *
   * <p>After calling this method the context forgets all previously seen archives. A subsequent
   * call to {@link #doLoopDetection(FreenetURI)} with a key that was seen before clearing will be
   * treated as a first encounter.
   */
  public synchronized void clear() {
    soFar = null;
  }
}
