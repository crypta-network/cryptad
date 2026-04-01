package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.InsertException;
import network.crypta.node.RequestClient;

/**
 * Asynchronous manifest insertion facade.
 *
 * <p>This abstract type defines the minimal surface that implementations use to insert a
 * directory-like "manifest" into the network. A manifest typically refers to a set of files and
 * sub-entries that are prepared and scheduled for insertion by the client stack. The instance
 * exposes coarse-grained metrics such as the number of files and the total byte size, and provides
 * a single entry point, {@link #start(ClientContext)}, to begin the asynchronous insertion flow.
 *
 * <p>Typical usage follows a simple pattern: construct a concrete {@code ManifestPutter} (e.g.
 * {@link DefaultManifestPutter} or {@link PlainManifestPutter}), configure it as needed, and call
 * {@link #start(ClientContext)} once to hand control to the client scheduler. After starting,
 * progress and error reporting are generally mediated by the {@link RequestClient} supplied at
 * construction time; concrete implementations decide how callbacks and persistence are wired.
 *
 * <p>Unless a subclass documents stronger guarantees, instances should be treated as
 * single-threaded and not assumed to be thread-safe. Implementations are free to internally queue
 * work and may perform I/O; consumers should assume that insertion can be long-running and that
 * counts and sizes are best-effort estimates without protocol overhead.
 *
 * <ul>
 *   <li>Responsibilities: provide counts/sizes and initiate the put operation.
 *   <li>Notable behavior: {@link #getSplitfileCryptoKey()} may return {@code null} when not
 *       applicable.
 *   <li>Lifecycle: construct → optionally inspect metrics → {@link #start(ClientContext)} → observe
 *       completion via client callbacks.
 * </ul>
 *
 * @see BaseClientPutter
 * @see DefaultManifestPutter
 * @see PlainManifestPutter
 */
public abstract class ManifestPutter extends BaseClientPutter {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * No-args constructor for serialization frameworks and subclass deserialization.
   *
   * <p>This constructor exists because a parent type implements {@link Serializable}. Concrete
   * subclasses typically expose public constructors with meaningful parameters; this one is
   * intended solely for frameworks that require a no-argument constructor.
   */
  @SuppressWarnings("unused")
  protected ManifestPutter() {}

  /**
   * Creates a new putter with the given scheduling priority and client identity.
   *
   * <p>The {@code priorityClass} influences how the client request scheduler orders this job
   * relative to others owned by the same {@link RequestClient}. The exact numeric ranges and
   * semantics are defined by the scheduler; higher-level code should pass a value consistent with
   * the surrounding request policy.
   *
   * @param priorityClass a scheduler priority hint; accepted values depend on the client policy.
   *     Use a value that reflects urgency; negative values are typically not meaningful.
   * @param requestClient the logical client that owns this request, used for accounting and
   *     callbacks; must be a valid, non-transient instance for the duration of the operation.
   */
  protected ManifestPutter(short priorityClass, RequestClient requestClient) {
    super(priorityClass, requestClient);
  }

  /**
   * Returns the number of files that will be inserted by this manifest.
   *
   * <p>This is a count of content files the implementation plans to publish as part of the
   * manifest. It may exclude directory entries and protocol overhead, and the value can be computed
   * lazily by implementations.
   *
   * @return a non-negative count describing how many content files are expected to be inserted; the
   *     value may be an estimate depending on the implementation strategy.
   */
  public abstract int countFiles();

  /**
   * Returns the total byte size of the content to be inserted.
   *
   * <p>The size represents the sum of the raw content bytes of all files referenced by the
   * manifest. It typically does not include protocol overhead, metadata, or
   * encryption/authentication tags. Implementations may compute this eagerly or lazily depending on
   * available information.
   *
   * @return a non-negative number of bytes representing the total content size; special values such
   *     as zero indicate an empty manifest or unknown size when used consistently by a subclass.
   */
  public abstract long totalSize();

  /**
   * Starts the asynchronous insertion of this manifest within the provided client context.
   *
   * <p>Implementations initiate whatever work is necessary to publish the manifest and its
   * referenced entries. The call typically returns promptly after queuing the operation; actual
   * progress and completion are orchestrated by the client stack. Unless a subclass specifies
   * otherwise, callers should only invoke this method once per instance.
   *
   * <pre>{@code
   * // Example: typical call path
   * ManifestPutter putter = /* obtain a concrete putter * / ...;
   * putter.start(context);
   * }</pre>
   *
   * @param context the client execution context that provides resources and scheduling for the
   *     operation; must be compatible with the implementation’s expectations and remain valid for
   *     the duration of the insertion.
   * @throws InsertException if the operation cannot be started due to configuration, validation, or
   *     environment problems detected before or during initial scheduling.
   */
  public abstract void start(ClientContext context) throws InsertException;

  /**
   * Returns the symmetric key used to encrypt splitfile content, when available.
   *
   * <p>Some implementations insert data using a splitfile format that may be encrypted with a
   * caller-visible key. When such a key exists, this method returns a byte array containing it;
   * otherwise it returns {@code null}. Callers should treat the returned array as sensitive and
   * immutable and, if needed, copy it before retaining.
   *
   * @return a byte array containing the splitfile encryption key, or {@code null} if encryption is
   *     not used or the key is not exposed by the implementation. The caller should not modify the
   *     returned array in place.
   */
  @SuppressWarnings("java:S1168")
  public byte[] getSplitfileCryptoKey() {
    return null;
  }
}
