package network.crypta.client.async;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import network.crypta.client.InsertContext;
import network.crypta.keys.FreenetURI;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles shared construction arguments for manifest putters.
 *
 * <p>This class is a small, immutable container that groups the inputs repeatedly required when
 * constructing manifest putters such as {@link DefaultManifestPutter} and {@link
 * PlainManifestPutter}. Callers typically build a manifest tree, choose a scheduler priority, and
 * select a target {@link FreenetURI}; those values are captured alongside a {@link InsertContext},
 * an optional crypto key override, and the runtime {@link ClientContext}. The bundle is
 * intentionally lightweight and does not validate or normalize inputs. The optional crypto key is
 * defensively copied at construction and on read; other references are retained as provided so
 * callers and downstream putters remain responsible for enforcing invariants.
 *
 * <p>Thread-safety is entirely determined by the referenced objects. The instance itself is
 * immutable, but values like the manifest map or the crypto key array can be mutated externally; if
 * the same instance is shared across threads, supply stable, thread-safe references. Equality and
 * hashing are structural and compare the crypto key by content to avoid reference-only comparisons.
 *
 * <ul>
 *   <li>Collects shared inputs for manifest putter construction and reuse.
 *   <li>Preserves legacy behavior by storing references without validation or copying.
 *   <li>Defines equality and hashing that include byte-array contents.
 * </ul>
 */
public final class ManifestPutterParams {
  private final InsertRequestParams requestParams;
  private final Map<String, Object> manifestElements;
  private final String defaultName;
  private final byte[] forceCryptoKey;
  private final ClientContext context;

  /**
   * Creates a parameter bundle for manifest putter construction.
   *
   * <p>This constructor simply stores the provided references and does not validate them. Callers
   * should ensure that required references are non-null and remain valid for the lifetime of the
   * putter. Any mutable inputs (for example, the manifest map or crypto key bytes) should not be
   * modified in ways that could affect downstream behavior. The bundle is designed for reuse across
   * constructors. The core configuration is assembled once and passed unchanged.
   *
   * <pre>{@code
   * var params = new ManifestPutterParams(
   *     new InsertRequestParams(cb, target, ctx, prio),
   *     manifest,
   *     defaultName,
   *     forceKey,
   *     context);
   * }</pre>
   *
   * @param requestParams shared insert request parameters including callback, target URI, and
   *     scheduling priority; may be {@code null} only if callers tolerate downstream failures.
   * @param manifestElements manifest tree of entry names to elements or sub-maps; stored by
   *     reference and interpreted by the target putter without normalization.
   * @param defaultName default document name for directory levels; may be {@code null} to disable
   *     default document inference by the putter.
   * @param forceCryptoKey optional explicit splitfile key material; copied when non-null.
   * @param context client context providing randomness and scheduling services; expected to be
   *     non-{@code null} during putter execution.
   */
  public ManifestPutterParams(
      InsertRequestParams requestParams,
      Map<String, Object> manifestElements,
      String defaultName,
      byte[] forceCryptoKey,
      ClientContext context) {
    this.requestParams = requestParams;
    this.manifestElements = manifestElements;
    this.defaultName = defaultName;
    this.forceCryptoKey = copyNullable(forceCryptoKey);
    this.context = context;
  }

  /**
   * Returns the callback used for progress and completion notifications.
   *
   * <p>The callback reference is sourced from {@link InsertRequestParams} and is returned as-is
   * without any validation or wrapping. Callers should treat the returned reference as a mutable
   * external state and avoid assuming thread-safety beyond what the callback implementation
   * guarantees. The value may be {@code null} if a caller supplied a null callback and the
   * downstream putter tolerates that configuration.
   *
   * @return the callback reference for insert lifecycle events, possibly {@code null}.
   */
  public ClientPutCallback clientCallback() {
    return requestParams.callback();
  }

  /**
   * Returns the manifest tree that maps entry names to elements or nested maps.
   *
   * <p>The returned map is the exact reference passed at construction time. No defensive copy is
   * created and no normalization is applied here, so callers should avoid mutating the map after
   * construction unless they explicitly intend to affect the downstream putter. If the map is
   * shared across threads, it must be safe for concurrent access or external synchronization should
   * be applied.
   *
   * @return the manifest element map reference; may be {@code null} if constructed that way.
   */
  public Map<String, Object> manifestElements() {
    return manifestElements;
  }

  /**
   * Returns the scheduler priority class for the insert request.
   *
   * <p>The priority value is forwarded directly from {@link InsertRequestParams}. This class does
   * not validate the value or enforce any ranges; it is interpreted by the scheduler in the
   * surrounding client context. Callers should supply a priority consistent with local policy and
   * should not expect this class to clamp or normalize the value.
   *
   * @return the priority class for scheduling, as originally provided by the caller.
   */
  public short prioClass() {
    return requestParams.priorityClass();
  }

  /**
   * Returns the target URI for the root manifest insert.
   *
   * <p>The URI is returned by reference and should be suitable for insertion (for example, a CHK or
   * SSK-like key). No validation is performed here, so any parsing or key-type checks are the
   * responsibility of the caller or the downstream putter. If the URI instance is mutable or
   * shared, callers must ensure it remains stable during use.
   *
   * @return the target {@link FreenetURI} used for the manifest insert, possibly {@code null}.
   */
  public FreenetURI target() {
    return requestParams.targetURI();
  }

  /**
   * Returns the default document name used for directory entries.
   *
   * <p>This value indicates which file name should be treated as the default document within each
   * directory level when a manifest is constructed. The value is stored without normalization and
   * may be {@code null} to indicate that no default document inference should occur. Consumers
   * should apply any required checks before relying on this value.
   *
   * @return the default document name, or {@code null} if no default is configured.
   */
  public String defaultName() {
    return defaultName;
  }

  /**
   * Returns the insert context that controls retry, compression, and compatibility policies.
   *
   * <p>The context reference is passed through from {@link InsertRequestParams} and is not copied.
   * It should remain valid and consistent for the lifetime of the insert operation that consumes
   * this bundle. If the context is mutable, callers must avoid changing settings in ways that could
   * invalidate the assumptions of a running putter.
   *
   * @return the insert context reference used by the manifest putter, possibly {@code null}.
   */
  public InsertContext ctx() {
    return requestParams.insertContext();
  }

  /**
   * Returns the explicit splitfile crypto key override, if any.
   *
   * <p>The returned array is a defensive copy. When provided, downstream putters may use these
   * bytes as deterministic key material; when {@code null}, they may derive or randomize a key as
   * needed.
   *
   * @return the crypto key byte array reference, or {@code null} if no override is set.
   */
  public byte[] forceCryptoKey() {
    return copyNullable(forceCryptoKey);
  }

  private static byte[] copyNullable(byte[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
  }

  /**
   * Returns the runtime client context used for randomness and scheduling services.
   *
   * <p>The context reference is stored without validation and is expected to remain non-null and
   * operational when the putter uses it. This bundle does not synchronize access to the context, so
   * callers should ensure the instance is safe for concurrent use according to its contract.
   *
   * @return the client context reference for execution services, possibly {@code null}.
   */
  public ClientContext context() {
    return context;
  }

  /**
   * Compares this parameter bundle to another for structural equality.
   *
   * <p>All reference fields are compared using their {@link Object#equals(Object)} implementations,
   * while the {@code forceCryptoKey} array is compared by content rather than reference. This
   * method does not validate or normalize inputs and does not treat any field as optional beyond
   * normal {@code null} handling. Two bundles created from distinct but equal maps, URIs, or
   * contexts are therefore considered equal, and different byte arrays with identical contents are
   * considered equal as well.
   *
   * @param o candidate object to compare with this bundle; may be {@code null}.
   * @return {@code true} when all fields are equal by the rules above, otherwise {@code false}.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ManifestPutterParams other)) return false;
    return Objects.equals(requestParams, other.requestParams)
        && Objects.equals(manifestElements, other.manifestElements)
        && Objects.equals(defaultName, other.defaultName)
        && Arrays.equals(forceCryptoKey, other.forceCryptoKey)
        && Objects.equals(context, other.context);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash incorporates all fields, using {@link Objects#hash(Object...)} for reference
   * components and {@link Arrays#hashCode(byte[])} for the crypto key array so that byte contents
   * participate in the hash. This makes the object suitable for hash-based collections as long as
   * callers avoid mutating referenced objects or the crypto key array after the bundle is used as a
   * key, because such mutations would violate the hash/equals contract.
   *
   * @return hash code derived from all components, including the crypto key contents.
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(requestParams, manifestElements, defaultName, context);
    result = 31 * result + Arrays.hashCode(forceCryptoKey);
    return result;
  }

  /**
   * Returns a human-readable representation of the bundle for diagnostics.
   *
   * <p>The string includes all components in declaration order and renders the crypto key using
   * {@link Arrays#toString(byte[])} so byte contents are visible. The output is intended for
   * logging and debugging and should not be parsed or used for security-sensitive decisions.
   * Because the result includes potentially sensitive values, callers should take care when
   * emitting it to untrusted logs or user-visible channels.
   *
   * @return descriptive string including component values and the crypto key contents.
   */
  @Override
  public @NotNull String toString() {
    return "ManifestPutterParams{"
        + "clientCallback="
        + requestParams.callback()
        + ", manifestElements="
        + manifestElements
        + ", prioClass="
        + requestParams.priorityClass()
        + ", target="
        + requestParams.targetURI()
        + ", defaultName="
        + defaultName
        + ", ctx="
        + requestParams.insertContext()
        + ", forceCryptoKey="
        + Arrays.toString(forceCryptoKey)
        + ", context="
        + context
        + '}';
  }
}
