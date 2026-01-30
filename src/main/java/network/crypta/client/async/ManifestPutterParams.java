package network.crypta.client.async;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import network.crypta.client.InsertContext;
import network.crypta.keys.FreenetURI;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the shared construction arguments for manifest putters.
 *
 * <p>This record collects the common inputs required to construct manifest putters such as {@link
 * DefaultManifestPutter} and {@link PlainManifestPutter}. Typical call sites assemble the manifest
 * tree, select a priority class and target {@link FreenetURI}, then pass this bundle to a putter
 * constructor alongside any mode-specific flags (for example, persistence). It is intentionally
 * lightweight: it performs no validation, transformation, or defensive copying, so callers and the
 * receiving putter determine how and when values are checked or copied.
 *
 * <p>Because the record carries references, its thread-safety depends on the referenced objects.
 * The record instance itself is immutable, but mutable inputs such as the manifest map or the
 * crypto key byte array can be modified by external code. If shared across threads, callers should
 * provide appropriately safe, stable inputs. Equality and hashing compare array contents for the
 * crypto key to avoid reference-only comparisons.
 *
 * <ul>
 *   <li>Groups parameters that are repeated across manifest putter constructors.
 *   <li>Preserves existing semantics by avoiding validation or copying.
 *   <li>Supports content-based equality for the optional crypto key.
 * </ul>
 *
 * @param clientCallback callback receiver for progress and completion events; must remain valid for
 *     the putter lifetime and may be {@code null} if callers allow it.
 * @param manifestElements manifest tree of entry names to elements or sub-maps; contents are
 *     interpreted by the target putter without additional normalization here.
 * @param prioClass scheduler priority class for the request; valid values depend on scheduler
 *     configuration and must match the caller’s intent.
 * @param target target URI for the root manifest; typically an SSK or CHK-like {@link FreenetURI}.
 * @param defaultName default document name for directory levels; may be {@code null} when no
 *     default document should be inferred.
 * @param ctx insert context providing retry, chunking, and compatibility settings; must align with
 *     the caller’s overall insertion policy.
 * @param forceCryptoKey optional explicit splitfile key material; {@code null} means the putter may
 *     derive or randomize keys as needed.
 * @param context client context providing randomness and scheduling services; expected to be
 *     non-{@code null} during putter execution.
 */
public record ManifestPutterParams(
    ClientPutCallback clientCallback,
    Map<String, Object> manifestElements,
    short prioClass,
    FreenetURI target,
    String defaultName,
    InsertContext ctx,
    byte[] forceCryptoKey,
    ClientContext context) {
  /**
   * Compares this parameter bundle to another for structural equality.
   *
   * <p>All reference fields are compared using their {@link Object#equals(Object)} implementations,
   * while the {@code forceCryptoKey} array is compared by content. The method does not treat any
   * field as optional beyond normal {@code null} handling, and it does not attempt to validate or
   * normalize values. As a result, two bundles created from distinct but equal maps or URIs will be
   * considered equal, while identity-different arrays with the same bytes will also be equal.
   *
   * @param o candidate object to compare with this bundle; may be {@code null}.
   * @return {@code true} when all fields are equal by the rules above, otherwise {@code false}.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        ManifestPutterParams(
            ClientPutCallback otherClientCallback,
            Map<String, Object> otherManifestElements,
            short otherPrioClass,
            FreenetURI otherTarget,
            String otherDefaultName,
            InsertContext otherCtx,
            byte[] otherForceCryptoKey,
            ClientContext otherContext))) return false;
    return prioClass == otherPrioClass
        && Objects.equals(clientCallback, otherClientCallback)
        && Objects.equals(manifestElements, otherManifestElements)
        && Objects.equals(target, otherTarget)
        && Objects.equals(defaultName, otherDefaultName)
        && Objects.equals(ctx, otherCtx)
        && Arrays.equals(forceCryptoKey, otherForceCryptoKey)
        && Objects.equals(context, otherContext);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash uses {@link Objects#hash(Object...)} for reference fields and {@link
   * Arrays#hashCode(byte[])} for the crypto key array to preserve content-based semantics. This is
   * suitable for use in hash-based collections as long as callers do not mutate referenced objects
   * that participate in equality.
   *
   * @return hash code derived from all record components, including the array contents.
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            clientCallback, manifestElements, prioClass, target, defaultName, ctx, context);
    result = 31 * result + Arrays.hashCode(forceCryptoKey);
    return result;
  }

  /**
   * Returns a human-readable representation of the bundle for diagnostics.
   *
   * <p>The string includes all record components in declaration order and renders the crypto key
   * using {@link Arrays#toString(byte[])} for byte-content visibility. It is intended for logging
   * and debugging and should not be parsed or used for security-sensitive output.
   *
   * @return descriptive string including component values and the crypto key contents.
   */
  @Override
  public @NotNull String toString() {
    return "ManifestPutterParams{"
        + "clientCallback="
        + clientCallback
        + ", manifestElements="
        + manifestElements
        + ", prioClass="
        + prioClass
        + ", target="
        + target
        + ", defaultName="
        + defaultName
        + ", ctx="
        + ctx
        + ", forceCryptoKey="
        + Arrays.toString(forceCryptoKey)
        + ", context="
        + context
        + '}';
  }
}
