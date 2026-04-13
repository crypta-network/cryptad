package network.crypta.client;

import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;

/**
 * Validates insert-target URIs at the client layer.
 *
 * <p>This adapter keeps insert-specific policy checks close to the client APIs that actually
 * perform inserts. The corresponding {@link FreenetURI} type stays focused on key parsing and key
 * transformations, while insert-specific failure reporting remains in {@code network.crypta.client}
 * where {@link InsertException} and {@link InsertExceptionMode} already define the public error
 * surface.
 *
 * <p>The current helper set is intentionally small. Callers use these methods immediately before
 * constructing insert jobs or accepting operator-provided target URIs, which keeps validation
 * consistent across HTTP, FCP, and asynchronous client flows without reintroducing a keys-to-client
 * dependency.
 */
public final class InsertUriChecks {

  /** Prevents instantiation of this comments-only validation utility. */
  private InsertUriChecks() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Verifies that the URI does not contain meta strings.
   *
   * <p>Insert requests accept a concrete key target, not a URI with additional meta-string path
   * components. When such components are present, the method throws the same client-layer exception
   * and mode that legacy insert validation used, so higher layers keep their existing behavior and
   * error handling.
   *
   * @param uri insert target to validate before starting client-side insert work
   * @throws InsertException if the URI carries meta strings that inserts do not support
   */
  public static void checkInsertURI(FreenetURI uri) throws InsertException {
    if (uri.hasMetaStrings()) {
      throw new InsertException(InsertExceptionMode.META_STRINGS_NOT_SUPPORTED, uri);
    }
  }
}
