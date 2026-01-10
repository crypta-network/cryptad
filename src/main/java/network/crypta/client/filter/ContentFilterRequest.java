package network.crypta.client.filter;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Immutable request data for {@link ContentFilter#filter(ContentFilterRequest)}.
 *
 * <p>This record bundles the streams, MIME metadata, and optional callback used during filtering so
 * callers can pass a single object through higher-level APIs.
 *
 * @param input source stream providing the original bytes; must remain readable for the duration of
 *     filtering; not closed by the filter
 * @param output destination stream receiving filtered bytes; the filter flushes but does not close
 *     it
 * @param typeName declared MIME type of {@code input}; parameters are allowed and will be parsed
 * @param maybeCharset hint inherited from a referring document; used when the handler allows
 *     charset inference and no BOM or explicit declaration is present; may be {@code null}
 * @param schemeHostAndPort request authority (scheme, host, and port) for same-origin checks and
 *     rewriting decisions
 * @param filterCallback callback for link discovery, tag replacement, and completion; may be {@code
 *     null}
 */
public record ContentFilterRequest(
    InputStream input,
    OutputStream output,
    String typeName,
    String maybeCharset,
    String schemeHostAndPort,
    FilterCallback filterCallback) {

  /**
   * Returns a copy of this request with the provided callback.
   *
   * @param callback callback to associate with the request; may be {@code null}
   * @return a new {@link ContentFilterRequest} with the updated callback
   */
  public ContentFilterRequest withFilterCallback(FilterCallback callback) {
    return new ContentFilterRequest(
        input, output, typeName, maybeCharset, schemeHostAndPort, callback);
  }
}
