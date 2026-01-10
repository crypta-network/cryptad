package network.crypta.client.filter;

import java.net.URI;

/**
 * Collects optional callbacks and context used when filtering discovers or rewrites links.
 *
 * <p>The encapsulated data is passed to {@link GenericReadFilterCallback} so that the filter
 * pipeline can report discovered URIs and perform tag substitutions consistently.
 *
 * @param baseURI base URI used to resolve relative references during filtering
 * @param foundUriCallback callback notified for each discovered URI; may be {@code null}
 * @param tagReplacerCallback callback used to replace or rewrite markup tokens; may be {@code null}
 * @param linkFilterExceptionProvider provider for constructing link-filter exceptions; may be
 *     {@code null}
 */
public record ContentFilterCallbacks(
    URI baseURI,
    FoundURICallback foundUriCallback,
    TagReplacerCallback tagReplacerCallback,
    LinkFilterExceptionProvider linkFilterExceptionProvider) {

  /**
   * Builds a {@link FilterCallback} that wraps the configured link processing callbacks.
   *
   * @return a {@link FilterCallback} suitable for {@link
   *     ContentFilter#filter(ContentFilterRequest)}
   */
  public FilterCallback toFilterCallback() {
    return new GenericReadFilterCallback(this);
  }
}
