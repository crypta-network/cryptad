package network.crypta.client.filter;

import java.net.URI;
import network.crypta.keys.FreenetURI;

/**
 * Callback interface used by content scanners, decoders, and crawlers to report items discovered
 * while processing a single logical page or document.
 *
 * <p>Implementations typically aggregate the reported data (for example, building an index, a link
 * graph, or a fetch queue) and may apply additional filtering or normalization. The contract
 * intentionally avoids prescribing ordering beyond basic causality: methods can be called multiple
 * times as the parser advances, and {@link #onFinishedPage()} signals that no further callbacks
 * will be made for the current page. Implementations should therefore treat the interface as a
 * stream of events rather than a random-access model.
 *
 * <p>Thread-safety is implementation defined. Unless otherwise documented by the caller, you should
 * not assume that invocations are serialized; if a shared state is mutated, synchronize or use
 * concurrent collections. Implementations are generally expected to be stateless or to scope state
 * to the current page between the first event and {@code onFinishedPage()}.
 *
 * <ul>
 *   <li>URI discovery: {@link #foundURI(FreenetURI)} and {@link #foundURI(FreenetURI, boolean)}
 *       report links and embedded resources.
 *   <li>Text capture: {@link #onText(String, String, URI)} exposes decoded text for indexing or
 *       analysis.
 *   <li>Lifecycle: {@link #onFinishedPage()} marks the end of processing for the current page.
 * </ul>
 */
public interface FoundURICallback {

  /**
   * Report that a Freenet URI has been discovered in the current document.
   *
   * <p>Callers use this to notify about hyperlinks or resources whose precise role may be
   * determined by the implementation (for example, enqueueing for retrieval, deduplication, or
   * indexing). Implementations should not assume uniqueness; the same URI can be reported more than
   * once. The method is idempotent with respect to side effects only if the implementation makes it
   * so; callers may not perform duplicate suppression.
   *
   * @param uri The URI. Consider clarifying how the caller communicates link semantics when richer
   *     metadata is available.
   */
  void foundURI(FreenetURI uri);

  /**
   * Report that a Freenet URI has been discovered, including a basic hint about its presentation
   * context within the page.
   *
   * <p>This variant carries an {@code inline} flag to help distinguish embedded resources from
   * navigational links in simple pipelines. The flag is advisory only. Implementations may ignore
   * it or use it to prioritize fetching, indexing, or display decisions. Callers may repeat the
   * same URI with different flags as they encounter it in multiple contexts.
   *
   * @param uri The URI. Consider clarifying how the caller communicates link semantics when richer
   *     metadata is available.
   * @param inline {@code true} when the URI appears as an inline/embedded resource in the current
   *     context (such as an image, stylesheet, or script); {@code false} when it is a navigational
   *     link or otherwise not rendered inline. Callers may pass either value; implementations
   *     should accept both without throwing and treat {@code null}-like semantics as absent.
   */
  void foundURI(FreenetURI uri, boolean inline);

  /**
   * Called when some plain text is processed. Spiders use this typically to index pages by their
   * content.
   *
   * <p>The supplied text has already been decoded according to the source format (for example, HTML
   * entity decoding if extracted from HTML). Implementations that forward text to a consumer which
   * expects display-ready data should re-encode as appropriate for that consumer.
   *
   * @param text The text. Will already have been fed through whatever decoding is necessary
   *     depending on the type of the source document e.g., HTMLDecoder. Will need to be re-encoded
   *     before being sent to e.g., a browser.
   * @param type Can be null, or may be, for example, the name of the HTML tag directly surrounding
   *     the text. E.g. "title" lets you find page titles.
   * @param baseURI The current base URI for this page. The base URI is not necessarily the URI of
   *     the page. It's the URI against which URIs on the page are resolved. It defaults to the URI
   *     of the page but can be overridden by base href in HTML, for example.
   */
  void onText(String text, String type, URI baseURI);

  /**
   * Signal that no more callbacks will be issued for the current page or document.
   *
   * <p>Callers invoke this exactly once per processed page after all {@code foundURI(...)} and
   * {@link #onText(String, String, URI)} events have been delivered. Implementations may use this
   * hook to flush buffers, commit accumulated state, or release resources associated with the page.
   * No further methods on this interface will be called for the same page after this signal.
   */
  void onFinishedPage();
}
