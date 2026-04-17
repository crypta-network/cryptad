package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.client.InsertUriChecks;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;

/**
 * Browse-owned HTTP toadlet base that retains the shared high-level client helper.
 *
 * <p>This class is the browse-side counterpart to the now content-neutral admin-owned {@link
 * Toadlet} base. The shared shell still owns route dispatch, reply helpers, and general HTTP
 * presentation logic, while browse-owned routes continue to need direct access to the legacy
 * high-level client for content fetches, insert requests, and fetch-context creation. Keeping those
 * operations here lets the boundary stay explicit: admin code no longer imports the client
 * contracts, and browse code keeps the remaining runtime-node coupling in one local place.
 *
 * <p>Subclasses typically use this base when they render or mutate network-backed content during a
 * request. The helper methods intentionally keep the historic blocking behavior of legacy browse
 * toadlets. Callers should therefore continue to use them only in request paths that already expect
 * synchronous fetch or insert work, and should prefer detached runtime ports elsewhere when a
 * narrower seam is available.
 *
 * <ul>
 *   <li>Owns the shared browse-content client for browse-only toadlets.
 *   <li>Preserves the legacy-blocking fetch and insert helper shape.
 *   <li>Keeps runtime-node content-client contracts out of admin-owned shell classes.
 * </ul>
 *
 * @see Toadlet
 * @see BrowseContentClient
 */
public abstract class ContentToadlet extends Toadlet {
  final BrowseContentClient client;

  /**
   * Creates a browse-owned toadlet bound to the shared high-level client.
   *
   * <p>The supplied client is typically created once during browse bootstrap and then reused across
   * multiple browse-owned toadlets so they share fetch defaults, request attribution, and insert
   * behavior. The base stores only the client reference; it does not perform I/O during
   * construction and does not create derived contexts eagerly.
   *
   * @param client shared browse-side high-level client used for fetch-context creation, blocking
   *     fetches, and inserts
   * @throws NullPointerException if {@code client} is {@code null}
   */
  protected ContentToadlet(BrowseContentClient client) {
    this.client = Objects.requireNonNull(client, "client");
  }

  /**
   * Performs a blocking fetch using the shared browse-side client.
   *
   * <p>The helper preserves the historical legacy HTTP behavior: if {@code maxSize} is positive, it
   * applies that value to both output and temporary-length limits on the supplied fetch context,
   * then performs the fetch synchronously through the shared browse-side client. The
   * caller-provided {@link RequestClient} is reused for request attribution and scheduler grouping.
   *
   * @param uri content URI to fetch for the current request
   * @param maxSize maximum number of bytes to allow for the fetched output and temporary data;
   *     non-positive values leave the existing context limits unchanged
   * @param clientContext request identity used by the waiter and scheduler for this fetch
   * @param fctx mutable fetch context to use for the request
   * @return completed fetch result returned by the shared client after the waiter observes success
   * @throws FetchException if the fetch fails, is canceled, or the waiter reports an error
   */
  FetchResult fetch(FreenetURI uri, long maxSize, RequestClient clientContext, FetchContext fctx)
      throws FetchException {
    if (maxSize > 0) {
      fctx.setMaxOutputLength(maxSize);
      fctx.setMaxTempLength(maxSize);
    }
    return client.fetch(uri, clientContext, fctx);
  }

  /**
   * Returns a fresh fetch context derived from the shared browse-side client.
   *
   * <p>Browse-owned toadlets use this to get the same baseline fetch policy the shared client would
   * use elsewhere, while still allowing per-request size limits and scheme/host hints to be applied
   * by callers. The returned context remains mutable and caller-owned after creation.
   *
   * @param maxSize requested maximum output size for the derived context
   * @param schemeHostAndPort scheme, host, and port string used when the client derives request
   *     context defaults for the current origin
   * @return fetch context created by the shared high-level client for one request
   */
  FetchContext getFetchContext(long maxSize, String schemeHostAndPort) {
    return client.getFetchContext(maxSize, schemeHostAndPort);
  }

  /**
   * Performs a blocking insert using the shared browse-side client.
   *
   * <p>The helper validates that the supplied {@link InsertBlock} carries a non-null desired URI
   * and that the URI is acceptable for legacy insert handling before delegating to the shared
   * client. It preserves the historic single-file insert behavior by requesting a normal insert
   * rather than a CHK-only computation.
   *
   * @param insert insert payload, metadata, and desired target URI for the operation
   * @param filenameHint optional filename hint used by the client when it derives manifest details
   * @return final URI returned by the shared high-level client after the insert completes
   * @throws InsertException if URI validation fails or the insert does not complete successfully
   * @throws NullPointerException if {@code insert.desiredURI} is {@code null}
   */
  FreenetURI insert(InsertBlock insert, String filenameHint) throws InsertException {
    FreenetURI desiredURI = Objects.requireNonNull(insert.desiredURI, "InsertBlock.desiredURI");
    InsertUriChecks.checkInsertURI(desiredURI);
    return client.insert(insert, false, filenameHint);
  }

  /**
   * Exposes the underlying high-level client for browse-owned subclasses that still need it.
   *
   * <p>Most subclasses should prefer the narrower helper methods on this base, but some legacy
   * browse-owned code still needs direct access to client operations or client-level configuration.
   * The returned instance is the same shared client that the constructor received.
   *
   * @return shared browse-side high-level client backing this toadlet
   */
  @SuppressWarnings("unused")
  protected BrowseContentClient getClientImpl() {
    return client;
  }
}
