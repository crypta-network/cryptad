package network.crypta.clients.http.bridge;

import java.util.Objects;
import java.util.Set;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;

/**
 * Runtime-backed browse-content client adapter.
 *
 * <p>This bridge is the concrete implementation of the browse-local {@link BrowseContentClient}
 * seam. It keeps the runtime-owned {@link HighLevelSimpleClient} behind a narrow HTTP-facing
 * contract so browse code can compile without importing the wider client body from {@code
 * :runtime-node}. The adapter is intentionally thin: it forwards size-limit tuning and context
 * creation directly, wraps blocking fetches through a {@link FetchWaiter}, and preserves the
 * underlying insert and prefetch semantics.
 *
 * <p>Callers do not use this type directly outside bridge assembly. It exists as an internal
 * binding detail for the legacy HTTP stack, where a runtime-owned client must be exposed through a
 * leaf-safe interface. The class is package-private for that reason. It is also immutable after
 * construction because it stores only the wrapped client reference and no per-request state.
 */
final class CoreBrowseContentClient implements BrowseContentClient {
  /** Runtime-owned client that performs the actual fetch, insert, and prefetch work. */
  private final HighLevelSimpleClient client;

  /**
   * Creates a bridge over the supplied runtime client.
   *
   * <p>The constructor rejects {@code null} eagerly because every method delegates directly to the
   * wrapped client. Callers typically construct one instance during HTTP bootstrap and then pass it
   * into browse-owned route registrars and toadlets as their content client dependency.
   *
   * @param client runtime-owned high-level client that will satisfy browse-content requests
   */
  CoreBrowseContentClient(HighLevelSimpleClient client) {
    this.client = Objects.requireNonNull(client, "client");
  }

  @Override
  public void setMaxLength(long maxLength) {
    client.setMaxLength(maxLength);
  }

  @Override
  public void setMaxIntermediateLength(long maxIntermediateLength) {
    client.setMaxIntermediateLength(maxIntermediateLength);
  }

  @Override
  public FetchContext getFetchContext() {
    return client.getFetchContext();
  }

  @Override
  public FetchContext getFetchContext(long maxSize, String schemeHostAndPort) {
    return client.getFetchContext(maxSize, schemeHostAndPort);
  }

  @Override
  public FetchResult fetch(FreenetURI uri, RequestClient requestClient, FetchContext fetchContext)
      throws FetchException {
    FetchWaiter waiter = new FetchWaiter(Objects.requireNonNull(requestClient, "requestClient"));
    client.fetch(Objects.requireNonNull(uri, "uri"), waiter, Objects.requireNonNull(fetchContext));
    return waiter.waitForCompletion();
  }

  @Override
  public FreenetURI insert(InsertBlock insert, boolean getChkOnly, String filenameHint)
      throws InsertException {
    return client.insert(Objects.requireNonNull(insert, "insert"), getChkOnly, filenameHint);
  }

  @Override
  public void prefetch(
      FreenetURI uri, long timeoutMillis, long maxSize, Set<String> allowedMimeTypes) {
    client.prefetch(Objects.requireNonNull(uri, "uri"), timeoutMillis, maxSize, allowedMimeTypes);
  }
}
