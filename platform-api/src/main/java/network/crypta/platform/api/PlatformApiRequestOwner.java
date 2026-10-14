package network.crypta.platform.api;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import network.crypta.platform.apphost.AppHost;
import network.crypta.runtime.spi.ContentFetchException;

/**
 * Isolates process-stop interrupts from reusable HTTP threads and retains exact launch ownership.
 */
@org.jetbrains.annotations.ApiStatus.Internal
public final class PlatformApiRequestOwner {
  private static final ScopedValue<CancellationContext> CANCELLATION = ScopedValue.newInstance();

  private PlatformApiRequestOwner() {}

  static PlatformApiResponse execute(
      AppHost host, PlatformApiRequest request, Supplier<PlatformApiResponse> route) {
    var principal = request.principal();
    if (host == null
        || principal.authSource() != PlatformApiAuthSource.APP_TOKEN
        || principal.launchId() == null
        || principal.launchId().isBlank()
        || !networkRoute(request)) return route.get();
    var result = new CompletableFuture<PlatformApiResponse>();
    Thread.ofVirtual()
        .name("app-network-request-owner")
        .uncaughtExceptionHandler((_, failure) -> result.completeExceptionally(failure))
        .start(() -> completeOwnedRequest(host, principal, route, result));
    try {
      // join preserves unrelated caller interrupts and does not make disconnection an owner cancel.
      return result.join();
    } catch (CompletionException failure) {
      if (failure.getCause() instanceof RuntimeException cause) throw cause;
      if (failure.getCause() instanceof Error cause) throw cause;
      throw new PlatformApiException(500, "internal_error", "Unexpected platform API failure.");
    }
  }

  private static void completeOwnedRequest(
      AppHost host,
      PlatformApiPrincipal principal,
      Supplier<PlatformApiResponse> route,
      CompletableFuture<PlatformApiResponse> result) {
    try {
      var registered = host.registerRequestOwner(principal.appId(), principal.launchId());
      if (registered.isEmpty()) {
        throw new PlatformApiException(
            401, "invalid_app_token", "App process is no longer running.");
      }
      PlatformApiResponse response;
      try (var owner = registered.orElseThrow()) {
        if (owner.cancellationRequested()) {
          throw new PlatformApiException(502, "content_fetch_failed", "Content fetch failed.");
        }
        response =
            ScopedValue.where(CANCELLATION, new CancellationContext(owner, new AtomicBoolean()))
                .call(route::get);
      }
      result.complete(response);
    } catch (IOException _) {
      result.completeExceptionally(
          new PlatformApiException(
              503, "app_request_owner_unavailable", "App request ownership is unavailable."));
    } catch (RuntimeException failure) {
      result.completeExceptionally(failure);
    }
  }

  /**
   * Consumes an interrupt already handled as cancellation of this dedicated request's native fetch.
   *
   * <p>The private scope is established only by the launch-bound router path. Cleanup requires the
   * AppHost lifecycle cancellation flag and a native interrupted failure carrying both an actual
   * cancellation request and its termination callback. It runs after callback/lease retention and
   * makes rejected-audit I/O possible without clearing any reusable HTTP caller's interrupt or
   * acknowledging native termination. Unowned, browser, timeout and unrelated interrupts remain
   * untouched; a handled cancellation can be consumed at most once.
   *
   * @param failure native asynchronous fetch failure whose causal stages have already been recorded
   * @return whether this dedicated owner thread's handled interrupt was consumed
   */
  public static boolean consumeHandledNativeCancellation(ContentFetchException failure) {
    if (!CANCELLATION.isBound()
        || !Thread.currentThread().isVirtual()
        || !failure.ownerCancellationRequested()
        || failure.ownerTermination() == null
        || !(failure.getCause() instanceof InterruptedException)) return false;
    var context = CANCELLATION.get();
    if (!context.owner().cancellationRequested() || !context.consumed().compareAndSet(false, true))
      return false;
    return Thread.interrupted();
  }

  private record CancellationContext(AppHost.RequestOwner owner, AtomicBoolean consumed) {}

  private static boolean networkRoute(PlatformApiRequest request) {
    List<String> path = request.pathSegments();
    return "POST".equals(request.method())
        && path.size() == 2
        && (("content".equals(path.getFirst()) && "fetch".equals(path.get(1)))
            || ("trust-graph".equals(path.getFirst())
                && ("import-uri".equals(path.get(1)) || "import-preview-uri".equals(path.get(1)))));
  }
}
