package network.crypta.platform.api;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.fs.AppEnv;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Real signed app lifecycle with a controlled asynchronous port; no installed daemon claim. */
class PlatformApiRequestOwnerIntegrationTest {
  private static final String APP = "request-owner";
  private static final List<String> PERMISSIONS =
      List.of("content.fetch", "trust.read", "trust.write");

  @ParameterizedTest
  @ValueSource(
      strings = {"content/fetch", "trust-graph/import-uri", "trust-graph/import-preview-uri"})
  void processStopReachesFetchOwnerAndKeepsBudgetUntilNativeAcknowledgment(
      String route, @TempDir Path root) throws Exception {
    var host = signedHost(root);
    host.start(APP);
    var launch = host.currentLaunch(APP).orElseThrow();
    var principal = PlatformApiPrincipal.appToken(APP, launch.permissions(), launch.launchId());
    var entered = new CountDownLatch(1);
    var interruptSeen = new AtomicBoolean();
    var termination = new CompletableFuture<Void>();
    var httpInterrupted = new AtomicBoolean();
    ContentFetchPort port =
        request -> {
          assertTrue(Thread.currentThread().isVirtual());
          entered.countDown();
          try {
            if (!new CountDownLatch(1).await(10, TimeUnit.SECONDS)) {
              throw new AssertionError("bounded owner cancellation was not delivered");
            }
          } catch (InterruptedException cause) {
            Thread.currentThread().interrupt();
            interruptSeen.set(true);
            throw new ContentFetchException(
                ContentFetchException.CATALOG_FETCH_FAILED,
                "controlled owner cancellation",
                cause,
                termination,
                true);
          }
          throw new AssertionError("unreachable owner wait");
        };
    var budget =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(root.resolve("budget")),
            AppNetworkBudgetConfig.defaults());
    var router = router(host, port, budget, root);
    var response = new CompletableFuture<PlatformApiResponse>();
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                response.complete(router.route(request(route, principal)));
                httpInterrupted.set(Thread.currentThread().isInterrupted());
              } catch (Throwable failure) {
                response.completeExceptionally(failure);
              }
            });
    try {
      assertTrue(entered.await(10, TimeUnit.SECONDS));
      assertTrue(host.stop(APP));
      var failed = response.get(10, TimeUnit.SECONDS);
      assertEquals(502, failed.statusCode());
      assertTrue(failed.body().contains("\"code\":\"content_fetch_failed\""));
      if (!route.equals("content/fetch")) {
        var graph = new FileTrustGraphStore(root.resolve("graph"));
        assertTrue(
            graph.auditEvents(10).stream()
                .anyMatch(event -> "content_fetch_failed".equals(event.statusCode())));
      }
      assertTrue(interruptSeen.get());
      assertFalse(httpInterrupted.get());
      assertFalse(termination.isDone());
      int heldFamilies = route.equals("content/fetch") ? 2 : 4;
      assertEquals(heldFamilies, budget.diagnostics().activeFamilyLeases());
      var kinds =
          budget.observation().snapshot().events().stream()
              .map(RuntimeWorkObservation.Event::kind)
              .toList();
      assertTrue(kinds.contains(RuntimeWorkObservation.Kind.FETCH_CANCEL_REQUESTED));
      assertTrue(kinds.contains(RuntimeWorkObservation.Kind.FETCH_TERMINATION_UNKNOWN));
      assertFalse(kinds.contains(RuntimeWorkObservation.Kind.FETCH_OWNER_TERMINATED));
      // This is the controlled port's native terminal callback, not a request-registry close.
      termination.complete(null);
      assertEquals(0, budget.diagnostics().activeFamilyLeases());
      assertEquals(0, budget.diagnostics().reservedFamilyRates());
      assertTrue(
          budget.observation().snapshot().events().stream()
              .anyMatch(
                  event -> event.kind() == RuntimeWorkObservation.Kind.FETCH_OWNER_TERMINATED));
      assertTrue(budget.diagnostics().valid());
    } finally {
      termination.complete(null);
      host.stop(APP);
    }
  }

  @Test
  void staleLaunchAndCapabilityDenialNeverInvokeFetchAndHttpInterruptIsPreserved(@TempDir Path root)
      throws Exception {
    var host = signedHost(root);
    host.start(APP);
    var first = host.currentLaunch(APP).orElseThrow();
    host.stop(APP);
    host.start(APP);
    var live = host.currentLaunch(APP).orElseThrow();
    var calls = new AtomicInteger();
    ContentFetchPort port =
        request -> {
          calls.incrementAndGet();
          assertFalse(Thread.currentThread().isInterrupted());
          return new BoundedContentFetchResult(new byte[] {1}, request.uri(), null, null);
        };
    var budget =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(root.resolve("budget")),
            AppNetworkBudgetConfig.defaults());
    var router = router(host, port, budget, root);
    try {
      var stale = PlatformApiPrincipal.appToken(APP, first.permissions(), first.launchId());
      assertEquals(401, router.route(request("content/fetch", stale)).statusCode());
      var denied = PlatformApiPrincipal.appToken(APP, List.of(), live.launchId());
      assertEquals(403, router.route(request("content/fetch", denied)).statusCode());
      assertEquals(0, calls.get());
      var result = new CompletableFuture<Boolean>();
      Thread.ofVirtual()
          .start(
              () -> {
                Thread.currentThread().interrupt();
                try {
                  var principal =
                      PlatformApiPrincipal.appToken(APP, live.permissions(), live.launchId());
                  var response = router.route(request("content/fetch", principal));
                  result.complete(
                      response.statusCode() == 200 && Thread.currentThread().isInterrupted());
                } catch (Throwable failure) {
                  result.completeExceptionally(failure);
                }
              });
      assertTrue(result.get(10, TimeUnit.SECONDS));
      assertEquals(1, calls.get());
    } finally {
      host.stop(APP);
    }
  }

  @Test
  void unownedNativeInterruptRemainsSetAndGenuineAuditFaultIsNotHidden(@TempDir Path root)
      throws Exception {
    var termination = new CompletableFuture<Void>();
    ContentFetchPort unownedPort =
        request -> {
          Thread.currentThread().interrupt();
          throw new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_FAILED,
              "unowned interruption",
              new InterruptedException(),
              termination,
              true);
        };
    var unownedRoot = Files.createDirectories(root.resolve("unowned"));
    var unownedBudget =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(unownedRoot.resolve("budget")),
            AppNetworkBudgetConfig.defaults());
    var unownedRouter = router(null, unownedPort, unownedBudget, unownedRoot);
    var result = new CompletableFuture<Boolean>();
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                var failed =
                    unownedRouter.route(
                        request(
                            "trust-graph/import-uri",
                            PlatformApiPrincipal.appToken(APP, PERMISSIONS)));
                result.complete(
                    failed.statusCode() == 503
                        && failed.body().contains("\"code\":\"trust_graph_store_unavailable\"")
                        && Thread.currentThread().isInterrupted());
              } catch (Throwable failure) {
                result.completeExceptionally(failure);
              }
            });
    assertTrue(result.get(10, TimeUnit.SECONDS));
    termination.complete(null);

    var ownedRoot = Files.createDirectories(root.resolve("owned"));
    var host = signedHost(ownedRoot);
    host.start(APP);
    var launch = host.currentLaunch(APP).orElseThrow();
    var entered = new CountDownLatch(1);
    var nativeTerminal = new CompletableFuture<Void>();
    ContentFetchPort ownedPort =
        request -> {
          entered.countDown();
          try {
            if (!new CountDownLatch(1).await(10, TimeUnit.SECONDS))
              throw new AssertionError("owner wait timed out");
          } catch (InterruptedException cause) {
            Thread.currentThread().interrupt();
            throw new ContentFetchException(
                ContentFetchException.CATALOG_FETCH_FAILED,
                "owned cancellation",
                cause,
                nativeTerminal,
                true);
          }
          throw new AssertionError("unreachable owner wait");
        };
    var budget =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(ownedRoot.resolve("budget")),
            AppNetworkBudgetConfig.defaults());
    var ownedRouter = router(host, ownedPort, budget, ownedRoot);
    // A real unusable store path must still report the persistence failure after owned cleanup.
    Files.delete(ownedRoot.resolve("graph/audit"));
    Files.writeString(ownedRoot.resolve("graph/audit"), "owned audit path failure fixture");
    var response = new CompletableFuture<PlatformApiResponse>();
    Thread.ofVirtual()
        .start(
            () -> {
              try {
                response.complete(
                    ownedRouter.route(
                        request(
                            "trust-graph/import-uri",
                            PlatformApiPrincipal.appToken(
                                APP, launch.permissions(), launch.launchId()))));
              } catch (Throwable failure) {
                response.completeExceptionally(failure);
              }
            });
    try {
      assertTrue(entered.await(10, TimeUnit.SECONDS));
      host.stop(APP);
      var failed = response.get(10, TimeUnit.SECONDS);
      assertEquals(503, failed.statusCode());
      assertTrue(failed.body().contains("\"code\":\"trust_graph_store_unavailable\""));
      assertEquals(4, budget.diagnostics().activeFamilyLeases());
      nativeTerminal.complete(null);
      assertEquals(0, budget.diagnostics().activeFamilyLeases());
    } finally {
      nativeTerminal.complete(null);
      host.stop(APP);
    }
  }

  private static PlatformApiRequest request(String route, PlatformApiPrincipal principal) {
    return new PlatformApiRequest(
        "POST",
        List.of(route.split("/")),
        Map.of("uri", List.of("CHK@controlled-request-owner")),
        principal);
  }

  private static PlatformApiRouter router(
      LocalProcessAppHost host, ContentFetchPort port, AppNetworkBudgetService budget, Path root) {
    var runtime = mock(RuntimePorts.class, Answers.RETURNS_DEEP_STUBS);
    when(runtime.contentFetch()).thenReturn(port);
    var graph = new FileTrustGraphStore(root.resolve("graph"));
    var handler = new TrustGraphApiHandler(graph, java.time.Clock.systemUTC(), budget);
    var shared = new PlatformApiSharedAppServices(null, null, null, null, handler, null, budget);
    return new PlatformApiRouter(
        runtime, host, null, null, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), shared);
  }

  private static LocalProcessAppHost signedHost(Path root) throws Exception {
    Assumptions.assumeFalse(new AppEnv().isWindows());
    var key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var trusted =
        TrustedAppKeys.of(
            new TrustedAppKey(
                "test-request-owner", AppBundleSignature.SIGNATURE_ALGORITHM, key.getPublic()));
    var policy =
        AppInstallVerificationPolicy.requireSigned(path -> AppBundleVerifier.verify(path, trusted));
    var host =
        new LocalProcessAppHost(
            new AppHostLayout(root.resolve("data"), root.resolve("cache"), root.resolve("run")),
            Duration.ofSeconds(2),
            new java.security.SecureRandom(),
            policy);
    Path staged = Files.createDirectories(root.resolve("stage"));
    Path script = staged.resolve("run.sh");
    Files.writeString(script, "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n");
    Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwx------"));
    Files.writeString(
        staged.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=request-owner
        app.name=Request owner fixture
        app.version=1.0.0
        app.exec=run.sh
        app.permissions=content.fetch,trust.read,trust.write
        """);
    AppBundleSigner.sign(staged, "test-request-owner", key.getPrivate());
    host.installFromDirectory(staged);
    return host;
  }
}
