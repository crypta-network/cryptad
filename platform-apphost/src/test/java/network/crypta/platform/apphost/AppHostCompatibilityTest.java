package network.crypta.platform.apphost;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AppHostCompatibilityTest {
  private static final String DIGEST = "d".repeat(64);

  @Test
  void installCatalogFromDirectory_whenHostUsesInterfaceDefaults_expectFailureBeforeMutation() {
    AtomicInteger abstractCalls = new AtomicInteger();
    AppHost host = defaultOnlyHost(abstractCalls);

    assertThrows(
        AppHostException.CatalogOriginPersistenceUnsupportedException.class,
        () -> host.installCatalogFromDirectory(Path.of("staged"), origin()));

    assertEquals(0, abstractCalls.get());
  }

  @Test
  void installCatalogFromDirectory_whenAuthorizationDefaultUsed_expectFailureBeforeCallback() {
    AtomicInteger abstractCalls = new AtomicInteger();
    AtomicInteger authorizationCalls = new AtomicInteger();
    AppHost host = defaultOnlyHost(abstractCalls);

    assertThrows(
        AppHostException.CatalogOriginPersistenceUnsupportedException.class,
        () ->
            host.installCatalogFromDirectory(
                Path.of("staged"),
                origin(),
                ignored -> {
                  authorizationCalls.incrementAndGet();
                  return () -> {};
                }));

    assertEquals(0, authorizationCalls.get());
    assertEquals(0, abstractCalls.get());
  }

  @Test
  void updateCatalogFromDirectory_whenHostUsesInterfaceDefaults_expectFailureBeforeMutation() {
    AtomicInteger abstractCalls = new AtomicInteger();
    AppHost host = defaultOnlyHost(abstractCalls);

    assertThrows(
        AppHostException.CatalogOriginPersistenceUnsupportedException.class,
        () ->
            host.updateCatalogFromDirectory(
                "sample-app",
                Path.of("staged"),
                origin(),
                AppHost.CatalogOriginExpectation.absent()));

    assertEquals(0, abstractCalls.get());
  }

  @Test
  void updateCatalogFromDirectory_whenAuthorizationDefaultUsed_expectFailureBeforeCallback() {
    AtomicInteger abstractCalls = new AtomicInteger();
    AtomicInteger authorizationCalls = new AtomicInteger();
    AppHost host = defaultOnlyHost(abstractCalls);

    assertThrows(
        AppHostException.CatalogOriginPersistenceUnsupportedException.class,
        () ->
            host.updateCatalogFromDirectory(
                "sample-app",
                Path.of("staged"),
                origin(),
                AppHost.CatalogOriginExpectation.absent(),
                ignored -> {
                  authorizationCalls.incrementAndGet();
                  return () -> {};
                }));

    assertEquals(0, authorizationCalls.get());
    assertEquals(0, abstractCalls.get());
  }

  @Test
  void recordCatalogOrigin_whenHostUsesInterfaceDefault_expectFailClosed() {
    AtomicInteger abstractCalls = new AtomicInteger();
    AppHost host = defaultOnlyHost(abstractCalls);

    assertThrows(
        AppHostException.CatalogOriginPersistenceUnsupportedException.class,
        () -> host.recordCatalogOrigin(origin()));

    assertEquals(0, abstractCalls.get());
  }

  @Test
  void rollbackRequiresCatalogAuthorization_whenLegacyHostHasNoOrigin_expectLegacyState()
      throws Exception {
    AtomicInteger abstractCalls = new AtomicInteger();
    AppHost host = defaultOnlyHost(abstractCalls);

    boolean required = host.rollbackRequiresCatalogAuthorization("sample-app");

    assertFalse(required);
    assertEquals(0, abstractCalls.get());
  }

  private static AppHost defaultOnlyHost(AtomicInteger abstractCalls) {
    return (AppHost)
        Proxy.newProxyInstance(
            AppHost.class.getClassLoader(),
            new Class<?>[] {AppHost.class},
            (proxy, method, arguments) -> {
              if (method.isDefault()) {
                return InvocationHandler.invokeDefault(proxy, method, arguments);
              }
              abstractCalls.incrementAndGet();
              throw new AssertionError("unexpected abstract AppHost call: " + method.getName());
            });
  }

  private static InstalledAppOrigin origin() {
    return InstalledAppOrigin.create(
        "sample-app",
        "1.0.0",
        DIGEST,
        "sample-catalog",
        "catalog-key",
        DIGEST,
        DIGEST,
        "publisher-key",
        DIGEST,
        DIGEST,
        "",
        "reviewed",
        "binding-1",
        DIGEST,
        DIGEST,
        DIGEST,
        Instant.parse("2026-08-27T00:00:00Z"),
        null);
  }
}
