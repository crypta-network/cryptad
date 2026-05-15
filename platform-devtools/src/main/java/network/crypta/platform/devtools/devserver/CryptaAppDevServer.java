package network.crypta.platform.devtools.devserver;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleStructureValidator;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.AppUiMode;

/**
 * Loopback static app server with a deterministic mock Platform API.
 *
 * <p>The server is intended for local development of staged static bundles created by {@code
 * crypta-app init}. It serves app-owned files beneath {@code /apps/{appId}/}, exposes the SDK
 * bootstrap JSON at both the app and root well-known locations, and provides a fixture-backed mock
 * Platform API beneath {@code /api/v1/}. It never talks to a real Crypta node, never exposes
 * AppHost process tokens, and does not install, update, or publish apps.
 *
 * <p>Instances own a JDK {@link HttpServer}, a small daemon-thread executor, and one mock browser
 * session issuer. Callers must close the server when a CLI process exits or a test finishes. The
 * default host policy keeps the listener on loopback unless the CLI explicitly allows a wider
 * binding and surfaces the resulting warning in {@link #startupSummary()}.
 */
public final class CryptaAppDevServer implements AutoCloseable {
  /** SDK bootstrap endpoint served at the origin root and within the app route. */
  private static final String BOOTSTRAP_PATH = "/.well-known/cryptad-bootstrap.json";

  /** Prefix for all app-owned UI routes served by the local development origin. */
  private static final String APPS_ROUTE_PREFIX = "/apps/";

  /** Normalized server configuration captured at startup. */
  private final DevServerConfig config;

  /** Validated static app manifest for the staged bundle being served. */
  private final AppBundleManifest manifest;

  /** Mock browser-session issuer used by bootstrap and API authorization checks. */
  private final DevServerBrowserSession browserSession;

  /** JDK HTTP listener that owns route dispatch for the local dev origin. */
  private final HttpServer server;

  /** Daemon-thread executor used by the JDK HTTP server. */
  private final ExecutorService executor;

  /** Fixture-backed mock Platform API handler. */
  private final MockPlatformApi mockApi;

  /** Startup warning shown when the caller explicitly allows a non-loopback listener. */
  private final String warning;

  /**
   * Creates a wrapper around already-startable server components.
   *
   * @param config normalized server configuration
   * @param manifest validated static app manifest
   * @param browserSession mock browser-session issuer for bootstrap and API requests
   * @param server configured JDK HTTP server
   * @param executor daemon-thread executor assigned to the server
   * @param mockApi fixture-backed mock Platform API handler
   * @param warning optional startup warning for non-loopback listeners
   */
  private CryptaAppDevServer(
      DevServerConfig config,
      AppBundleManifest manifest,
      DevServerBrowserSession browserSession,
      HttpServer server,
      ExecutorService executor,
      MockPlatformApi mockApi,
      String warning) {
    this.config = config;
    this.manifest = manifest;
    this.browserSession = browserSession;
    this.server = server;
    this.executor = executor;
    this.mockApi = mockApi;
    this.warning = warning;
  }

  /**
   * Starts one dev server.
   *
   * @param config server configuration supplied by CLI or tests
   * @return running server instance that must be closed by the caller
   * @throws IOException if the bundle cannot be validated or the listener cannot be opened
   */
  public static CryptaAppDevServer start(DevServerConfig config) throws IOException {
    return start(config, Clock.systemUTC(), new SecureRandom());
  }

  /**
   * Starts one dev server with injectable time and randomness for deterministic tests.
   *
   * @param config server configuration supplied by CLI or tests
   * @param clock clock used for browser-session expiration decisions
   * @param random randomness source used to create browser-session tokens
   * @return running server instance that must be closed by the caller
   * @throws IOException if validation, fixture setup, or listener creation fails
   */
  static CryptaAppDevServer start(DevServerConfig config, Clock clock, SecureRandom random)
      throws IOException {
    DevServerConfig checked = Objects.requireNonNull(config, "config");
    Clock checkedClock = Objects.requireNonNull(clock, "clock");
    SecureRandom checkedRandom = Objects.requireNonNull(random, "random");
    String warning =
        LoopbackHostPolicy.requireAllowedHost(checked.host(), checked.allowNonLoopback());
    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(checked.bundleDir());
    AppBundleManifest manifest = validated.manifest();
    if (manifest.uiMode() != AppUiMode.STATIC) {
      throw new AppDistributionException("crypta-app dev supports only app.ui.mode=static bundles");
    }
    DevServerStaticAssets.checkStaticAssetSafety(checked.bundleDir(), manifest);
    HttpServer server = HttpServer.create(new InetSocketAddress(checked.host(), checked.port()), 0);
    AtomicInteger threadIds = new AtomicInteger();
    ExecutorService executor =
        Executors.newFixedThreadPool(
            4,
            runnable -> {
              Thread thread =
                  new Thread(runnable, "crypta-app-dev-server-" + threadIds.incrementAndGet());
              thread.setDaemon(true);
              return thread;
            });
    DevServerBrowserSession browserSession =
        new DevServerBrowserSession(checked.sessionTtl(), checkedClock, checkedRandom);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(
            checked.fixtureDir(), manifest.appId(), manifest.appName(), manifest.appVersion());
    MockPlatformApi mockApi = new MockPlatformApi(browserSession::isValid, fixtures);
    CryptaAppDevServer devServer =
        new CryptaAppDevServer(
            checked, manifest, browserSession, server, executor, mockApi, warning);
    server.createContext("/", devServer::handle);
    server.setExecutor(executor);
    server.start();
    return devServer;
  }

  /**
   * Returns the assigned listener port.
   *
   * @return concrete TCP port, including the OS-assigned value when configured with port {@code 0}
   */
  public int port() {
    return server.getAddress().getPort();
  }

  /**
   * Returns the listener host text.
   *
   * @return normalized host value from {@link DevServerConfig}
   */
  @SuppressWarnings("unused")
  public String host() {
    return config.host();
  }

  /**
   * Returns the app id being served.
   *
   * @return manifest app id used in local app routes
   */
  public String appId() {
    return manifest.appId();
  }

  /**
   * Returns the browser launch URL for the app.
   *
   * @return entry-directory URL that gives relative static references the same base as production
   */
  public String uiUrl() {
    return DevServerBootstrapJson.entryDirectoryUrl(manifest, baseUrl());
  }

  /**
   * Returns the root bootstrap JSON URL used by the SDK's first probe.
   *
   * @return same-origin well-known bootstrap URL for the local dev server
   */
  public String bootstrapUrl() {
    return baseUrl() + BOOTSTRAP_PATH;
  }

  /**
   * Returns the local mock Platform API root.
   *
   * @return base URL for mock {@code /api/v1/} endpoints, including a trailing slash
   */
  public String apiRoot() {
    return baseUrl() + "/api/v1/";
  }

  /**
   * Returns a startup banner with no token or private path material.
   *
   * @return redacted multi-line summary suitable for CLI stdout
   */
  public String startupSummary() {
    StringBuilder builder = new StringBuilder();
    if (!warning.isBlank()) {
      builder.append(warning).append('\n');
    }
    builder
        .append("Crypta app dev server\n")
        .append("App: ")
        .append(manifest.appId())
        .append(' ')
        .append(manifest.appVersion())
        .append('\n')
        .append("UI:  ")
        .append(uiUrl())
        .append('\n')
        .append("API: ")
        .append(apiRoot());
    return builder.toString();
  }

  @Override
  public void close() {
    server.stop(0);
    executor.shutdownNow();
  }

  /**
   * Dispatches one HTTP exchange by raw path so encoded separators remain visible to route checks.
   *
   * @param exchange incoming JDK HTTP exchange
   * @throws IOException if a response cannot be written
   */
  private void handle(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getRawPath();
    try {
      if (path.equals(BOOTSTRAP_PATH)
          || path.equals(APPS_ROUTE_PREFIX + manifest.appId() + BOOTSTRAP_PATH)) {
        sendBootstrap(exchange);
        return;
      }
      if (path.startsWith("/api/v1/") || path.equals("/api/v1")) {
        mockApi.handle(exchange);
        return;
      }
      String appRootPath = DevServerBootstrapJson.appRootPath(manifest);
      String entryDirectoryPath = DevServerBootstrapJson.entryDirectoryPath(manifest);
      if (path.equals(APPS_ROUTE_PREFIX + manifest.appId())) {
        redirect(exchange, entryDirectoryPath);
        return;
      }
      if (path.equals(appRootPath) && !entryDirectoryPath.equals(appRootPath)) {
        redirect(exchange, entryDirectoryPath);
        return;
      }
      if (path.startsWith(APPS_ROUTE_PREFIX)) {
        sendStatic(exchange, path);
        return;
      }
      sendNotFound(exchange);
    } catch (AppDistributionException exception) {
      sendError(exchange, 400, "invalid_static_asset", exception.getMessage());
    }
  }

  /**
   * Sends SDK bootstrap JSON with the current or freshly rotated mock browser session.
   *
   * @param exchange incoming bootstrap request
   * @throws IOException if the JSON response cannot be written
   */
  private void sendBootstrap(HttpExchange exchange) throws IOException {
    DevServerBrowserSession.Session session = browserSession.currentForBootstrap();
    String json =
        DevServerBootstrapJson.serialize(manifest, baseUrl(), session.token(), session.expiresAt());
    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
    exchange.getResponseHeaders().set("Cache-Control", "no-store");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream body = exchange.getResponseBody()) {
      body.write(bytes);
    }
  }

  /**
   * Resolves and sends one static app asset from the staged bundle.
   *
   * @param exchange incoming static asset request
   * @param path raw request path beneath the local app route
   * @throws IOException if route resolution or response writing fails
   */
  private void sendStatic(HttpExchange exchange, String path) throws IOException {
    var asset = DevServerStaticAssets.resolve(config.bundleDir(), manifest, path);
    if (asset.isEmpty()) {
      sendNotFound(exchange);
      return;
    }
    byte[] bytes = asset.get().bytes();
    exchange.getResponseHeaders().set("Content-Type", asset.get().contentType());
    exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream body = exchange.getResponseBody()) {
      body.write(bytes);
    }
  }

  /**
   * Sends a JSON {@code 404} response consistent with mock API errors.
   *
   * @param exchange incoming request that did not match a route
   * @throws IOException if the response cannot be written
   */
  private static void sendNotFound(HttpExchange exchange) throws IOException {
    sendError(exchange, 404, "not_found", "Not found.");
  }

  /**
   * Sends one JSON error response.
   *
   * @param exchange incoming request to complete
   * @param status HTTP response status code
   * @param code stable error code for clients and tests
   * @param message human-readable error message
   * @throws IOException if the response cannot be written
   */
  private static void sendError(HttpExchange exchange, int status, String code, String message)
      throws IOException {
    MockPlatformApi.sendJson(
        exchange,
        status,
        "{\"error\":{\"code\":\""
            + MockPlatformApiFixtures.Json.escape(code)
            + "\",\"message\":\""
            + MockPlatformApiFixtures.Json.escape(message)
            + "\"}}");
  }

  /**
   * Sends a local redirect to the static entry directory.
   *
   * @param exchange incoming app-root request
   * @param location relative route location for the entry directory
   * @throws IOException if response headers cannot be sent
   */
  private static void redirect(HttpExchange exchange, String location) throws IOException {
    exchange.getResponseHeaders().set("Location", location);
    exchange.sendResponseHeaders(302, -1);
    exchange.close();
  }

  /**
   * Builds the origin URL for this listener.
   *
   * @return HTTP origin URL without a trailing slash
   */
  private String baseUrl() {
    return "http://" + bracketIpv6(config.host()) + ":" + port();
  }

  /**
   * Wraps IPv6 literal hosts for use in HTTP URLs.
   *
   * @param host normalized listener host text
   * @return host text suitable for inclusion in a URL authority
   */
  private static String bracketIpv6(String host) {
    return host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
  }
}
