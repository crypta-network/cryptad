package network.crypta.clients.http;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import network.crypta.platform.api.PlatformApiPaths;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppBrowserSessionIssuer;
import network.crypta.platform.appui.AppStaticAsset;
import network.crypta.platform.appui.AppStaticAssetException;
import network.crypta.platform.appui.AppStaticAssetService;
import network.crypta.platform.appui.AppUiBootstrap;
import network.crypta.platform.appui.AppUiBootstrapJson;
import network.crypta.platform.appui.AppUiBootstrapService;
import network.crypta.platform.appui.AppUiOrigin;
import network.crypta.platform.appui.AppUiOriginBinding;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appui.AppUiPaths;
import network.crypta.platform.appui.AppUiSecurityHeaders;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.support.io.FileBucket;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loopback-only per-app HTTP server for isolated static app UI origins.
 *
 * <p>The server allocates one {@code 127.0.0.1:<port>} listener per static app as bindings are
 * requested. Each listener serves the app at its origin root, but request handling is adapted back
 * through {@link AppStaticAssetService} and {@link AppUiBootstrapService}. That keeps installed
 * bundle confinement, path traversal rejection, content-type handling, and browser-session issuance
 * in the reusable app UI layer.
 *
 * <p>This type is owned by the legacy admin HTTP adapter because it must share the operator-facing
 * admin root, JavaScript policy, and Web Shell launch route. It deliberately binds only to the
 * advertised IPv4 loopback address so the URL given to the browser matches the socket. Bindings are
 * lazy and are refreshed against the current {@link InstalledAppSnapshot}; removing or changing an
 * app invalidates the corresponding origin entry and any launch nonces for that app.
 *
 * <p>Bootstrap JSON is guarded by a short-lived launch nonce. The nonce is placed in the Web Shell
 * launch URL fragment and must be echoed in {@value #BOOTSTRAP_NONCE_HEADER}; ordinary local
 * processes that can reach the loopback port do not receive a browser-session token without that
 * launch proof.
 *
 * @see AppUiOriginRegistry
 * @see AppUiOriginBinding
 */
final class AppUiLoopbackOriginServer implements AppUiOriginRegistry, AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(AppUiLoopbackOriginServer.class);
  private static final int BACKLOG = 16;
  private static final int BOOTSTRAP_NONCE_BYTES = 32;
  static final int MAX_BOOTSTRAP_NONCES_PER_APP = 16;
  private static final Duration BOOTSTRAP_NONCE_LIFETIME = Duration.ofHours(1);

  /**
   * Request header that carries the Web Shell launch proof for isolated bootstrap fetches.
   *
   * <p>The value is a bearer nonce, not an app browser session. It authorizes issuance of a fresh
   * browser session only for the app id that received the original launch URL.
   */
  static final String BOOTSTRAP_NONCE_HEADER = "X-Crypta-App-Bootstrap-Nonce";

  /**
   * URL-fragment parameter used to deliver the launch proof to the static app page.
   *
   * <p>The fragment keeps the nonce out of the HTTP request line when Web Shell opens the app. The
   * SDK reads the value in the browser and sends it back through {@link #BOOTSTRAP_NONCE_HEADER}.
   */
  static final String BOOTSTRAP_NONCE_FRAGMENT_PARAMETER = "cryptadBootstrapNonce";

  private static final String JSON_CONTENT_TYPE = "application/json; charset=UTF-8";
  private static final String TEXT_CONTENT_TYPE = "text/plain";

  private final AppHost appHost;
  private final AppStaticAssetService assetService;
  private final AppUiBootstrapService bootstrapService;
  private final BootstrapNonceStore bootstrapNonces = new BootstrapNonceStore();
  private final String platformApiRoot;
  private final String shellRoot;
  private final BooleanSupplier javascriptEnabled;
  private final ExecutorService executor;
  private final Map<String, BindingServer> byAppId = new ConcurrentHashMap<>();
  private final Map<String, AppUiOriginBinding> byOrigin = new ConcurrentHashMap<>();

  /**
   * Creates a loopback-origin registry backed by lazy per-app HTTP listeners.
   *
   * <p>The server derives both the Platform API root and Web Shell root from {@code adminRoot}; the
   * scheme and host therefore follow the configured admin listener instead of assuming plain HTTP.
   * Static app listeners are not started during construction. They are created on demand by {@link
   * #bindingForApp(String)} or {@link #launchUrlForApp(String)} and are stopped when {@link
   * #close()} is called.
   *
   * @param appHost source of installed app snapshots and static app metadata.
   * @param sessionIssuer issuer used for app browser sessions in bootstrap JSON.
   * @param adminRoot absolute admin origin root, including scheme, host, and port.
   * @param javascriptEnabled live supplier for the operator's FProxy JavaScript policy.
   */
  AppUiLoopbackOriginServer(
      AppHost appHost,
      AppBrowserSessionIssuer sessionIssuer,
      String adminRoot,
      BooleanSupplier javascriptEnabled) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.assetService = new AppStaticAssetService(appHost);
    this.bootstrapService = new AppUiBootstrapService(appHost, sessionIssuer);
    String normalizedAdminRoot = normalizeAdminRoot(adminRoot);
    this.platformApiRoot = appendRootPath(normalizedAdminRoot, PlatformApiPaths.API_V1_PREFIX);
    this.shellRoot = appendRootPath(normalizedAdminRoot, WebShellPaths.SHELL_ROOT);
    this.javascriptEnabled = Objects.requireNonNull(javascriptEnabled, "javascriptEnabled");
    this.executor = Executors.newCachedThreadPool(new DaemonThreadFactory());
  }

  /**
   * Returns an active isolated binding for a static app, creating its listener if necessary.
   *
   * <p>Only installed static apps receive loopback origins. Missing apps, process-only apps, and
   * apps whose snapshot no longer describes static UI remove any stale listener and return empty.
   * Existing listeners are reused so browser tabs keep a stable origin while the installed snapshot
   * is refreshed.
   *
   * @param appId installed app identifier requested by Web Shell or the API summary path.
   * @return the current isolated binding, or empty when the app cannot use static UI isolation.
   */
  @Override
  public Optional<AppUiOriginBinding> bindingForApp(String appId) {
    try {
      Optional<InstalledAppSnapshot> snapshot = appHost.describe(appId);
      if (snapshot.isEmpty() || snapshot.get().manifest().uiMode() != AppUiMode.STATIC) {
        removeBindingServer(appId);
        return Optional.empty();
      }
      BindingServer bindingServer = byAppId.get(snapshot.get().appId());
      if (bindingServer == null) {
        bindingServer = createBindingServer(snapshot.get());
        BindingServer raced = byAppId.putIfAbsent(snapshot.get().appId(), bindingServer);
        if (raced != null) {
          byOrigin.remove(bindingServer.binding().origin());
          bindingServer.stop();
          bindingServer = raced;
        }
      }
      refreshBinding(bindingServer, snapshot.get());
      return Optional.of(bindingServer.binding());
    } catch (IOException | RuntimeException e) {
      LOG.warn("Failed to provide isolated app UI origin for {}", appId, e);
      return Optional.empty();
    }
  }

  /**
   * Builds the browser launch URL for an app and attaches a bootstrap launch proof when isolated.
   *
   * <p>The returned URL is safe to hand to Web Shell launch controls. For active isolated bindings,
   * the URL includes a fragment nonce that is scoped to {@code appId}; for non-isolated fallback
   * bindings, the binding's UI URL is returned unchanged.
   *
   * @param appId installed app identifier selected by the operator.
   * @return launch URL for the current UI binding, or empty when no binding is available.
   */
  @Override
  public Optional<String> launchUrlForApp(String appId) {
    Optional<AppUiOriginBinding> binding = bindingForApp(appId);
    if (binding.isEmpty()) {
      return Optional.empty();
    }
    if (!binding.get().isolatedAndActive()) {
      return Optional.ofNullable(binding.get().uiUrl());
    }
    BindingServer bindingServer = byAppId.get(binding.get().appId());
    if (bindingServer == null) {
      return Optional.empty();
    }
    String nonce =
        bootstrapNonces.issue(binding.get().appId(), bindingServer.snapshotFingerprint());
    return Optional.of(appendBootstrapNonceFragment(binding.get().uiUrl(), nonce));
  }

  /**
   * Looks up a registered binding by its browser origin.
   *
   * <p>The lookup refreshes the app binding before returning it, so callers do not authenticate
   * CORS requests against origins that were removed after the map entry was created.
   *
   * @param origin browser {@code Origin} header value to validate against current app bindings.
   * @return current binding for that origin, or empty when the origin is unknown or stale.
   */
  @Override
  public Optional<AppUiOriginBinding> bindingForOrigin(String origin) {
    if (origin == null || origin.isBlank()) {
      return Optional.empty();
    }
    AppUiOriginBinding binding = byOrigin.get(origin.trim());
    if (binding == null) {
      return Optional.empty();
    }
    return bindingForApp(binding.appId()).filter(current -> origin.trim().equals(current.origin()));
  }

  /**
   * Stops every loopback listener owned by this registry and clears launch nonce state.
   *
   * <p>The method is idempotent for normal shutdown paths. It does not stop the admin listener or
   * invalidate already-issued browser-session tokens; those remain owned by the session store.
   */
  @Override
  public void close() {
    byAppId.values().forEach(BindingServer::stop);
    byAppId.clear();
    byOrigin.clear();
    bootstrapNonces.clear();
    executor.shutdownNow();
  }

  private BindingServer createBindingServer(InstalledAppSnapshot snapshot) {
    try {
      HttpServer server =
          HttpServer.create(new InetSocketAddress(advertisedLoopbackAddress(), 0), BACKLOG);
      AppUiOrigin origin = AppUiOrigin.loopback(snapshot.appId(), server.getAddress().getPort());
      AppUiOriginBinding binding =
          AppUiOriginBinding.isolatedLoopback(
              snapshot.manifest(), origin, platformApiRoot, shellRoot);
      BindingServer bindingServer =
          new BindingServer(server, origin, binding, SnapshotFingerprint.from(snapshot));
      server.createContext("/", exchange -> handle(exchange, bindingServer));
      server.setExecutor(executor);
      server.start();
      byOrigin.put(binding.origin(), binding);
      return bindingServer;
    } catch (IOException e) {
      throw new IllegalStateException("Failed to start app UI loopback listener.", e);
    }
  }

  private void refreshBinding(BindingServer bindingServer, InstalledAppSnapshot snapshot) {
    AppUiOriginBinding refreshed =
        AppUiOriginBinding.isolatedLoopback(
            snapshot.manifest(), bindingServer.origin(), platformApiRoot, shellRoot);
    AppUiOriginBinding previous = bindingServer.binding();
    SnapshotFingerprint previousFingerprint = bindingServer.snapshotFingerprint();
    SnapshotFingerprint refreshedFingerprint = SnapshotFingerprint.from(snapshot);
    bindingServer.update(refreshed, refreshedFingerprint);
    if (!Objects.equals(previousFingerprint, refreshedFingerprint)) {
      bootstrapNonces.clearApp(snapshot.appId());
    }
    if (!Objects.equals(previous.origin(), refreshed.origin())) {
      byOrigin.remove(previous.origin());
    }
    byOrigin.put(refreshed.origin(), refreshed);
  }

  private void removeBindingServer(String appId) {
    BindingServer bindingServer = byAppId.remove(appId);
    if (bindingServer == null) {
      return;
    }
    byOrigin.remove(bindingServer.binding().origin());
    bootstrapNonces.clearApp(appId);
    bindingServer.stop();
  }

  private void handle(HttpExchange exchange, BindingServer bindingServer) throws IOException {
    String method = exchange.getRequestMethod();
    if (!"GET".equals(method) && !"HEAD".equals(method)) {
      sendText(exchange, 405, null, "Method not allowed.");
      return;
    }
    boolean includeBody = "GET".equals(method);
    Optional<AppUiOriginBinding> refreshedBinding = refreshBindingForRequest(bindingServer);
    if (refreshedBinding.isEmpty()) {
      sendText(exchange, 404, null, "App UI is not available.", includeBody);
      return;
    }
    AppUiOriginBinding binding = refreshedBinding.get();
    String adminPath = toAdminAppPath(binding.appId(), exchange.getRequestURI().getRawPath());
    try {
      if (AppUiBootstrapService.isBootstrapRequest(adminPath)) {
        writeBootstrap(exchange, binding, adminPath, includeBody);
        return;
      }
      Optional<String> canonicalRootRedirect = assetService.canonicalRootRedirect(adminPath);
      if (canonicalRootRedirect.isPresent()) {
        redirect(exchange, toOriginPath(canonicalRootRedirect.get()), includeBody);
        return;
      }
      Optional<AppStaticAsset> asset = assetService.resolve(adminPath);
      if (asset.isEmpty()) {
        sendText(exchange, 404, null, "App UI asset not found.", includeBody);
        return;
      }
      writeAsset(exchange, binding, asset.get(), includeBody);
    } catch (AppStaticAssetException exception) {
      int status = exception.statusCode() == 404 ? 404 : 400;
      sendText(exchange, status, null, "App UI path is not valid.", includeBody);
    }
  }

  private Optional<AppUiOriginBinding> refreshBindingForRequest(BindingServer bindingServer)
      throws IOException {
    String appId = bindingServer.binding().appId();
    Optional<InstalledAppSnapshot> snapshot = appHost.describe(appId);
    if (snapshot.isEmpty() || snapshot.get().manifest().uiMode() != AppUiMode.STATIC) {
      byOrigin.remove(bindingServer.binding().origin());
      bootstrapNonces.clearApp(appId);
      return Optional.empty();
    }
    refreshBinding(bindingServer, snapshot.get());
    return Optional.of(bindingServer.binding());
  }

  private void writeBootstrap(
      HttpExchange exchange, AppUiOriginBinding binding, String adminPath, boolean includeBody)
      throws IOException, AppStaticAssetException {
    if (!includeBody) {
      if (bootstrapService.isAvailable(adminPath)) {
        sendHeaders(exchange, 200, appHeaders(binding), JSON_CONTENT_TYPE, 0L);
      } else {
        sendText(exchange, 404, null, "App UI bootstrap not found.", false);
      }
      return;
    }
    if (!validBootstrapProof(binding, exchange)) {
      sendText(exchange, 401, appHeaders(binding), "App UI bootstrap launch proof is required.");
      return;
    }
    Optional<AppUiBootstrap> bootstrap =
        bootstrapService.resolve(adminPath, platformApiRoot, shellRoot, binding);
    if (bootstrap.isEmpty()) {
      sendText(exchange, 404, null, "App UI bootstrap not found.");
      return;
    }
    byte[] body = AppUiBootstrapJson.serialize(bootstrap.get()).getBytes(StandardCharsets.UTF_8);
    sendBytes(exchange, 200, appHeaders(binding), body, JSON_CONTENT_TYPE, true);
  }

  private void writeAsset(
      HttpExchange exchange, AppUiOriginBinding binding, AppStaticAsset asset, boolean includeBody)
      throws IOException {
    Headers headers = appHeaders(binding);
    if (!includeBody) {
      sendOkHeadHeaders(exchange, headers, asset.contentType(), asset.sizeBytes());
      return;
    }
    sendHeaders(exchange, 200, headers, asset.contentType(), asset.sizeBytes());
    try (FileBucket bucket = new FileBucket(asset.path().toFile(), true, false, false, false);
        var input = bucket.getInputStream();
        OutputStream output = exchange.getResponseBody()) {
      input.transferTo(output);
    }
  }

  private Headers appHeaders(AppUiOriginBinding binding) {
    Headers headers = new Headers();
    for (Map.Entry<String, String> entry :
        AppUiSecurityHeaders.headers(
                javascriptEnabled.getAsBoolean(), binding.platformApiRoot(), binding.shellRoot())
            .entrySet()) {
      headers.add(entry.getKey(), entry.getValue());
    }
    headers.add("cache-control", "no-store");
    return headers;
  }

  private boolean validBootstrapProof(AppUiOriginBinding binding, HttpExchange exchange) {
    String nonce = exchange.getRequestHeaders().getFirst(BOOTSTRAP_NONCE_HEADER);
    BindingServer bindingServer = byAppId.get(binding.appId());
    return bindingServer != null
        && bootstrapNonces.verify(binding.appId(), bindingServer.snapshotFingerprint(), nonce);
  }

  private static void redirect(HttpExchange exchange, String location, boolean includeBody)
      throws IOException {
    Headers headers = new Headers();
    headers.add("Location", appendRawQuery(location, exchange.getRequestURI().getRawQuery()));
    if (!includeBody) {
      sendHeaders(exchange, 302, headers, null, 0L);
      return;
    }
    sendText(exchange, 302, headers, "Redirecting to app UI.");
  }

  private static void sendText(HttpExchange exchange, int status, Headers headers, String text)
      throws IOException {
    sendText(exchange, status, headers, text, true);
  }

  private static void sendText(
      HttpExchange exchange, int status, Headers headers, String text, boolean includeBody)
      throws IOException {
    sendBytes(
        exchange,
        status,
        headers,
        text.getBytes(StandardCharsets.UTF_8),
        TEXT_CONTENT_TYPE,
        includeBody);
  }

  private static void sendBytes(
      HttpExchange exchange,
      int status,
      Headers headers,
      byte[] body,
      String contentType,
      boolean includeBody)
      throws IOException {
    sendHeaders(exchange, status, headers, contentType, includeBody ? body.length : 0L);
    if (includeBody) {
      try (OutputStream output = exchange.getResponseBody()) {
        output.write(body);
      }
    }
  }

  private static void sendHeaders(
      HttpExchange exchange, int status, Headers headers, String contentType, long length)
      throws IOException {
    Headers responseHeaders = exchange.getResponseHeaders();
    if (headers != null) {
      responseHeaders.putAll(headers);
    }
    if (contentType != null) {
      responseHeaders.add("content-type", contentType);
    }
    exchange.sendResponseHeaders(status, length);
  }

  private static void sendOkHeadHeaders(
      HttpExchange exchange, Headers headers, String contentType, long length) throws IOException {
    Headers responseHeaders = exchange.getResponseHeaders();
    if (headers != null) {
      responseHeaders.putAll(headers);
    }
    if (contentType != null) {
      responseHeaders.add("content-type", contentType);
    }
    responseHeaders.set("content-length", Long.toString(length));
    exchange.sendResponseHeaders(200, -1L);
  }

  private static String toAdminAppPath(String appId, String rawPath) {
    String path = rawPath == null || rawPath.isBlank() ? "/" : rawPath;
    if ("/".equals(path)) {
      return AppUiPaths.appRoot(appId);
    }
    return AppUiPaths.APPS_ROOT + appId + path;
  }

  private static String toOriginPath(String adminPath) {
    String remainder = adminPath.substring(AppUiPaths.APPS_ROOT.length());
    int slash = remainder.indexOf('/');
    return slash < 0 ? "/" : remainder.substring(slash);
  }

  private static String appendRawQuery(String path, String rawQuery) {
    if (rawQuery == null) {
      return path;
    }
    int fragmentIndex = path.indexOf('#');
    if (fragmentIndex < 0) {
      return path + "?" + rawQuery;
    }
    return path.substring(0, fragmentIndex) + "?" + rawQuery + path.substring(fragmentIndex);
  }

  private static String normalizeAdminRoot(String adminRoot) {
    String value = Objects.requireNonNull(adminRoot, "adminRoot").trim();
    if (value.isEmpty()) {
      throw new IllegalArgumentException("adminRoot must not be blank");
    }
    return value.endsWith("/") ? value : value + "/";
  }

  private static String appendRootPath(String root, String path) {
    String relativePath = path.startsWith("/") ? path.substring(1) : path;
    return root + relativePath;
  }

  private static InetAddress advertisedLoopbackAddress() throws IOException {
    return InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
  }

  private static String appendBootstrapNonceFragment(String url, String nonce) {
    String separator = url.indexOf('#') < 0 ? "#" : "&";
    return url + separator + BOOTSTRAP_NONCE_FRAGMENT_PARAMETER + "=" + nonce;
  }

  /** Stores short-lived Web Shell launch proofs keyed by their opaque nonce values. */
  private static final class BootstrapNonceStore {
    private final SecureRandom random = new SecureRandom();
    private final Map<String, BootstrapNonce> nonces = new ConcurrentHashMap<>();
    private long nextSequence;

    private synchronized String issue(String appId, SnapshotFingerprint snapshotFingerprint) {
      Instant now = Instant.now();
      pruneExpired(now);
      evictOldestAppNonces(appId);
      String nonce = generateNonce();
      while (nonces.containsKey(nonce)) {
        nonce = generateNonce();
      }
      nonces.put(
          nonce,
          new BootstrapNonce(
              appId, snapshotFingerprint, nextSequence++, now.plus(BOOTSTRAP_NONCE_LIFETIME)));
      return nonce;
    }

    private synchronized boolean verify(
        String appId, SnapshotFingerprint snapshotFingerprint, String nonce) {
      if (nonce == null || nonce.isBlank()) {
        return false;
      }
      Instant now = Instant.now();
      pruneExpired(now);
      BootstrapNonce issued = nonces.get(nonce.trim());
      return issued != null
          && issued.appId().equals(appId)
          && issued.snapshotFingerprint().equals(snapshotFingerprint)
          && issued.expiresAt().isAfter(now);
    }

    private synchronized void clearApp(String appId) {
      nonces.entrySet().removeIf(entry -> entry.getValue().appId().equals(appId));
    }

    private synchronized void clear() {
      nonces.clear();
    }

    private String generateNonce() {
      byte[] bytes = new byte[BOOTSTRAP_NONCE_BYTES];
      random.nextBytes(bytes);
      return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void evictOldestAppNonces(String appId) {
      while (countAppNonces(appId) >= MAX_BOOTSTRAP_NONCES_PER_APP) {
        String oldestNonce = oldestAppNonce(appId);
        if (oldestNonce == null) {
          return;
        }
        nonces.remove(oldestNonce);
      }
    }

    private long countAppNonces(String appId) {
      return nonces.values().stream().filter(nonce -> nonce.appId().equals(appId)).count();
    }

    private String oldestAppNonce(String appId) {
      String oldestNonce = null;
      long oldestSequence = Long.MAX_VALUE;
      for (Map.Entry<String, BootstrapNonce> entry : nonces.entrySet()) {
        BootstrapNonce nonce = entry.getValue();
        if (nonce.appId().equals(appId) && nonce.sequence() < oldestSequence) {
          oldestNonce = entry.getKey();
          oldestSequence = nonce.sequence();
        }
      }
      return oldestNonce;
    }

    private void pruneExpired(Instant now) {
      nonces.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }
  }

  /**
   * Immutable association between a launch proof and the installed app snapshot that received it.
   */
  private record BootstrapNonce(
      String appId, SnapshotFingerprint snapshotFingerprint, long sequence, Instant expiresAt) {}

  /**
   * Internal install-state fingerprint used to keep launch proofs scoped to one app snapshot.
   *
   * <p>The manifest is the semantic security boundary for browser-session permissions. Filesystem
   * identities provide an additional install-generation signal for normal AppHost updates, where
   * the copied bundle root or manifest file is replaced even if some manifest fields stay the same.
   */
  private record SnapshotFingerprint(
      AppManifest manifest,
      Path installedRoot,
      FileIdentity installedRootIdentity,
      FileIdentity manifestFileIdentity) {
    private static SnapshotFingerprint from(InstalledAppSnapshot snapshot) {
      return new SnapshotFingerprint(
          snapshot.manifest(),
          snapshot.paths().installedRoot(),
          FileIdentity.from(snapshot.paths().installedRoot()),
          FileIdentity.from(snapshot.paths().manifestFile()));
    }
  }

  /** Display-free filesystem identity for one installed-bundle path. */
  private record FileIdentity(String fileKey, long sizeBytes, long lastModifiedMillis) {
    private static final FileIdentity UNAVAILABLE = new FileIdentity(null, -1L, -1L);

    private static FileIdentity from(Path path) {
      try {
        BasicFileAttributes attributes =
            Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Object fileKey = attributes.fileKey();
        return new FileIdentity(
            fileKey == null ? null : fileKey.toString(),
            attributes.size(),
            attributes.lastModifiedTime().toMillis());
      } catch (IOException e) {
        return UNAVAILABLE;
      }
    }
  }

  /** Holds the active HTTP listener and the latest app binding advertised for that listener. */
  private static final class BindingServer {
    private final HttpServer server;
    private final AppUiOrigin origin;
    private final AtomicReference<AppUiOriginBinding> binding;
    private final AtomicReference<SnapshotFingerprint> snapshotFingerprint;

    private BindingServer(
        HttpServer server,
        AppUiOrigin origin,
        AppUiOriginBinding binding,
        SnapshotFingerprint snapshotFingerprint) {
      this.server = server;
      this.origin = origin;
      this.binding = new AtomicReference<>(binding);
      this.snapshotFingerprint = new AtomicReference<>(snapshotFingerprint);
    }

    private AppUiOrigin origin() {
      return origin;
    }

    private AppUiOriginBinding binding() {
      return binding.get();
    }

    private SnapshotFingerprint snapshotFingerprint() {
      return snapshotFingerprint.get();
    }

    private void update(AppUiOriginBinding binding, SnapshotFingerprint snapshotFingerprint) {
      this.binding.set(binding);
      this.snapshotFingerprint.set(snapshotFingerprint);
    }

    private void stop() {
      server.stop(0);
    }
  }

  /** Creates daemon worker threads so loopback app listeners cannot keep node shutdown alive. */
  private static final class DaemonThreadFactory implements ThreadFactory {
    @Override
    public Thread newThread(@NotNull Runnable runnable) {
      Thread thread = new Thread(runnable, "Cryptad-AppUi-Origin");
      thread.setDaemon(true);
      return thread;
    }
  }
}
