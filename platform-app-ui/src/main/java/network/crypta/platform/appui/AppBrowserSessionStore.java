package network.crypta.platform.appui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Objects;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Bounded in-memory browser app session issuer and verifier.
 *
 * <p>The store is the PR-205 bridge between app-owned static UI bootstrap and Platform API
 * authentication. It generates URL-safe opaque tokens with at least 256 bits of entropy, records a
 * token-free {@link AppBrowserSession}, and binds that session to the installed app snapshot that
 * existed at issuance time. Verification re-checks the app through {@link AppHost}, so sessions
 * stop authenticating when the app is removed, stops being a static UI, or no longer matches the
 * manifest/install fingerprint captured at issue time.
 *
 * <p>This implementation is deliberately process-local and memory-backed. It does not survive node
 * restart or share state across processes. Browser origin isolation is supplied by the app UI
 * origin binding recorded in the session metadata, while this store keeps the opaque token and
 * verifies that metadata. All public entry points are synchronized, and capacity trimming uses the
 * access-ordered map to discard the least recently used retained session after expired entries have
 * been pruned. Raw tokens are retained only as map keys and are never returned from verification or
 * included in {@link #toString()}.
 *
 * <ul>
 *   <li>{@link #issue(InstalledAppSnapshot)} is called by the app UI bootstrap path.
 *   <li>{@link #verify(String)} is called by the Platform API HTTP bridge.
 *   <li>Missing AppHost metadata and I/O failures fail closed as invalid sessions.
 * </ul>
 *
 * @see AppBrowserSessionIssuer
 * @see AppBrowserSessionVerifier
 */
public final class AppBrowserSessionStore
    implements AppBrowserSessionIssuer, AppBrowserSessionVerifier {
  /**
   * Default absolute lifetime for browser sessions issued to app-owned static UIs.
   *
   * <p>The lifetime is intentionally short and server-enforced. Browser code may display or use the
   * matching expiry timestamp, but verification against this store remains authoritative.
   */
  public static final Duration DEFAULT_LIFETIME = Duration.ofHours(1);

  /**
   * Default maximum number of live browser sessions retained by one daemon process.
   *
   * <p>The bound prevents unbounded memory growth from reloads, probes, or abandoned pages. When
   * the capacity is exceeded, expired entries are already gone and the least recently used retained
   * session is evicted first.
   */
  public static final int DEFAULT_CAPACITY = 1024;

  private static final int TOKEN_BYTES = 32;

  private final AppHost appHost;
  private final Clock clock;
  private final SecureRandom random;
  private final Duration lifetime;
  private final int capacity;
  private final LinkedHashMap<String, StoredSession> sessions =
      new LinkedHashMap<>(16, 0.75F, true);

  /**
   * Creates a session store using the default one-hour lifetime, capacity, and secure randomness.
   *
   * <p>This is the production constructor used by HTTP route registration. It uses the system UTC
   * clock and a new {@link SecureRandom} instance, and it keeps all issued sessions in this JVM
   * only. Tests use the package-private constructor to inject deterministic clocks and token
   * generators.
   *
   * @param appHost AppHost used to reject stale or uninstalled-app sessions during verification
   * @throws NullPointerException if the AppHost dependency is {@code null}
   */
  public AppBrowserSessionStore(AppHost appHost) {
    this(appHost, Clock.systemUTC(), new SecureRandom(), DEFAULT_LIFETIME, DEFAULT_CAPACITY);
  }

  /**
   * Creates a session store with explicit testable dependencies.
   *
   * <p>The constructor is package-private so production wiring uses the default policy while tests
   * can control time, randomness, lifetime, and capacity. The injected random source is expected to
   * produce high-entropy bytes in production-like uses; this constructor does not weaken or replace
   * token uniqueness checks.
   *
   * @param appHost AppHost used for stale installed-app checks during verification
   * @param clock clock used for issue, expiry, and pruning decisions
   * @param random random byte source used to generate opaque bearer tokens
   * @param lifetime positive absolute lifetime applied to newly issued sessions
   * @param capacity positive maximum number of retained sessions
   * @throws IllegalArgumentException if lifetime or capacity is not positive
   * @throws NullPointerException if any dependency or lifetime value is {@code null}
   */
  AppBrowserSessionStore(
      AppHost appHost, Clock clock, SecureRandom random, Duration lifetime, int capacity) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.random = Objects.requireNonNull(random, "random");
    this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
    if (lifetime.isZero() || lifetime.isNegative()) {
      throw new IllegalArgumentException("lifetime must be positive");
    }
    if (capacity <= 0) {
      throw new IllegalArgumentException("capacity must be positive");
    }
    this.capacity = capacity;
  }

  /**
   * Issues a browser session for one installed static app snapshot.
   *
   * <p>The snapshot supplies the app id, manifest permissions, UI mode, and install-state binding
   * recorded with the generated token. Before storing a new session, the method removes expired
   * entries; after storing it, the method trims the map to the configured capacity. The returned
   * issuance value is the only object that exposes the raw token, and it is intended for immediate
   * serialization into app-owned UI bootstrap JSON.
   *
   * @param snapshot installed static app snapshot used to bind the issued session
   * @return token and expiry metadata for app-owned UI bootstrap JSON
   * @throws IllegalArgumentException if the snapshot is not a static app UI
   * @throws NullPointerException if the installed app snapshot is {@code null}
   */
  @Override
  public synchronized AppBrowserSessionIssue issue(InstalledAppSnapshot snapshot) {
    return issue(snapshot, null);
  }

  /**
   * Issues a browser session for one installed static app snapshot and origin binding.
   *
   * <p>The origin binding becomes part of the token-free verified session metadata. Isolated
   * loopback sessions therefore authenticate only when the HTTP bridge sees the expected browser
   * {@code Origin} header.
   */
  @Override
  public synchronized AppBrowserSessionIssue issue(
      InstalledAppSnapshot snapshot, AppUiOriginBinding binding) {
    InstalledAppSnapshot checkedSnapshot = Objects.requireNonNull(snapshot, "snapshot");
    if (checkedSnapshot.manifest().uiMode() != AppUiMode.STATIC) {
      throw new IllegalArgumentException("browser sessions require static app UI");
    }
    pruneExpired(clock.instant());
    AppBrowserSession session = newSession(checkedSnapshot.manifest(), binding);
    String token = generateUniqueToken();
    sessions.put(token, new StoredSession(session, manifestBinding(checkedSnapshot)));
    trimToCapacity();
    return new AppBrowserSessionIssue(token, session.expiresAt());
  }

  /**
   * Verifies one opaque browser session token.
   *
   * <p>Verification trims the supplied header value, prunes expired sessions, looks up the retained
   * entry, and revalidates the app against the current {@link AppHost} snapshot. Unknown, blank,
   * expired, stale, non-static, uninstalled, and metadata-unavailable sessions all return {@link
   * java.util.Optional#empty()}. A failed stale or expired lookup also removes the retained map
   * entry so repeated invalid requests do not keep dead sessions alive.
   *
   * @param token token presented by the Platform API bridge from {@code X-Crypta-App-Session}
   * @return token-free session metadata when the token is live and still matches the installed app
   */
  @Override
  public synchronized java.util.Optional<AppBrowserSession> verify(String token) {
    if (token == null || token.isBlank()) {
      return java.util.Optional.empty();
    }
    String normalizedToken = token.trim();
    Instant now = clock.instant();
    pruneExpired(now);
    StoredSession stored = sessions.get(normalizedToken);
    if (stored == null || !stored.session().expiresAt().isAfter(now)) {
      sessions.remove(normalizedToken);
      return java.util.Optional.empty();
    }
    if (!stillMatchesInstalledApp(stored)) {
      sessions.remove(normalizedToken);
      return java.util.Optional.empty();
    }
    return java.util.Optional.of(stored.session());
  }

  /**
   * Returns redacted diagnostic state for the in-memory store.
   *
   * <p>The string reports only aggregate policy and retention counts. It intentionally omits raw
   * tokens, app ids, manifest permissions, filesystem paths, and fingerprint material because this
   * method is a common accidental logging path during route-registration debugging.
   *
   * @return diagnostic text with capacity, retained count, and lifetime only
   */
  @Override
  public synchronized String toString() {
    return "AppBrowserSessionStore[capacity="
        + capacity
        + ", retainedSessions="
        + sessions.size()
        + ", lifetime="
        + lifetime
        + "]";
  }

  private AppBrowserSession newSession(AppManifest manifest, AppUiOriginBinding binding) {
    Instant issuedAt = clock.instant();
    return new AppBrowserSession(
        manifest.appId(), manifest.permissions(), issuedAt, issuedAt.plus(lifetime), binding);
  }

  private String generateUniqueToken() {
    String token;
    do {
      byte[] bytes = new byte[TOKEN_BYTES];
      random.nextBytes(bytes);
      token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    } while (sessions.containsKey(token));
    return token;
  }

  private void pruneExpired(Instant now) {
    sessions
        .entrySet()
        .removeIf(
            stringStoredSessionEntry ->
                !stringStoredSessionEntry.getValue().session().expiresAt().isAfter(now));
  }

  private void trimToCapacity() {
    Iterator<String> iterator = sessions.keySet().iterator();
    while (sessions.size() > capacity && iterator.hasNext()) {
      iterator.next();
      iterator.remove();
    }
  }

  private boolean stillMatchesInstalledApp(StoredSession stored) {
    try {
      return appHost
          .describe(stored.session().appId())
          .filter(snapshot -> snapshot.manifest().uiMode() == AppUiMode.STATIC)
          .map(AppBrowserSessionStore::manifestBinding)
          .filter(stored.manifestBinding()::equals)
          .isPresent();
    } catch (IOException _) {
      return false;
    }
  }

  private static String manifestBinding(InstalledAppSnapshot snapshot) {
    AppManifest manifest = snapshot.manifest();
    return String.join(
        "\u001F",
        Integer.toString(manifest.manifestVersion()),
        manifest.appId(),
        manifest.appName(),
        manifest.appVersion(),
        manifest.execPathText(),
        manifest.uiMode().manifestValue(),
        manifest.uiEntry() == null ? "" : manifest.uiEntry(),
        String.join("\u001E", manifest.permissions()),
        String.valueOf(manifest.dataQuotaBytes()),
        String.valueOf(manifest.cacheQuotaBytes()),
        manifest.restartPolicy().manifestValue(),
        Integer.toString(manifest.restartMaxAttempts()),
        Long.toString(manifest.restartBackoffMillis()),
        pathFingerprint(snapshot.paths().installedRoot()),
        pathFingerprint(snapshot.paths().manifestFile()));
  }

  private static String pathFingerprint(Path path) {
    Path normalized = path.toAbsolutePath().normalize();
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(normalized, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      Object fileKey = attributes.fileKey();
      return String.join(
          "\u001D",
          normalized.toString(),
          attributes.lastModifiedTime().toString(),
          Long.toString(attributes.size()),
          fileKey == null ? "" : fileKey.toString());
    } catch (IOException _) {
      return normalized + "\u001Dmissing";
    }
  }

  private record StoredSession(AppBrowserSession session, String manifestBinding) {}
}
