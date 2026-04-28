package network.crypta.platform.appui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppBrowserSessionStoreTest {
  private static final Instant START = Instant.parse("2026-04-28T10:00:00Z");

  @TempDir private Path tempDir;

  @Test
  void issue_whenStaticAppInstalled_expectOpaqueTokenAndTokenFreeVerification() {
    MutableAppHost appHost =
        new MutableAppHost(staticApp("demo-app", List.of("queue.write", "queue.read")));
    MutableClock clock = new MutableClock(START);
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(appHost, clock, new SecureRandom(), Duration.ofHours(1), 10);

    AppBrowserSessionIssue issue = store.issue(appHost.describeUnchecked("demo-app"));
    Optional<AppBrowserSession> verified = store.verify(issue.token());

    assertTrue(issue.token().length() >= 43);
    assertFalse(issue.token().contains("="));
    assertEquals(START.plus(Duration.ofHours(1)), issue.expiresAt());
    assertTrue(verified.isPresent());
    assertEquals("demo-app", verified.orElseThrow().appId());
    assertEquals(List.of("queue.read", "queue.write"), verified.orElseThrow().permissions());
    assertFalse(issue.toString().contains(issue.token()));
    assertFalse(store.toString().contains(issue.token()));
  }

  @Test
  void verify_whenSessionIsBlankUnknownOrExpired_expectEmpty() {
    MutableAppHost appHost = new MutableAppHost(staticApp("demo-app", List.of("queue.read")));
    MutableClock clock = new MutableClock(START);
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(appHost, clock, new SecureRandom(), Duration.ofHours(1), 10);

    AppBrowserSessionIssue issue = store.issue(appHost.describeUnchecked("demo-app"));
    clock.advance(Duration.ofHours(1).plusSeconds(1));

    assertTrue(store.verify(null).isEmpty());
    assertTrue(store.verify(" ").isEmpty());
    assertTrue(store.verify("unknown").isEmpty());
    assertTrue(store.verify(issue.token()).isEmpty());
  }

  @Test
  void verify_whenAppUninstalledOrManifestChanges_expectEmpty() {
    MutableAppHost appHost = new MutableAppHost(staticApp("demo-app", List.of("queue.read")));
    MutableClock clock = new MutableClock(START);
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(appHost, clock, new SecureRandom(), Duration.ofHours(1), 10);
    AppBrowserSessionIssue uninstalled = store.issue(appHost.describeUnchecked("demo-app"));
    AppBrowserSessionIssue changed = store.issue(appHost.describeUnchecked("demo-app"));

    appHost.removeDemoApp();
    assertTrue(store.verify(uninstalled.token()).isEmpty());

    appHost.put(staticApp("demo-app", List.of("queue.read", "queue.write")));
    assertTrue(store.verify(changed.token()).isEmpty());
  }

  @Test
  void verify_whenAppNoLongerStatic_expectEmpty() {
    MutableAppHost appHost = new MutableAppHost(staticApp("demo-app", List.of("queue.read")));
    MutableClock clock = new MutableClock(START);
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(appHost, clock, new SecureRandom(), Duration.ofHours(1), 10);
    AppBrowserSessionIssue issue = store.issue(appHost.describeUnchecked("demo-app"));

    appHost.put(app("demo-app", AppUiMode.SHELL_PANEL, "/app/node/#queue", List.of("queue.read")));

    assertTrue(store.verify(issue.token()).isEmpty());
  }

  @Test
  void verify_whenInstalledManifestFileChanges_expectEmpty() throws IOException {
    MutableAppHost appHost = new MutableAppHost(staticApp("demo-app", List.of("queue.read")));
    InstalledAppSnapshot snapshot = appHost.describeUnchecked("demo-app");
    materializeInstalledManifest(snapshot, "version=1", START);
    MutableClock clock = new MutableClock(START);
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(appHost, clock, new SecureRandom(), Duration.ofHours(1), 10);
    AppBrowserSessionIssue issue = store.issue(snapshot);

    materializeInstalledManifest(snapshot, "version=2", START.plusSeconds(1));

    assertTrue(store.verify(issue.token()).isEmpty());
  }

  @Test
  void verify_whenAppHostDescribeFails_expectEmptyAndSessionRemoved() {
    MutableAppHost appHost = new MutableAppHost(staticApp("demo-app", List.of("queue.read")));
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(
            appHost, new MutableClock(START), new SecureRandom(), Duration.ofHours(1), 10);
    AppBrowserSessionIssue issue = store.issue(appHost.describeUnchecked("demo-app"));

    appHost.failDescribe();
    assertTrue(store.verify(issue.token()).isEmpty());

    appHost.allowDescribe();
    assertTrue(store.verify(issue.token()).isEmpty());
  }

  @Test
  void issue_whenAppIsNotStatic_expectIllegalArgumentException() {
    MutableAppHost appHost =
        new MutableAppHost(app("demo-app", AppUiMode.SHELL_PANEL, "/app/node/#queue", List.of()));
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(
            appHost, new MutableClock(START), new SecureRandom(), Duration.ofHours(1), 10);

    InstalledAppSnapshot shellPanelSnapshot = appHost.describeUnchecked("demo-app");

    assertThrows(IllegalArgumentException.class, () -> store.issue(shellPanelSnapshot));
  }

  @Test
  void issue_whenCapacityExceeded_expectOldestSessionDropped() {
    MutableAppHost appHost =
        new MutableAppHost(
            staticApp("first-app", List.of("queue.read")),
            staticApp("second-app", List.of("queue.read")));
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(
            appHost, new MutableClock(START), new SecureRandom(), Duration.ofHours(1), 1);

    AppBrowserSessionIssue first = store.issue(appHost.describeUnchecked("first-app"));
    AppBrowserSessionIssue second = store.issue(appHost.describeUnchecked("second-app"));

    assertTrue(store.verify(first.token()).isEmpty());
    assertTrue(store.verify(second.token()).isPresent());
  }

  @Test
  void issue_whenRandomGeneratesDuplicateToken_expectRetriesUntilUnique() {
    MutableAppHost appHost =
        new MutableAppHost(
            staticApp("first-app", List.of("queue.read")),
            staticApp("second-app", List.of("queue.read")));
    AppBrowserSessionStore store =
        new AppBrowserSessionStore(
            appHost,
            new MutableClock(START),
            new ScriptedSecureRandom(repeatedByte(1), repeatedByte(1), repeatedByte(2)),
            Duration.ofHours(1),
            10);

    AppBrowserSessionIssue first = store.issue(appHost.describeUnchecked("first-app"));
    AppBrowserSessionIssue second = store.issue(appHost.describeUnchecked("second-app"));

    assertNotEquals(first.token(), second.token());
    assertTrue(store.verify(first.token()).isPresent());
    assertTrue(store.verify(second.token()).isPresent());
  }

  private InstalledAppSnapshot staticApp(String appId, List<String> permissions) {
    return app(appId, AppUiMode.STATIC, "static/index.html", permissions);
  }

  private static byte[] repeatedByte(int value) {
    byte[] bytes = new byte[32];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static void materializeInstalledManifest(
      InstalledAppSnapshot snapshot, String text, Instant lastModifiedAt) throws IOException {
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().manifestFile(), text);
    Files.setLastModifiedTime(snapshot.paths().manifestFile(), FileTime.from(lastModifiedAt));
  }

  private InstalledAppSnapshot app(
      String appId, AppUiMode uiMode, String uiEntry, List<String> permissions) {
    AppManifest manifest =
        new AppManifest(
            1,
            appId,
            "Demo App",
            "1.0.0",
            "bin/launch.sh",
            uiMode,
            uiEntry,
            permissions,
            null,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            appId,
            tempDir.resolve("installed").resolve(appId),
            tempDir.resolve("data").resolve(appId),
            tempDir.resolve("cache").resolve(appId),
            tempDir.resolve("run").resolve(appId));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    private void advance(Duration duration) {
      instant = instant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }

  private static final class MutableAppHost implements AppHost {
    private final Map<String, InstalledAppSnapshot> snapshots = new LinkedHashMap<>();
    private boolean failDescribe;

    private MutableAppHost(InstalledAppSnapshot... snapshots) {
      for (InstalledAppSnapshot snapshot : snapshots) {
        put(snapshot);
      }
    }

    private void put(InstalledAppSnapshot snapshot) {
      snapshots.put(snapshot.appId(), snapshot);
    }

    private void removeDemoApp() {
      snapshots.remove("demo-app");
    }

    private void failDescribe() {
      failDescribe = true;
    }

    private void allowDescribe() {
      failDescribe = false;
    }

    private InstalledAppSnapshot describeUnchecked(String appId) {
      return snapshots.get(appId);
    }

    @Override
    public InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) {
      throw new UnsupportedOperationException();
    }

    @Override
    public InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void uninstall(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<InstalledAppSnapshot> listInstalled() {
      return List.copyOf(snapshots.values());
    }

    @Override
    public Optional<InstalledAppSnapshot> describe(String appId) throws IOException {
      if (failDescribe) {
        throw new IOException("metadata unavailable");
      }
      return Optional.ofNullable(snapshots.get(appId));
    }

    @Override
    public RunningAppSnapshot start(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean stop(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Optional<RunningAppSnapshot> status(String appId) {
      return Optional.empty();
    }

    @Override
    public List<RunningAppSnapshot> listRunning() {
      return List.of();
    }

    @Override
    public AppRuntimeStatusSnapshot runtimeStatus(String appId) throws IOException {
      if (!snapshots.containsKey(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new AppRuntimeStatusSnapshot(
          appId, AppRuntimeState.STOPPED, false, null, null, null, null, 0, 0, false, null);
    }

    @Override
    public List<AppRuntimeStatusSnapshot> listRuntimeStatus() {
      return snapshots.keySet().stream()
          .map(
              appId ->
                  new AppRuntimeStatusSnapshot(
                      appId,
                      AppRuntimeState.STOPPED,
                      false,
                      null,
                      null,
                      null,
                      null,
                      0,
                      0,
                      false,
                      null))
          .toList();
    }

    @Override
    public AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes) throws IOException {
      if (!snapshots.containsKey(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new AppProcessLogSnapshot(appId, false, false, maxBytes, 0L, "", null);
    }
  }

  private static final class ScriptedSecureRandom extends SecureRandom {
    private final byte[][] values;
    private int index;

    private ScriptedSecureRandom(byte[]... values) {
      this.values = values.clone();
    }

    @Override
    public void nextBytes(byte[] bytes) {
      byte[] value = values[Math.min(index, values.length - 1)];
      index++;
      System.arraycopy(value, 0, bytes, 0, Math.min(value.length, bytes.length));
    }
  }
}
