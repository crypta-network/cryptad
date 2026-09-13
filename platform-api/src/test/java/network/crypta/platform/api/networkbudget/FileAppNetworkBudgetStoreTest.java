package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FileAppNetworkBudgetStoreTest {
  @TempDir private Path tempDir;

  @Test
  void writeAndRead_whenUsagePersisted_expectSafeMetadataRestored() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    AppNetworkBudgetUsage usage =
        new AppNetworkBudgetUsage(
            "Social-Inbox",
            AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
            Instant.parse("2026-06-12T00:00:00Z"),
            Duration.ofHours(1),
            12,
            Instant.parse("2026-06-12T00:10:00Z"),
            "allowed",
            null);

    store.write(usage);

    AppNetworkBudgetUsage restored =
        store.read("social-inbox", AppNetworkBudgetOperation.SUBSCRIPTION_POLL).orElseThrow();
    assertEquals("social-inbox", restored.appId());
    assertEquals(AppNetworkBudgetOperation.SUBSCRIPTION_POLL, restored.operation());
    assertEquals(12, restored.count());
    assertEquals("allowed", restored.lastDecision());
    assertTrue(
        Files.exists(tempDir.resolve("social-inbox").resolve("subscription_poll.properties")));
  }

  @Test
  void listAll_whenUnsafeOrCorruptFilesExist_expectOnlySafeRecordsReturned() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    store.write(
        AppNetworkBudgetUsage.empty(
                "feed-reader",
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                Instant.parse("2026-06-12T00:00:00Z"),
                Duration.ofMinutes(1))
            .allowedAt(Instant.parse("2026-06-12T00:00:05Z")));
    Files.createDirectories(tempDir.resolve("unsafe app"));
    Files.writeString(
        tempDir.resolve("unsafe app").resolve("CHK@raw.properties"),
        "token=/tmp/private\n<html>queue</html>",
        StandardCharsets.UTF_8);
    Files.writeString(
        tempDir.resolve("feed-reader").resolve("corrupt.properties"),
        "not=valid",
        StandardCharsets.UTF_8);

    List<AppNetworkBudgetUsage> usages = store.listAll();

    assertEquals(1, usages.size());
    assertEquals("feed-reader", usages.getFirst().appId());
  }

  @Test
  void read_whenSpecificCounterIsMalformed_expectReadFailure() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    Files.createDirectories(tempDir.resolve("feed-reader"));
    Files.writeString(
        tempDir.resolve("feed-reader").resolve("foreground_content_fetch.properties"),
        "not=valid\n",
        StandardCharsets.UTF_8);

    IOException failure =
        assertThrows(
            IOException.class,
            () -> store.read("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));

    assertEquals("App network budget metadata is unavailable.", failure.getMessage());
  }

  @Test
  void write_whenAppIdContainsRawUriText_expectRejectedBeforePathCreation() {
    String rawUriAppId = "feed-reader/USK@private";
    Instant windowStart = Instant.parse("2026-06-12T00:00:00Z");
    Duration window = Duration.ofMinutes(1);

    assertThrows(
        IllegalArgumentException.class,
        () ->
            AppNetworkBudgetUsage.empty(
                rawUriAppId,
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                windowStart,
                window));
  }

  @Test
  void write_whenInternalScopePersisted_expectPathSafeNonAppDirectory() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    store.write(
        AppNetworkBudgetUsage.empty(
                AppNetworkBudgetScope.GLOBAL,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                Instant.parse("2026-06-12T00:00:00Z"),
                Duration.ofHours(1))
            .allowedAt(Instant.parse("2026-06-12T00:00:05Z")));

    AppNetworkBudgetUsage restored =
        store
            .read(AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.SUBSCRIPTION_POLL)
            .orElseThrow();

    assertEquals(AppNetworkBudgetScope.GLOBAL, restored.appId());
    assertTrue(
        Files.exists(
            tempDir.resolve(AppNetworkBudgetScope.GLOBAL).resolve("subscription_poll.properties")));
  }

  @Test
  void write_whenMetadataPersisted_expectNoRawContentSecretsOrPaths() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    store.write(
        AppNetworkBudgetUsage.empty(
                "feed-reader",
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                Instant.parse("2026-06-12T00:00:00Z"),
                Duration.ofMinutes(1))
            .deniedAt(
                Instant.parse("2026-06-12T00:00:10Z"),
                "rate_limited",
                Instant.parse("2026-06-12T00:01:00Z")));

    String persisted =
        Files.readString(
            tempDir.resolve("feed-reader").resolve("foreground_content_fetch.properties"),
            StandardCharsets.UTF_8);

    assertTrue(persisted.contains("operation=foreground_content_fetch"));
    assertFalse(persisted.contains("USK@"));
    assertFalse(persisted.contains("/tmp"));
    assertFalse(persisted.contains("token"));
    assertFalse(persisted.contains("<html"));
  }

  @Test
  void observe_whenRootAbsentOrEmpty_expectKnownEmpty() throws Exception {
    FileAppNetworkBudgetStore absent = new FileAppNetworkBudgetStore(tempDir.resolve("absent"));
    FileAppNetworkBudgetStore empty = new FileAppNetworkBudgetStore(tempDir);

    assertTrue(absent.observe(1).isEmpty());
    assertTrue(empty.observe(1).isEmpty());
  }

  @Test
  void observe_whenBoundDoesNotIncludeDirectoryAndCounter_expectUnavailable() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    AppNetworkBudgetUsage usage = observationUsage();
    store.write(usage);

    assertThrows(IOException.class, () -> store.observe(0));
    assertThrows(IOException.class, () -> store.observe(-1));
    assertThrows(IOException.class, () -> store.observe(1));
    assertEquals(List.of(usage), store.observe(2));
  }

  @Test
  void observe_whenTemporaryWriteExists_expectIgnoredButChargedToInspectionBound()
      throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    AppNetworkBudgetUsage usage = observationUsage();
    store.write(usage);
    Files.writeString(tempDir.resolve("feed-reader/.app-network-budget-write.tmp"), "partial");

    assertThrows(IOException.class, () -> store.observe(2));
    assertEquals(List.of(usage), store.observe(3));
  }

  @ParameterizedTest
  @ValueSource(strings = {"unexpected.txt", "unknown.properties"})
  void observe_whenUnrecognizedCounterPresent_expectUnavailableDespiteLegacyListing(String name)
      throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    AppNetworkBudgetUsage usage = observationUsage();
    store.write(usage);
    Files.writeString(tempDir.resolve("feed-reader").resolve(name), "not=valid");

    assertThrows(IOException.class, () -> store.observe(10));
    assertEquals(List.of(usage), store.listAll());
  }

  @Test
  void observe_whenRootOrAppEntryIsNotDirectory_expectUnavailable() throws Exception {
    Path file = Files.writeString(tempDir.resolve("file"), "unexpected");
    FileAppNetworkBudgetStore fileRoot = new FileAppNetworkBudgetStore(file);
    FileAppNetworkBudgetStore invalidEntry = new FileAppNetworkBudgetStore(tempDir);

    assertThrows(IOException.class, () -> fileRoot.observe(10));
    assertThrows(IOException.class, () -> invalidEntry.observe(10));
  }

  @Test
  void observe_whenCounterIsDirectory_expectUnavailable() throws Exception {
    Files.createDirectories(tempDir.resolve("feed-reader/subscription_poll.properties"));
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);

    assertThrows(IOException.class, () -> store.observe(10));
  }

  @Test
  void observe_whenScopeInvalid_expectUnavailableWithoutPathInMessage() throws Exception {
    Files.createDirectory(tempDir.resolve("invalid scope"));
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);

    IOException failure = assertThrows(IOException.class, () -> store.observe(10));

    assertEquals("App network budget metadata is unavailable.", failure.getMessage());
  }

  @Test
  void observe_whenCounterExceedsByteBound_expectUnavailableButLegacyReadPreserved()
      throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    AppNetworkBudgetUsage usage = observationUsage();
    store.write(usage);
    Path file = tempDir.resolve("feed-reader/subscription_poll.properties");
    String metadata = Files.readString(file);
    Files.writeString(file, metadata + "#" + "x".repeat(8191 - metadata.length()));
    assertEquals(List.of(usage), store.observe(10));

    Files.writeString(file, Files.readString(file) + "x");

    assertThrows(IOException.class, () -> store.observe(10));
    assertEquals(
        usage,
        store.read("feed-reader", AppNetworkBudgetOperation.SUBSCRIPTION_POLL).orElseThrow());
  }

  @Test
  void observe_whenCounterDoesNotMatchFilename_expectUnavailable() throws Exception {
    FileAppNetworkBudgetStore store = new FileAppNetworkBudgetStore(tempDir);
    store.write(observationUsage());
    Files.move(
        tempDir.resolve("feed-reader/subscription_poll.properties"),
        tempDir.resolve("feed-reader/foreground_content_fetch.properties"));

    assertThrows(IOException.class, () -> store.observe(10));
  }

  private static AppNetworkBudgetUsage observationUsage() {
    return AppNetworkBudgetUsage.empty(
        "feed-reader",
        AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
        Instant.parse("2026-06-12T00:00:00Z"),
        Duration.ofHours(1));
  }
}
