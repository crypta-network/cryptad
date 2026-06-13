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
}
