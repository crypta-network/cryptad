package network.crypta.platform.api.content.subscriptions;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FileContentSubscriptionStoreTest {
  private static final String APP_ID = "feed-reader";
  private static final String SUBSCRIPTION_ID = "sub-alpha";
  private static final String SOURCE = "USK@example/feed/7/feed.json";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");

  @TempDir Path tempDir;

  @Test
  void writeAndRead_whenSubscriptionContainsSourceUri_expectPathUsesAppAndSubscriptionIdsOnly()
      throws IOException {
    Path root = tempDir.resolve("content-subscriptions");
    FileContentSubscriptionStore store = new FileContentSubscriptionStore(root);
    ContentSubscription subscription = subscription();

    store.write(subscription);

    assertTrue(Files.isRegularFile(root.resolve(APP_ID).resolve(SUBSCRIPTION_ID + ".properties")));
    try (Stream<Path> paths = Files.walk(root)) {
      assertFalse(paths.map(Path::toString).anyMatch(path -> path.contains("USK@")));
    }
    Optional<ContentSubscription> restored = store.read(APP_ID, SUBSCRIPTION_ID);
    assertTrue(restored.isPresent());
    assertEquals(subscription.toSummary(), restored.orElseThrow().toSummary());
  }

  @Test
  void listForApp_whenFileIsCorrupt_expectIgnoredWithoutRootPathExposure() throws IOException {
    Path root = tempDir.resolve("content-subscriptions");
    Path appDirectory = root.resolve(APP_ID);
    Files.createDirectories(appDirectory);
    Files.writeString(
        appDirectory.resolve("sub-corrupt.properties"), "version=1\nsourceUri=/tmp/x\n");
    FileContentSubscriptionStore store = new FileContentSubscriptionStore(root);

    List<ContentSubscription> subscriptions = store.listForApp(APP_ID);

    assertTrue(subscriptions.isEmpty());
  }

  @Test
  void pauseResumeAndDelete_whenPersisted_expectRoundTripStateChanges() throws IOException {
    FileContentSubscriptionStore store =
        new FileContentSubscriptionStore(tempDir.resolve("content-subscriptions"));
    ContentSubscription paused = subscription().withPaused(NOW.plusSeconds(1));
    store.write(paused);

    ContentSubscription restored = store.read(APP_ID, SUBSCRIPTION_ID).orElseThrow();
    assertFalse(restored.enabled());
    assertEquals(ContentSubscriptionStatus.PAUSED, restored.status());

    ContentSubscription resumed = restored.withResumed(NOW.plusSeconds(2));
    store.write(resumed);
    assertTrue(store.read(APP_ID, SUBSCRIPTION_ID).orElseThrow().enabled());

    assertTrue(store.delete(APP_ID, SUBSCRIPTION_ID));
    assertTrue(store.read(APP_ID, SUBSCRIPTION_ID).isEmpty());
  }

  @Test
  void deleteAllForApp_whenMultipleRecordsExist_expectOnlyAppDirectoryRemoved() throws IOException {
    Path root = tempDir.resolve("content-subscriptions");
    FileContentSubscriptionStore store = new FileContentSubscriptionStore(root);
    store.write(subscription(APP_ID, "sub-one", SOURCE));
    store.write(subscription(APP_ID, "sub-two", "USK@example/second/7/feed.json"));
    store.write(subscription("other-app", "sub-three", "USK@example/other/7/feed.json"));

    store.deleteAllForApp(APP_ID);

    assertTrue(store.listForApp(APP_ID).isEmpty());
    assertEquals(1, store.listForApp("other-app").size());
    assertFalse(Files.exists(root.resolve(APP_ID)));
    assertTrue(Files.exists(root.resolve("other-app")));
  }

  private static ContentSubscription subscription() {
    return subscription(APP_ID, SUBSCRIPTION_ID, SOURCE);
  }

  private static ContentSubscription subscription(
      String appId, String subscriptionId, String source) {
    return ContentSubscription.create(
        subscriptionId,
        appId,
        "Daily feed",
        source,
        new ContentSubscriptionPolicy(Duration.ofMinutes(5), 256L, Duration.ofSeconds(1)),
        NOW,
        NOW);
  }
}
