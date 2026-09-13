package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class InMemoryAppNetworkBudgetStoreTest {
  @Test
  void observe_whenEmpty_expectKnownEmptyWithPositiveBoundOnly() throws Exception {
    InMemoryAppNetworkBudgetStore store = new InMemoryAppNetworkBudgetStore();

    assertTrue(store.observe(1).isEmpty());
    assertThrows(IOException.class, () -> store.observe(0));
    assertThrows(IOException.class, () -> store.observe(-1));
  }

  @Test
  void observe_whenLimitReached_expectCompleteSortedDetachedSnapshot() throws Exception {
    InMemoryAppNetworkBudgetStore store = new InMemoryAppNetworkBudgetStore();
    AppNetworkBudgetUsage second = usage("second-app");
    AppNetworkBudgetUsage first = usage("first-app");
    store.write(second);
    store.write(first);

    List<AppNetworkBudgetUsage> observed = store.observe(2);
    store.write(usage("third-app"));

    assertEquals(List.of(first, second), observed);
    assertThrows(IOException.class, () -> store.observe(2));
    assertEquals(3, store.observe(3).size());
  }

  @Test
  void write_whenReplacingNormalizedScope_expectSingleUpdatedRecord() throws Exception {
    InMemoryAppNetworkBudgetStore store = new InMemoryAppNetworkBudgetStore();
    AppNetworkBudgetUsage initial = usage("Feed-Reader");
    AppNetworkBudgetUsage updated = initial.allowedAt(Instant.parse("2026-06-12T00:00:05Z"));
    store.write(initial);

    store.write(updated);

    assertEquals(List.of(updated), store.observe(1));
    assertEquals(
        updated,
        store.read("FEED-READER", AppNetworkBudgetOperation.SUBSCRIPTION_POLL).orElseThrow());
    assertTrue(store.read("other-app", AppNetworkBudgetOperation.SUBSCRIPTION_POLL).isEmpty());
  }

  private static AppNetworkBudgetUsage usage(String appId) {
    return AppNetworkBudgetUsage.empty(
        appId,
        AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
        Instant.parse("2026-06-12T00:00:00Z"),
        Duration.ofHours(1));
  }
}
