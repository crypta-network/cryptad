package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppNetworkBudgetStoreTest {
  @Test
  void observe_whenLegacyStoreHasNoObservationSupport_expectUnavailableEvenWithEmptyDiagnostics()
      throws Exception {
    AppNetworkBudgetStore legacy =
        new AppNetworkBudgetStore() {
          @Override
          public Optional<AppNetworkBudgetUsage> read(
              String appId, AppNetworkBudgetOperation operation) {
            return Optional.empty();
          }

          @Override
          public void write(AppNetworkBudgetUsage usage) {
            throw new UnsupportedOperationException();
          }

          @Override
          public List<AppNetworkBudgetUsage> listAll() {
            return List.of();
          }
        };

    IOException failure = assertThrows(IOException.class, () -> legacy.observe(10));

    assertEquals("Budget observation unavailable", failure.getMessage());
    assertTrue(legacy.listAll().isEmpty());
  }
}
