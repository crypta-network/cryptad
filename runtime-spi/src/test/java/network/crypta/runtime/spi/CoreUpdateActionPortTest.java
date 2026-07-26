package network.crypta.runtime.spi;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CoreUpdateActionPortTest {
  @Test
  void defaultMethods_whenAdapterDoesNotOverrideLifecycleMethods_expectFailClosedResults() {
    CoreUpdateActionPort actionPort = new DefaultCoreUpdateActionPort();
    AtomicBoolean storeActionInvoked = new AtomicBoolean();

    CoreSupportLifecycleSnapshot snapshot = actionPort.supportLifecycleSnapshot();
    Optional<String> storeResult =
        actionPort.withCurrentStoreTarget(
            "flatpak",
            "network.crypta.Cryptad",
            "https://flathub.org/apps/network.crypta.Cryptad",
            () -> {
              storeActionInvoked.set(true);
              return "launched";
            });

    assertFalse(snapshot.known());
    assertEquals(-1, snapshot.running().build());
    assertEquals(List.of("lifecycle_unavailable"), snapshot.warnings());
    assertTrue(storeResult.isEmpty());
    assertFalse(storeActionInvoked.get());
  }

  private static final class DefaultCoreUpdateActionPort implements CoreUpdateActionPort {
    @Override
    public boolean isCoreUpdaterAvailable() {
      return false;
    }

    @Override
    public boolean isCoreDownloadAvailable() {
      return false;
    }

    @Override
    public boolean startCoreDownloadFromUi() {
      return false;
    }

    @Override
    public <T> Optional<T> withDownloadedInstaller(String rawPath, InstallerAction<T> action) {
      return Optional.empty();
    }
  }
}
