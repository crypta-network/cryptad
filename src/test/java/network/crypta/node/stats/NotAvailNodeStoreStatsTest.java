package network.crypta.node.stats;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // Test method naming convention per instructions
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotAvailNodeStoreStatsTest {

  private Stream<Executable> unavailableInvocations() {
    return Stream.of(
        () -> new NotAvailNodeStoreStats().avgLocation(),
        () -> new NotAvailNodeStoreStats().avgSuccess(),
        () -> new NotAvailNodeStoreStats().furthestSuccess(),
        () -> new NotAvailNodeStoreStats().avgDist(),
        () -> new NotAvailNodeStoreStats().distanceStats());
  }

  @ParameterizedTest(name = "method throws StatsNotAvailableException")
  @MethodSource("unavailableInvocations")
  @DisplayName("All StoreLocationStats methods throw when stats are unavailable")
  void methods_whenCalled_expectStatsNotAvailableException(Executable invocation) {
    StatsNotAvailableException ex = assertThrows(StatsNotAvailableException.class, invocation);
    // Default constructor is used, so message and cause are expected to be null.
    assertAll(() -> assertNull(ex.getMessage()), () -> assertNull(ex.getCause()));
  }
}
