package network.crypta.runtime.spi;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AlertListSnapshotTest {

  @Test
  void constructor_whenSourceListMutatedAfterCreation_expectDefensiveCopyAndEncounterOrder() {
    List<AlertSnapshot> sourceAlerts = new ArrayList<>();
    AlertSnapshot firstAlert = sampleAlert(1, AlertSeverity.WARNING);
    AlertSnapshot secondAlert = sampleAlert(2, AlertSeverity.ERROR);
    sourceAlerts.add(firstAlert);
    sourceAlerts.add(secondAlert);

    AlertListSnapshot snapshot = new AlertListSnapshot(sourceAlerts);

    sourceAlerts.clear();
    sourceAlerts.add(sampleAlert(3, AlertSeverity.MINOR));

    assertEquals(List.of(firstAlert, secondAlert), snapshot.alerts());
  }

  @Test
  void constructor_whenAlertsExposed_expectUnmodifiableView() {
    AlertListSnapshot snapshot =
        new AlertListSnapshot(List.of(sampleAlert(1, AlertSeverity.WARNING)));
    List<AlertSnapshot> alerts = snapshot.alerts();
    AlertSnapshot addedAlert = sampleAlert(2, AlertSeverity.ERROR);

    assertThrows(UnsupportedOperationException.class, () -> alerts.add(addedAlert));
  }

  @Test
  void constructor_whenAlertsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> new AlertListSnapshot(null));
  }

  private static AlertSnapshot sampleAlert(int id, AlertSeverity severity) {
    return new AlertSnapshot(
        id,
        "Alert " + id,
        "Summary " + id,
        "Body " + id,
        severity,
        true,
        "Dismiss",
        false,
        id * 100L);
  }
}
