package network.crypta.runtime.admin;

import network.crypta.runtime.alerts.AbstractUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.AlertListSnapshot;
import network.crypta.runtime.spi.AlertSeverity;
import network.crypta.runtime.spi.AlertSnapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyAlertPortTest {

  @Mock private UserAlertManager alertManager;

  @Test
  void snapshot_whenCalled_returnsDetachedVisibleAlertsInManagerOrder() {
    UserAlert visibleAlert =
        new TestUserAlert(
            42, "Visible title", "Visible short", "Visible text", UserAlert.WARNING, true, 1234L);
    UserAlert hiddenAlert =
        new TestUserAlert(
            99, "Hidden title", "Hidden short", "Hidden text", UserAlert.MINOR, false, 5678L);
    when(alertManager.getAlerts()).thenReturn(new UserAlert[] {visibleAlert, hiddenAlert});

    AlertListSnapshot snapshot = new LegacyAlertPort(alertManager).snapshot();

    assertEquals(1, snapshot.alerts().size());
    assertEquals(
        new AlertSnapshot(
            42,
            "Visible title",
            "Visible short",
            "Visible text",
            AlertSeverity.WARNING,
            true,
            "Delete",
            false,
            1234L),
        snapshot.alerts().getFirst());
  }

  @Test
  void dismiss_whenCalled_delegatesToManagerByAlertId() {
    new LegacyAlertPort(alertManager).dismiss(17);

    verify(alertManager).dismissAlert(17);
  }

  private static final class TestUserAlert extends AbstractUserAlert {
    private final int id;
    private final long updatedTimeMillis;

    private TestUserAlert(
        int id,
        String title,
        String shortText,
        String text,
        short priorityClass,
        boolean valid,
        long updatedTimeMillis) {
      super(
          true,
          title,
          Body.of(text, shortText, null),
          priorityClass,
          valid,
          new DismissOptions("Delete", true));
      this.id = id;
      this.updatedTimeMillis = updatedTimeMillis;
    }

    @Override
    public long getUpdatedTime() {
      return updatedTimeMillis;
    }

    @Override
    public int hashCode() {
      return id;
    }
  }
}
